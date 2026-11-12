from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from acp_gateway.app import create_app
from acp_gateway.config import from_dict

KEYS = {"observe": "gw-key-observe-0000000001", "redact": "gw-key-redact-00000000002",
        "block": "gw-key-block-000000000003", "closed": "gw-key-closed-00000000004"}
ENV = {"GW_OBSERVE": KEYS["observe"], "GW_REDACT": KEYS["redact"], "GW_BLOCK": KEYS["block"],
       "GW_CLOSED": KEYS["closed"], "UPSTREAM_KEY": "sk-real-provider-key"}


def raw_config(**over):
    cfg = {
        "upstreams": {"openai": {"base_url": "https://api.upstream.test/v1", "api_key_env": "UPSTREAM_KEY", "external": True},
                      "local": {"base_url": "http://vllm.internal:8000/v1", "external": False}},
        "clients": [
            {"name": "obs-agent", "key_env": "GW_OBSERVE", "upstream": "openai", "mode": "observe",
             "tools": {"deny": ["transfer_funds"]}},
            {"name": "red-agent", "key_env": "GW_REDACT", "upstream": "openai", "mode": "redact",
             "business_unit": "lending", "tools": {"deny": ["transfer_funds"], "require_approval": ["execute_sql"]}},
            {"name": "blk-agent", "key_env": "GW_BLOCK", "upstream": "openai", "mode": "block", "models": ["gpt-test"],
             "rate_limit_per_min": 5, "max_classification": "INTERNAL"},
            {"name": "closed-agent", "key_env": "GW_CLOSED", "upstream": "local", "mode": "block", "fail": "closed"},
        ],
    }
    cfg.update(over)
    return cfg


class Upstream:
    """A fake provider: records what the gateway sent and answers with whatever the test queued."""

    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.bodies: list[dict] = []
        self.reply: dict | None = None
        self.status = 200
        self.sse: list[bytes] | None = None
        self.raise_error = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        self.bodies.append(json.loads(request.content or b"{}"))
        if self.raise_error:
            raise httpx.ConnectError("down")
        if self.sse is not None and self.bodies[-1].get("stream"):
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=b"".join(self.sse))
        return httpx.Response(self.status, json=self.reply if self.reply is not None else completion("hello"))


def completion(content=None, tool_calls=None, finish="stop"):
    msg = {"role": "assistant", "content": content}
    if tool_calls:
        msg["tool_calls"] = [{"id": f"call_{i}", "type": "function", "function": {"name": n, "arguments": "{}"}}
                             for i, n in enumerate(tool_calls)]
        finish = "tool_calls"
    return {"id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "gpt-test",
            "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}}


@pytest.fixture
def upstream():
    return Upstream()


@pytest.fixture
def make(tmp_path, upstream):
    def _make(env=None, dashboard_transport=None, **over):
        cfg = raw_config(**over)
        cfg.setdefault("audit_path", str(tmp_path / "audit.jsonl"))
        e = dict(ENV)
        e.update(env or {})
        settings = from_dict(cfg, e)
        import os
        os.environ["UPSTREAM_KEY"] = ENV["UPSTREAM_KEY"]
        app = create_app(settings, upstream_transport=httpx.MockTransport(upstream.handler),
                         dashboard_transport=dashboard_transport, start_dashboard=False)
        return app
    return _make


@pytest.fixture
def gw(make):
    with TestClient(make()) as c:
        yield c


def auth(which):
    return {"Authorization": f"Bearer {KEYS[which]}"}


def chat(text, role="user", **kw):
    return {"model": "gpt-test", "messages": [{"role": "system", "content": "You are a bank assistant."},
                                              {"role": role, "content": text}], **kw}


def audit_rows(app_or_client):
    app = getattr(app_or_client, "app", app_or_client)
    path = app.state.audit.path
    return [json.loads(x) for x in open(path, encoding="utf-8") if x.strip()]
