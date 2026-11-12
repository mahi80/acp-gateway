"""ACP gateway: an OpenAI-compatible proxy that applies ACP's controls with no change to the agent's code.

Point an agent's base URL at the gateway and give it a gateway key:

    OPENAI_BASE_URL=https://gateway.internal/v1   OPENAI_API_KEY=<gateway key>

The gateway identifies the client by that key, checks the request, forwards it to the configured upstream with
the real provider key, checks the answer, and writes one audit row. The caller never chooses the upstream URL.

Routes
    POST /v1/chat/completions    checked both ways (streaming supported)
    GET  /v1/models              passed through
    POST /v1/embeddings          request checked, response passed through
    GET  /healthz, /metrics
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
from starlette.concurrency import run_in_threadpool

from .audit import AuditLog, DashboardLink
from .config import Client, Settings, Upstream
from .policy import Decision, Engine

_log = logging.getLogger("acp_gateway")

#: request headers that are never forwarded upstream (the gateway sets its own auth and framing)
_DROP_REQ = {"authorization", "host", "content-length", "connection", "transfer-encoding", "cookie",
             "x-api-key", "api-key", "proxy-authorization", "accept-encoding", "x-forwarded-for"}
_KEEP_RESP = {"content-type", "x-request-id", "openai-processing-ms", "retry-after"}


def _error(status: int, code: str, message: str, request_id: str, **extra: Any) -> JSONResponse:
    headers = {"x-acp-request-id": request_id}
    if extra.get("retry_after"):
        headers["retry-after"] = str(extra["retry_after"])
    return JSONResponse({"error": {"message": message, "type": "acp_gateway", "code": code, "param": None}},
                        status_code=status, headers=headers)


def _bearer(request: Request) -> str:
    h = request.headers.get("authorization", "")
    if h[:7].lower() == "bearer ":
        return h[7:].strip()
    return request.headers.get("x-api-key", "") or request.headers.get("api-key", "")


class Metrics:
    def __init__(self) -> None:
        self.counts: dict[tuple[str, str], int] = {}

    def inc(self, client: str, outcome: str) -> None:
        self.counts[(client, outcome)] = self.counts.get((client, outcome), 0) + 1

    def render(self) -> str:
        lines = ["# TYPE acp_gateway_requests_total counter"]
        for (c, o), n in sorted(self.counts.items()):
            lines.append(f'acp_gateway_requests_total{{client="{c}",outcome="{o}"}} {n}')
        return "\n".join(lines) + "\n"


def create_app(settings: Settings, *, upstream_transport: httpx.AsyncBaseTransport | None = None,
               dashboard_transport=None, start_dashboard: bool = True) -> FastAPI:
    engine = Engine(settings)
    audit = AuditLog(settings.audit_path)
    link = DashboardLink(settings.dashboard_url, settings.dashboard_api_key, settings.clients, engine.set_paused,
                         transport=dashboard_transport)
    metrics = Metrics()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.http = httpx.AsyncClient(transport=upstream_transport, follow_redirects=False,
                                           limits=httpx.Limits(max_connections=200, max_keepalive_connections=50))
        if start_dashboard:
            link.start()
        try:
            yield
        finally:
            link.stop()
            await app.state.http.aclose()

    app = FastAPI(title="ACP gateway", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.engine, app.state.audit, app.state.link, app.state.metrics = engine, audit, link, metrics

    def record(client: Client, request_id: str, started: float, body: Any, req: Decision, resp: Decision | None,
               *, upstream_status: int | None, outcome: str, stream: bool, usage: dict | None = None) -> None:
        findings = [f.to_dict() for f in req.findings] + ([f.to_dict() for f in resp.findings] if resp else [])
        final = resp if (resp is not None and resp.blocked) else req
        action = "block" if (req.blocked or (resp is not None and resp.blocked)) else (
            "redact" if "redact" in (req.action, resp.action if resp else "") else "allow")
        row = {"ts": round(time.time(), 3), "request_id": request_id, "client": client.name,
               "business_unit": client.business_unit, "mode": client.mode, "upstream": client.upstream,
               "model": str(body.get("model"))[:120] if isinstance(body, dict) else None, "stream": stream,
               "action": action, "reason": final.reason if action == "block" else "", "findings": findings,
               "control_errors": req.control_errors + (resp.control_errors if resp else 0),
               "upstream_status": upstream_status, "duration_ms": int((time.time() - started) * 1000),
               "total_tokens": int((usage or {}).get("total_tokens") or 0)}
        try:
            link.submit(audit.append(row))
        except Exception as e:  # noqa: BLE001 — an audit failure is loud but never changes the answer already decided
            _log.error("audit write failed: %s", type(e).__name__)
        metrics.inc(client.name, outcome)

    async def read_json(request: Request, request_id: str):
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > settings.max_body_bytes:
            return None, _error(413, "body_too_large", "The request body is too large.", request_id)
        chunks, size = [], 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > settings.max_body_bytes:
                return None, _error(413, "body_too_large", "The request body is too large.", request_id)
            chunks.append(chunk)
        try:
            body = json.loads(b"".join(chunks) or b"{}")
        except (ValueError, RecursionError):
            return None, _error(400, "invalid_json", "The request body is not valid JSON.", request_id)
        if not isinstance(body, dict):
            return None, _error(400, "invalid_json", "The request body must be a JSON object.", request_id)
        return body, None

    def authenticate(request: Request, request_id: str):
        client = settings.client_for_key(_bearer(request))
        if client is None:
            return None, None, _error(401, "invalid_gateway_key", "Unknown or missing gateway key.", request_id)
        return client, settings.upstreams[client.upstream], None

    def upstream_headers(request: Request, up: Upstream, request_id: str) -> dict:
        h = {k: v for k, v in request.headers.items() if k.lower() not in _DROP_REQ}
        key = up.api_key()
        if key:
            h["authorization"] = f"Bearer {key}"
        h["x-acp-request-id"] = request_id
        return h

    def passthrough_headers(r: httpx.Response, request_id: str) -> dict:
        h = {k: v for k, v in r.headers.items() if k.lower() in _KEEP_RESP}
        h["x-acp-request-id"] = request_id
        return h

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "clients": len(settings.clients), "audit_rows": audit.rows,
                "dashboard": "linked" if link.enabled else "off", "dashboard_dropped": link.dropped}

    @app.get("/metrics")
    async def metrics_route():
        return PlainTextResponse(metrics.render())

    @app.get("/v1/models")
    async def models(request: Request):
        rid = uuid.uuid4().hex
        client, up, err = authenticate(request, rid)
        if err:
            return err
        try:
            r = await app.state.http.get(f"{up.base_url}/models", headers=upstream_headers(request, up, rid),
                                         timeout=up.timeout_s)
        except httpx.HTTPError:
            return _error(502, "upstream_unreachable", "The model provider could not be reached.", rid)
        return Response(r.content, status_code=r.status_code, headers=passthrough_headers(r, rid))

    @app.post("/v1/embeddings")
    async def embeddings(request: Request):
        rid, started = uuid.uuid4().hex, time.time()
        client, up, err = authenticate(request, rid)
        if err:
            return err
        body, err = await read_json(request, rid)
        if err:
            return err
        texts = body.get("input")
        texts = [texts] if isinstance(texts, str) else [t for t in (texts or []) if isinstance(t, str)][:2000]
        probe = {"model": body.get("model"), "messages": [{"role": "user", "content": t} for t in texts]}
        d = await run_in_threadpool(engine.check_request, client, up, probe)
        if d.blocked:
            record(client, rid, started, body, d, None, upstream_status=None, outcome="blocked", stream=False)
            return _error(d.status, d.reason, d.message, rid, retry_after=d.retry_after_s)
        if d.action == "redact":
            red = [m["content"] for m in d.body["messages"]]
            body = {**body, "input": red[0] if isinstance(body.get("input"), str) else red}
        try:
            r = await app.state.http.post(f"{up.base_url}/embeddings", json=body,
                                          headers=upstream_headers(request, up, rid), timeout=up.timeout_s)
        except httpx.HTTPError:
            record(client, rid, started, body, d, None, upstream_status=None, outcome="upstream_error", stream=False)
            return _error(502, "upstream_unreachable", "The model provider could not be reached.", rid)
        record(client, rid, started, body, d, None, upstream_status=r.status_code, outcome="forwarded", stream=False)
        return Response(r.content, status_code=r.status_code, headers=passthrough_headers(r, rid))

    @app.post("/v1/chat/completions")
    async def chat(request: Request):
        rid, started = uuid.uuid4().hex, time.time()
        client, up, err = authenticate(request, rid)
        if err:
            return err
        body, err = await read_json(request, rid)
        if err:
            return err
        stream = bool(body.get("stream"))

        req_d = await run_in_threadpool(engine.check_request, client, up, body)
        if req_d.blocked:
            record(client, rid, started, body, req_d, None, upstream_status=None, outcome="blocked", stream=stream)
            return _error(req_d.status, req_d.reason, req_d.message, rid, retry_after=req_d.retry_after_s)
        out_body = req_d.body if req_d.action == "redact" else body
        headers = upstream_headers(request, up, rid)
        url = f"{up.base_url}/chat/completions"

        if stream and client.mode == "observe":
            return await _stream_observed(app, engine, record, client, up, rid, started, body, out_body, req_d, url, headers)

        # Enforcing modes need the whole answer before any of it reaches the agent: a tool call the client is
        # not allowed to make, or personal data, cannot be taken back once it has been streamed. The answer is
        # collected, checked, and then returned in the shape the caller asked for.
        try:
            if stream:
                up_body = {**out_body, "stream": False}
                up_body.pop("stream_options", None)
            else:
                up_body = out_body
            r = await app.state.http.post(url, json=up_body, headers=headers, timeout=up.timeout_s)
        except httpx.HTTPError:
            record(client, rid, started, body, req_d, None, upstream_status=None, outcome="upstream_error", stream=stream)
            return _error(502, "upstream_unreachable", "The model provider could not be reached.", rid)
        if r.status_code >= 400:
            record(client, rid, started, body, req_d, None, upstream_status=r.status_code, outcome="upstream_error", stream=stream)
            return Response(r.content, status_code=r.status_code, headers=passthrough_headers(r, rid))
        try:
            data = r.json()
            if not isinstance(data, dict):
                raise ValueError("not an object")
        except ValueError:
            record(client, rid, started, body, req_d, None, upstream_status=r.status_code, outcome="upstream_error", stream=stream)
            if client.mode != "observe":
                return _error(502, "upstream_invalid", "The model provider returned an answer that could not be checked.", rid)
            return Response(r.content, status_code=r.status_code, headers=passthrough_headers(r, rid))

        resp_d = await run_in_threadpool(engine.check_response, client, data)
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else None
        if resp_d.blocked:
            record(client, rid, started, body, req_d, resp_d, upstream_status=r.status_code, outcome="blocked", stream=stream, usage=usage)
            return _error(resp_d.status, resp_d.reason, resp_d.message, rid)
        final = resp_d.body if resp_d.action == "redact" else data
        record(client, rid, started, body, req_d, resp_d, upstream_status=r.status_code,
               outcome="redacted" if "redact" in (req_d.action, resp_d.action) else "forwarded", stream=stream, usage=usage)
        if stream:
            return StreamingResponse(_as_sse(final), media_type="text/event-stream",
                                     headers={"x-acp-request-id": rid, "cache-control": "no-cache"})
        return JSONResponse(final, status_code=r.status_code, headers={"x-acp-request-id": rid})

    return app


def _as_sse(completion: dict):
    """Replay a checked completion as OpenAI stream chunks (one per choice, then the terminator)."""
    base = {"id": completion.get("id", ""), "object": "chat.completion.chunk",
            "created": completion.get("created", int(time.time())), "model": completion.get("model", "")}

    async def gen():
        for ch in completion.get("choices") or []:
            msg = ch.get("message") or {}
            delta: dict = {"role": msg.get("role", "assistant")}
            if msg.get("content") is not None:
                delta["content"] = msg["content"]
            if msg.get("tool_calls"):
                delta["tool_calls"] = [{**tc, "index": i} for i, tc in enumerate(msg["tool_calls"])]
            yield _sse({**base, "choices": [{"index": ch.get("index", 0), "delta": delta, "finish_reason": None}]})
            yield _sse({**base, "choices": [{"index": ch.get("index", 0), "delta": {},
                                             "finish_reason": ch.get("finish_reason") or "stop"}]})
        if completion.get("usage"):
            yield _sse({**base, "choices": [], "usage": completion["usage"]})
        yield b"data: [DONE]\n\n"

    return gen()


def _sse(obj: dict) -> bytes:
    return b"data: " + json.dumps(obj, separators=(",", ":")).encode() + b"\n\n"


async def _stream_observed(app, engine, record, client, up, rid, started, body, out_body, req_d, url, headers):
    """Observe mode: bytes go to the agent as they arrive; the answer is reassembled on the side and checked
    after the last chunk, so findings are recorded with no added latency."""
    try:
        req = app.state.http.build_request("POST", url, json=out_body, headers=headers, timeout=up.timeout_s)
        r = await app.state.http.send(req, stream=True)
    except httpx.HTTPError:
        record(client, rid, started, body, req_d, None, upstream_status=None, outcome="upstream_error", stream=True)
        return _error(502, "upstream_unreachable", "The model provider could not be reached.", rid)
    if r.status_code >= 400:
        content = await r.aread()
        await r.aclose()
        record(client, rid, started, body, req_d, None, upstream_status=r.status_code, outcome="upstream_error", stream=True)
        return Response(content, status_code=r.status_code,
                        headers={"content-type": r.headers.get("content-type", "application/json"), "x-acp-request-id": rid})

    async def gen():
        text: dict[int, list[str]] = {}
        tools: dict[tuple[int, int], dict] = {}
        usage = None
        buf = b""
        kept = 0
        try:
            async for chunk in r.aiter_bytes():
                yield chunk
                if kept > 4 * 1024 * 1024:           # stop reassembling a very long answer; keep streaming it
                    continue
                buf += chunk
                while b"\n\n" in buf:
                    event, buf = buf.split(b"\n\n", 1)
                    for line in event.split(b"\n"):
                        if not line.startswith(b"data:"):
                            continue
                        payload = line[5:].strip()
                        if not payload or payload == b"[DONE]":
                            continue
                        try:
                            obj = json.loads(payload)
                        except ValueError:
                            continue
                        if isinstance(obj.get("usage"), dict):
                            usage = obj["usage"]
                        for ch in obj.get("choices") or []:
                            delta = ch.get("delta") or {}
                            idx = int(ch.get("index") or 0)
                            if isinstance(delta.get("content"), str):
                                text.setdefault(idx, []).append(delta["content"])
                                kept += len(delta["content"])
                            for tc in delta.get("tool_calls") or []:
                                slot = tools.setdefault((idx, int(tc.get("index") or 0)), {"function": {"name": "", "arguments": ""}})
                                fn = tc.get("function") or {}
                                slot["function"]["name"] += fn.get("name") or ""
                                slot["function"]["arguments"] += fn.get("arguments") or ""
        finally:
            await r.aclose()
            choices = []
            for idx in sorted(set(text) | {i for i, _ in tools}):
                msg: dict = {"role": "assistant", "content": "".join(text.get(idx, []))}
                calls = [v for (i, _), v in sorted(tools.items()) if i == idx]
                if calls:
                    msg["tool_calls"] = calls
                choices.append({"index": idx, "message": msg})
            resp_d = engine.check_response(client, {"choices": choices})
            record(client, rid, started, body, req_d, resp_d, upstream_status=r.status_code, outcome="forwarded",
                   stream=True, usage=usage)

    return StreamingResponse(gen(), status_code=r.status_code, media_type="text/event-stream",
                             headers={"x-acp-request-id": rid, "cache-control": "no-cache"})
