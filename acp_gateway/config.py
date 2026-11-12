"""Gateway configuration: who may call, where their traffic goes, and how strictly it is checked.

One YAML file (``ACP_GATEWAY_CONFIG``) names the upstream model providers and the clients. A client is one
agent or application; it presents a gateway key, never a provider key. Provider keys stay on the gateway and
are read from the environment variable named in the file — a secret is never written in the file itself.

    upstreams:
      openai:
        base_url: https://api.openai.com/v1
        api_key_env: OPENAI_API_KEY
        external: true              # data leaves the organisation: the confidentiality check applies
      local-vllm:
        base_url: http://vllm.internal:8000/v1
        external: false

    clients:
      - name: loan-assistant        # the agent's name in audit rows and on the ACP dashboard
        key_env: GW_KEY_LOAN        # the gateway key this client presents (Authorization: Bearer ...)
        business_unit: lending
        upstream: openai
        mode: observe               # observe | redact | block
        fail: open                  # open | closed — what happens when a check itself fails
        models: [gpt-4o-mini]       # optional allowlist
        rate_limit_per_min: 120
        tools:
          deny: [transfer_funds]
          require_approval: [execute_sql]

Modes:
    observe   everything is forwarded; findings are only recorded. Start every client here.
    redact    personal data is masked in both directions; injections and denied tool calls are blocked.
    block     a request or response with personal data is refused; injections and denied tool calls are blocked.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MODES = ("observe", "redact", "block")
FAIL = ("open", "closed")


class ConfigError(ValueError):
    """The configuration is unusable; the message names the entry and the reason."""


@dataclass(frozen=True)
class Upstream:
    name: str
    base_url: str
    api_key_env: str = ""
    external: bool = True
    timeout_s: float = 120.0

    def api_key(self) -> str:
        return os.environ.get(self.api_key_env, "") if self.api_key_env else ""


@dataclass(frozen=True)
class Client:
    name: str
    key_sha256: str                       # the gateway key is held only as a digest
    upstream: str
    business_unit: str = ""
    mode: str = "observe"
    fail: str = "open"
    models: tuple[str, ...] = ()
    rate_limit_per_min: int = 600
    tools_deny: tuple[str, ...] = ()
    tools_allow: tuple[str, ...] = ()
    tools_require_approval: tuple[str, ...] = ()
    max_classification: str = ""          # highest data level this client may send to an EXTERNAL upstream


@dataclass
class Settings:
    upstreams: dict[str, Upstream] = field(default_factory=dict)
    clients: list[Client] = field(default_factory=list)
    max_body_bytes: int = 2 * 1024 * 1024
    audit_path: str = ""
    audit_content: bool = False           # store redacted excerpts in audit rows (off: findings and sizes only)
    dashboard_url: str = ""
    dashboard_api_key: str = ""

    def client_for_key(self, presented: str) -> Client | None:
        if not presented:
            return None
        digest = hashlib.sha256(presented.encode()).hexdigest()
        hit = None
        for c in self.clients:                       # compare against every client: no early exit on a match
            if hmac.compare_digest(c.key_sha256, digest):
                hit = c
        return hit


def _digest(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _list(v: Any, what: str) -> tuple[str, ...]:
    if v in (None, ""):
        return ()
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ConfigError(f"{what} must be a list of strings")
    return tuple(v)


def _upstream(name: str, raw: Any) -> Upstream:
    if not isinstance(raw, dict):
        raise ConfigError(f"upstream {name!r} must be a mapping")
    url = str(raw.get("base_url") or "").rstrip("/")
    if not url.startswith(("https://", "http://")):
        raise ConfigError(f"upstream {name!r}: base_url must be an http(s) URL")
    external = bool(raw.get("external", True))
    if external and url.startswith("http://") and not raw.get("allow_plaintext"):
        raise ConfigError(f"upstream {name!r}: an external upstream must use https (set allow_plaintext: true to override)")
    if "api_key" in raw:
        raise ConfigError(f"upstream {name!r}: put the key in an environment variable and name it in api_key_env")
    try:
        timeout = float(raw.get("timeout_s", 120))
    except (TypeError, ValueError) as e:
        raise ConfigError(f"upstream {name!r}: timeout_s must be a number") from e
    return Upstream(name=name, base_url=url, api_key_env=str(raw.get("api_key_env") or ""), external=external,
                    timeout_s=timeout if 0 < timeout <= 900 else 120.0)


def _client(raw: Any, upstreams: dict[str, Upstream], env: dict) -> Client:
    if not isinstance(raw, dict):
        raise ConfigError("each client must be a mapping")
    name = str(raw.get("name") or "").strip()
    if not name:
        raise ConfigError("a client has no name")
    if "key" in raw:
        raise ConfigError(f"client {name!r}: put the gateway key in an environment variable and name it in key_env")
    key_env = str(raw.get("key_env") or "")
    digest = str(raw.get("key_sha256") or "").lower()
    if key_env:
        key = env.get(key_env, "")
        if len(key) < 16:
            raise ConfigError(f"client {name!r}: {key_env} is unset or shorter than 16 characters")
        digest = _digest(key)
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise ConfigError(f"client {name!r}: needs key_env, or key_sha256 (64 hex characters)")
    up = str(raw.get("upstream") or "")
    if up not in upstreams:
        raise ConfigError(f"client {name!r}: upstream {up!r} is not defined")
    mode = str(raw.get("mode") or "observe").lower()
    if mode not in MODES:
        raise ConfigError(f"client {name!r}: mode must be one of {MODES}")
    fail = str(raw.get("fail") or "open").lower()
    if fail not in FAIL:
        raise ConfigError(f"client {name!r}: fail must be one of {FAIL}")
    tools = raw.get("tools") or {}
    if not isinstance(tools, dict):
        raise ConfigError(f"client {name!r}: tools must be a mapping")
    try:
        rate = int(raw.get("rate_limit_per_min", 600))
    except (TypeError, ValueError) as e:
        raise ConfigError(f"client {name!r}: rate_limit_per_min must be a whole number") from e
    if rate <= 0:
        raise ConfigError(f"client {name!r}: rate_limit_per_min must be positive")
    level = str(raw.get("max_classification") or "").upper()
    if level and level not in ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"):
        raise ConfigError(f"client {name!r}: max_classification must be PUBLIC, INTERNAL, CONFIDENTIAL or RESTRICTED")
    return Client(name=name, key_sha256=digest, upstream=up, business_unit=str(raw.get("business_unit") or ""),
                  mode=mode, fail=fail, models=_list(raw.get("models"), f"client {name!r}: models"),
                  rate_limit_per_min=rate, tools_deny=_list(tools.get("deny"), f"client {name!r}: tools.deny"),
                  tools_allow=_list(tools.get("allow"), f"client {name!r}: tools.allow"),
                  tools_require_approval=_list(tools.get("require_approval"), f"client {name!r}: tools.require_approval"),
                  max_classification=level)


def from_dict(raw: Any, env: dict | None = None) -> Settings:
    env = dict(os.environ) if env is None else env
    if not isinstance(raw, dict):
        raise ConfigError("the configuration must be a mapping with 'upstreams' and 'clients'")
    ups_raw = raw.get("upstreams") or {}
    if not isinstance(ups_raw, dict) or not ups_raw:
        raise ConfigError("at least one upstream is required")
    upstreams = {str(n): _upstream(str(n), u) for n, u in ups_raw.items()}
    cl_raw = raw.get("clients") or []
    if not isinstance(cl_raw, list) or not cl_raw:
        raise ConfigError("at least one client is required")
    clients = [_client(c, upstreams, env) for c in cl_raw]
    names = [c.name for c in clients]
    if len(set(names)) != len(names):
        raise ConfigError("client names must be unique")
    if len({c.key_sha256 for c in clients}) != len(clients):
        raise ConfigError("two clients share one gateway key")
    try:
        max_body = int(raw.get("max_body_bytes", 2 * 1024 * 1024))
    except (TypeError, ValueError) as e:
        raise ConfigError("max_body_bytes must be a whole number") from e
    return Settings(upstreams=upstreams, clients=clients,
                    max_body_bytes=max(1024, min(max_body, 64 * 1024 * 1024)),
                    audit_path=str(raw.get("audit_path") or env.get("ACP_GATEWAY_AUDIT", "")),
                    audit_content=bool(raw.get("audit_content", False)),
                    dashboard_url=str(env.get("ACP_DASHBOARD_URL", "")).rstrip("/"),
                    dashboard_api_key=str(env.get("ACP_API_KEY", "")))


def load(path: str | None = None, env: dict | None = None) -> Settings:
    import yaml

    env = dict(os.environ) if env is None else env
    p = path or env.get("ACP_GATEWAY_CONFIG", "")
    if not p:
        raise ConfigError("set ACP_GATEWAY_CONFIG to the gateway's YAML file")
    try:
        raw = yaml.safe_load(Path(p).read_text(encoding="utf-8"))
    except OSError as e:
        raise ConfigError(f"cannot read {p}: {e.strerror}") from e
    except yaml.YAMLError as e:
        raise ConfigError(f"{p} is not valid YAML: {str(e)[:200]}") from e
    return from_dict(raw, env)
