"""Audit trail: one row per proxied request, hash-chained, with no message text.

Rows go to a local append-only JSONL file (mode 0600) and, when ``ACP_DASHBOARD_URL`` and ``ACP_API_KEY`` are
set, to the ACP dashboard, where each gateway client appears as an agent. The dashboard link also carries the
operator's pause: a heartbeat answered with 423 stops that client at the gateway until it is unpaused.

The dashboard is never on the request path. Rows are queued and shipped by a background thread; if the
dashboard is down the queue is bounded and the local file still has everything.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from collections import deque
from typing import Any, Callable

_log = logging.getLogger("acp_gateway.audit")
GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: str = ""):
        self.path = path
        self._lock = threading.Lock()
        self._prev = GENESIS
        self.rows = 0
        if path:
            os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            os.close(fd)
            self._prev = self._tail_hash()

    def _tail_hash(self) -> str:
        last = None
        try:
            with open(self.path, "rb") as f:
                for line in f:
                    if line.strip():
                        last = line
        except OSError:
            return GENESIS
        if not last:
            return GENESIS
        try:
            return str(json.loads(last).get("hash") or GENESIS)
        except ValueError:
            return GENESIS

    def append(self, row: dict) -> dict:
        with self._lock:
            row = dict(row)
            row["prev_hash"] = self._prev
            body = json.dumps(row, sort_keys=True, separators=(",", ":"), default=str)
            row["hash"] = hashlib.sha256(body.encode()).hexdigest()
            self._prev = row["hash"]
            self.rows += 1
            if self.path:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(row, sort_keys=True, separators=(",", ":"), default=str) + "\n")
            return row


def verify(path: str) -> tuple[bool, int, str]:
    """(ok, rows, problem) for an audit file."""
    prev, n = GENESIS, 0
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate((ln for ln in f if ln.strip()), 1):
            try:
                row = json.loads(line)
            except ValueError:
                return False, n, f"row {n} is not JSON"
            h = row.pop("hash", None)
            if row.get("prev_hash") != prev:
                return False, n, f"row {n} does not follow the row before it"
            body = json.dumps(row, sort_keys=True, separators=(",", ":"), default=str)
            if hashlib.sha256(body.encode()).hexdigest() != h:
                return False, n, f"row {n} was altered"
            prev = h
    return True, n, ""


Transport = Callable[[str, str, Any, dict, float], tuple[int, Any]]


def _http(method: str, url: str, body: Any, headers: dict, timeout: float) -> tuple[int, Any]:
    import httpx

    with httpx.Client(timeout=timeout, follow_redirects=False) as c:
        r = c.request(method, url, json=body, headers=headers)
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, None


class DashboardLink:
    """Registers each client as an agent, heartbeats, ships audit rows, and applies the pause switch."""

    def __init__(self, url: str, api_key: str, clients: list, on_pause: Callable[[str, str | None], None], *,
                 interval_s: float = 10.0, transport: Transport | None = None, max_queue: int = 5000):
        self.url, self._key = url.rstrip("/"), api_key
        self._clients = {c.name: c for c in clients}
        self._on_pause = on_pause
        self._interval = interval_s
        self._tr = transport or _http
        self._ids: dict[str, str] = {}
        self._q: deque = deque(maxlen=max_queue)
        self._qlock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.dropped = 0

    @property
    def enabled(self) -> bool:
        return bool(self.url and self._key)

    def _headers(self) -> dict:
        return {"X-API-Key": self._key, "Content-Type": "application/json"}

    def submit(self, row: dict) -> None:
        if not self.enabled:
            return
        with self._qlock:
            if len(self._q) == self._q.maxlen:
                self.dropped += 1
            self._q.append(row)

    def _register(self, name: str) -> str | None:
        c = self._clients[name]
        payload = {"agent_code": None, "name": c.name, "bu": c.business_unit or "default", "framework": "acp-gateway",
                   "endpoint": "", "process_name": "ACP gateway", "process_type": "gateway",
                   "license_key": os.environ.get("ACP_LICENSE_KEY", ""),
                   "governance_config": {"gateway": {"mode": c.mode, "fail": c.fail, "upstream": c.upstream}}}
        status, data = self._tr("POST", f"{self.url}/api/agents/register", payload, self._headers(), 10.0)
        if status == 200 and isinstance(data, dict) and data.get("agent_id"):
            return str(data["agent_id"])
        _log.warning("dashboard did not register client %s (HTTP %s)", name, status)
        return None

    def tick(self) -> None:
        """One cycle: register what is missing, heartbeat, flush the queue. Safe to call from tests."""
        for name in self._clients:
            try:
                if name not in self._ids:
                    aid = self._register(name)
                    if not aid:
                        continue
                    self._ids[name] = aid
                status, data = self._tr("POST", f"{self.url}/api/agents/{self._ids[name]}/heartbeat",
                                        {"status": "running"}, self._headers(), 10.0)
                if status == 423:
                    why = (data or {}).get("paused_reason") or (data or {}).get("detail") or "paused at the dashboard"
                    self._on_pause(name, str(why))
                elif status == 200:
                    act = (data or {}).get("action") if isinstance(data, dict) else None
                    if act == "pause" or (isinstance(data, dict) and data.get("status") == "paused"):
                        self._on_pause(name, str((data or {}).get("reason") or "paused at the dashboard"))
                    else:
                        self._on_pause(name, None)
                # any other answer (dashboard down, 5xx, 429): keep the last known state
            except Exception as e:  # noqa: BLE001 — the link is best-effort and never on the request path
                _log.warning("dashboard heartbeat for %s failed: %s", name, type(e).__name__)
        with self._qlock:
            batch = [self._q.popleft() for _ in range(min(len(self._q), 200))]
        if not batch:
            return
        entries = [{"agent_id": self._ids.get(r.get("client", ""), ""), "agent_name": r.get("client", ""),
                    "tool_name": f"llm:{r.get('model') or 'unknown'}", "bu": r.get("business_unit", ""),
                    "process_name": "ACP gateway", "process_type": "gateway", "session_id": r.get("request_id", ""),
                    "user_role": "gateway", "allowed": r.get("action") != "block", "reason": r.get("reason", ""),
                    "args": {"findings": r.get("findings", []), "mode": r.get("mode")}, "result_summary": "",
                    "cost_usd": 0, "tokens": r.get("total_tokens", 0), "iteration": 0,
                    "duration_ms": r.get("duration_ms", 0),
                    "span_type": "governance_block" if r.get("action") == "block" else "llm_call",
                    "framework": "acp-gateway", "timestamp": r.get("ts", time.time())} for r in batch]
        try:
            status, _ = self._tr("POST", f"{self.url}/api/audit/batch", entries, self._headers(), 10.0)
            if status >= 300:
                raise RuntimeError(f"HTTP {status}")
        except Exception as e:  # noqa: BLE001
            with self._qlock:                        # put the batch back at the front, oldest first
                for r in reversed(batch):
                    if len(self._q) < (self._q.maxlen or 0):
                        self._q.appendleft(r)
                    else:
                        self.dropped += 1
            _log.warning("dashboard refused %d audit rows (%s); they stay queued", len(batch), str(e)[:80])

    def start(self) -> None:
        if not self.enabled or self._thread:
            return

        def loop() -> None:
            while not self._stop.is_set():
                self.tick()
                self._stop.wait(self._interval)

        self._thread = threading.Thread(target=loop, name="acp-gateway-dashboard", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
