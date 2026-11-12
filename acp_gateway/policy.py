"""The checks the gateway applies to traffic, built on the ACP SDK's controls.

Nothing here is new detection logic: the gateway calls the same controls an agent would run in-process with
``acp-sdk`` (Q29 injection firewall, Q25 PII scanner, Q30 tool permissions, Q33 rate limiter, Q34
confidentiality), but from outside the agent, on the request and response bodies it proxies.

A decision never carries the text it was made on: findings hold a control id, a type and a count.
"""
from __future__ import annotations

import copy
import logging
import re
import threading
from dataclasses import dataclass, field
from typing import Any

from acp.controls.confidentiality import CLASSIFICATION_LEVELS, ConfidentialityClassifier
from acp.controls.injection_firewall import InjectionFirewall
from acp.controls.pii_scanner import PIIScanner
from acp.controls.rate_limiter import SemanticRateLimiter
from acp.controls.tool_permissions import ToolPermissionMatrix

from .config import Client, Settings, Upstream

_log = logging.getLogger("acp_gateway.policy")

#: text longer than this is scanned in overlapping windows, so one huge field cannot stall a worker
_SCAN_WINDOW = 16 * 1024
_SCAN_OVERLAP = 512
_MAX_TEXTS = 2000


@dataclass
class Finding:
    control: str                 # Q25, Q29, Q30, Q33, Q34, model, gateway
    kind: str                    # e.g. AADHAAR, INSTRUCTION_OVERRIDE, DENIED_BY_POLICY
    where: str                   # request.user, request.tool, response, response.tool_call
    count: int = 1
    detail: str = ""             # never message text: a tool name, a level, a limit

    def to_dict(self) -> dict:
        return {"control": self.control, "kind": self.kind, "where": self.where, "count": self.count,
                **({"detail": self.detail} if self.detail else {})}


@dataclass
class Decision:
    action: str = "allow"        # allow | redact | block
    reason: str = ""             # machine-readable, set when blocked
    message: str = ""            # what the caller is told
    status: int = 200
    findings: list[Finding] = field(default_factory=list)
    body: Any = None             # the (possibly rewritten) JSON body to forward / return
    control_errors: int = 0
    retry_after_s: int = 0

    @property
    def blocked(self) -> bool:
        return self.action == "block"


def _windows(text: str):
    if len(text) <= _SCAN_WINDOW:
        yield text
        return
    step = _SCAN_WINDOW - _SCAN_OVERLAP
    for i in range(0, len(text), step):
        yield text[i:i + _SCAN_WINDOW]


def _parts(msg: dict) -> list[tuple[Any, Any]]:
    """Every text in one chat message as (container, key) pairs so a redaction can be written back in place."""
    out: list[tuple[Any, Any]] = []
    c = msg.get("content")
    if isinstance(c, str):
        out.append((msg, "content"))
    elif isinstance(c, list):
        for part in c[:_MAX_TEXTS]:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                out.append((part, "text"))
    return out


class Engine:
    """One per gateway process. Thread-safe: the controls are read-only after construction except the rate
    limiter and the paused set, which are guarded here."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._fw = InjectionFirewall(block_on_detection=False)
        self._pii = PIIScanner(mode="log")
        self._conf = ConfidentialityClassifier()
        self._tools = ToolPermissionMatrix(
            policies={c.name: {"allow": list(c.tools_allow), "deny": list(c.tools_deny),
                               "require_approval": list(c.tools_require_approval)} for c in settings.clients},
            bu_policies={"_gateway": {}},          # no built-in business-unit lists: the file is the policy
            auto_escalate_destructive=False)
        self._rate = SemanticRateLimiter(
            global_limit=10 ** 9, window_seconds=60,
            per_agent_limits={c.name: c.rate_limit_per_min for c in settings.clients})
        self._lock = threading.Lock()
        self._paused: dict[str, str] = {}

    # ---- operator pause (the dashboard's kill switch reaches the gateway through the heartbeat) -------------
    def set_paused(self, client: str, reason: str | None) -> None:
        with self._lock:
            if reason is None:
                self._paused.pop(client, None)
            else:
                self._paused[client] = reason[:200]

    def paused(self, client: str) -> str | None:
        with self._lock:
            return self._paused.get(client)

    # ---- helpers ------------------------------------------------------------------------------------------------
    def _guard(self, d: Decision, client: Client, control: str, fn):
        """Run one control. A control that raises is recorded; an enforcing client set to fail closed is refused."""
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 — a broken check must not take the client's traffic down by accident
            d.control_errors += 1
            d.findings.append(Finding("gateway", "CONTROL_ERROR", control, detail=type(e).__name__))
            _log.error("control %s failed for client %s: %s", control, client.name, type(e).__name__)
            if client.mode != "observe" and client.fail == "closed" and not d.blocked:
                d.action, d.status, d.reason = "block", 503, "control_unavailable"
                d.message = "A safety check is unavailable and this client is set to fail closed."
            return None

    def _injection(self, text: str, tool: str | None):
        best = None
        for w in _windows(text):
            r = self._fw.scan_tool_result(tool, w) if tool else self._fw.scan_input(w)
            if r.is_injection and (best is None or r.confidence > best.confidence):
                best = r
        return best

    def _pii_scan(self, text: str) -> tuple[dict[str, int], str]:
        counts: dict[str, int] = {}
        out: list[str] = []
        if len(text) <= _SCAN_WINDOW:
            chunks = [text]
        else:                                        # redaction needs non-overlapping pieces
            chunks = [text[i:i + _SCAN_WINDOW] for i in range(0, len(text), _SCAN_WINDOW)]
        for w in chunks:
            r = self._pii.scan(w)
            if r.has_pii:
                for f in r.findings:
                    counts[f.pii_type] = counts.get(f.pii_type, 0) + 1
                out.append(r.redacted_text or w)
            else:
                out.append(w)
        return counts, "".join(out)

    # ---- request ------------------------------------------------------------------------------------------------
    def check_request(self, client: Client, upstream: Upstream, body: dict) -> Decision:
        enforcing = client.mode != "observe"
        d = Decision(body=body)

        why = self.paused(client.name)
        if why is not None:                          # an operator's pause applies in every mode
            d.action, d.status, d.reason = "block", 423, "agent_paused"
            d.message = f"This agent is paused by its operator: {why}"
            d.findings.append(Finding("gateway", "PAUSED", "request"))
            return d

        rl = self._guard(d, client, "Q33", lambda: self._rate.check(client.name, "chat"))
        if rl is not None and not rl.allowed:
            d.findings.append(Finding("Q33", "RATE_LIMITED", "request", detail=f"{rl.limit}/min"))
            if enforcing:
                d.action, d.status, d.reason = "block", 429, "rate_limited"
                d.message = f"Rate limit of {rl.limit} requests per minute reached."
                d.retry_after_s = max(1, int((rl.retry_after_ms or 1000) / 1000))
                return d

        model = body.get("model")
        if client.models and model not in client.models:
            d.findings.append(Finding("model", "MODEL_NOT_ALLOWED", "request", detail=str(model)[:80]))
            if enforcing:
                d.action, d.status, d.reason = "block", 403, "model_not_allowed"
                d.message = "This client is not allowed to use that model."
                return d

        messages = body.get("messages")
        if not isinstance(messages, list):
            return d

        work = copy.deepcopy(body) if client.mode == "redact" else body
        wmsgs = work["messages"]
        all_text: list[str] = []
        for i, msg in enumerate(messages[:_MAX_TEXTS]):
            if not isinstance(msg, dict):
                continue
            role = str(msg.get("role") or "")
            for j, (holder, key) in enumerate(_parts(msg)):
                text = holder[key]
                if not text:
                    continue
                all_text.append(text)
                # instructions hidden in what the USER typed or in what a TOOL returned; the system prompt is
                # the operator's own and earlier assistant turns are the model's
                if role in ("user", "tool", "function"):
                    tool = (str(msg.get("name") or msg.get("tool_call_id") or "tool")[:80]
                            if role in ("tool", "function") else None)
                    hit = self._guard(d, client, "Q29", lambda t=text, tl=tool: self._injection(t, tl))
                    if hit is not None:
                        d.findings.append(Finding("Q29", hit.injection_type or "INJECTION",
                                                  f"request.{'tool' if tool else 'user'}",
                                                  count=len(hit.matched_patterns) or 1))
                res = self._guard(d, client, "Q25", lambda t=text: self._pii_scan(t))
                if res is not None and res[0]:
                    for kind, n in res[0].items():
                        d.findings.append(Finding("Q25", kind, f"request.{role or 'message'}", count=n))
                    if client.mode == "redact":
                        wparts = _parts(wmsgs[i])
                        if j < len(wparts):
                            wparts[j][0][wparts[j][1]] = res[1]

        if upstream.external and client.max_classification and all_text:
            joined = "\n".join(all_text)[: 4 * _SCAN_WINDOW]
            cls = self._guard(d, client, "Q34", lambda: self._conf.classify(joined))
            if cls is not None and (CLASSIFICATION_LEVELS.index(cls.level)
                                    > CLASSIFICATION_LEVELS.index(client.max_classification)):
                d.findings.append(Finding("Q34", "OVER_CLASSIFICATION", "request", detail=cls.level))

        if d.blocked or not enforcing:
            return d
        kinds = {f.control for f in d.findings}
        if "Q29" in kinds:
            d.action, d.status, d.reason = "block", 403, "prompt_injection"
            d.message = "The request was refused: it contains instructions that try to override the agent."
        elif "Q34" in kinds:
            d.action, d.status, d.reason = "block", 403, "data_classification"
            d.message = "The request was refused: it carries data this client may not send to an external model."
        elif "Q25" in kinds:
            if client.mode == "block":
                d.action, d.status, d.reason = "block", 403, "personal_data"
                d.message = "The request was refused: it contains personal data."
            else:
                d.action, d.body = "redact", work
        return d

    # ---- response -----------------------------------------------------------------------------------------------
    def check_response(self, client: Client, body: dict) -> Decision:
        enforcing = client.mode != "observe"
        d = Decision(body=body)
        choices = body.get("choices")
        if not isinstance(choices, list):
            return d
        work = copy.deepcopy(body) if enforcing else body
        changed = False
        for ci, ch in enumerate(choices[:64]):
            msg = ch.get("message") if isinstance(ch, dict) else None
            if not isinstance(msg, dict):
                continue
            wmsg = work["choices"][ci]["message"]

            # personal data first, then tool calls: the note about a refused tool is added to the content last
            for j, (holder, key) in enumerate(_parts(msg)):
                text = holder[key]
                if not text:
                    continue
                res = self._guard(d, client, "Q25", lambda t=text: self._pii_scan(t))
                if res is not None and res[0]:
                    for kind, n in res[0].items():
                        d.findings.append(Finding("Q25", kind, "response", count=n))
                    if client.mode == "redact":
                        wparts = _parts(wmsg)
                        if j < len(wparts) and wparts[j][1] == key:
                            wparts[j][0][wparts[j][1]] = res[1]
                            changed = True

            calls = msg.get("tool_calls")
            if isinstance(calls, list) and calls:
                kept = []
                for call in calls[:256]:
                    name = str(((call or {}).get("function") or {}).get("name") or "")[:128] if isinstance(call, dict) else ""
                    r = self._guard(d, client, "Q30", lambda n=name: self._tools.check(client.name, n))
                    if r is not None and (not r.allowed or r.requires_approval):
                        d.findings.append(Finding("Q30", r.reason or "DENIED", "response.tool_call", detail=name))
                    else:
                        kept.append(call)
                if enforcing and len(kept) != len(calls):
                    denied = [f.detail for f in d.findings if f.control == "Q30"]
                    changed = True
                    if kept:
                        wmsg["tool_calls"] = kept
                    else:
                        wmsg.pop("tool_calls", None)
                        work["choices"][ci]["finish_reason"] = "stop"
                    note = ("[ACP gateway] The agent tried to call a tool it is not allowed to use here: "
                            + ", ".join(sorted(set(denied))) + ".")
                    prev = wmsg.get("content")
                    wmsg["content"] = (prev + "\n" + note) if isinstance(prev, str) and prev else note

        if d.blocked or not enforcing:
            return d
        if client.mode == "block" and any(f.control == "Q25" for f in d.findings):
            d.action, d.status, d.reason = "block", 403, "personal_data_in_response"
            d.message = "The model's answer was withheld: it contains personal data."
            return d
        if changed:
            d.action, d.body = "redact", work
        return d
