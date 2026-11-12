"""``python -m acp_gateway`` — run the gateway, or check a config / an audit file.

    python -m acp_gateway                      serve (ACP_GATEWAY_CONFIG, ACP_GATEWAY_HOST, ACP_GATEWAY_PORT)
    python -m acp_gateway check [config.yaml]  validate the configuration and exit
    python -m acp_gateway verify audit.jsonl   verify an audit file's hash chain
    python -m acp_gateway new-key              print a new gateway key and its sha256
"""
from __future__ import annotations

import hashlib
import logging
import os
import secrets
import sys

from .config import ConfigError, load


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    cmd = argv[0] if argv else "serve"
    if cmd in ("-h", "--help"):
        print(__doc__)
        return 0
    if cmd == "new-key":
        key = "acpgw_" + secrets.token_urlsafe(32)
        print(f"key:        {key}\nkey_sha256: {hashlib.sha256(key.encode()).hexdigest()}")
        return 0
    if cmd == "verify":
        from .audit import verify
        if len(argv) < 2:
            print("usage: python -m acp_gateway verify AUDIT.jsonl", file=sys.stderr)
            return 2
        ok, rows, problem = verify(argv[1])
        print(f"{'OK' if ok else 'BROKEN'}: {rows} row(s)" + (f" — {problem}" if problem else ""))
        return 0 if ok else 1
    try:
        settings = load(argv[1] if cmd == "check" and len(argv) > 1 else None)
    except ConfigError as e:
        print(f"configuration error: {e}", file=sys.stderr)
        return 2
    if cmd == "check":
        for c in settings.clients:
            up = settings.upstreams[c.upstream]
            print(f"client {c.name}: mode={c.mode} fail={c.fail} upstream={c.upstream} "
                  f"({'external' if up.external else 'internal'}) key={'set' if up.api_key() or not up.api_key_env else 'MISSING ' + up.api_key_env}")
        return 0
    if cmd != "serve":
        print(f"unknown command {cmd!r}", file=sys.stderr)
        return 2
    import uvicorn

    from .app import create_app

    logging.basicConfig(level=os.environ.get("ACP_GATEWAY_LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    uvicorn.run(create_app(settings), host=os.environ.get("ACP_GATEWAY_HOST", "127.0.0.1"),
                port=int(os.environ.get("ACP_GATEWAY_PORT", "8080")), log_level="info", access_log=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
