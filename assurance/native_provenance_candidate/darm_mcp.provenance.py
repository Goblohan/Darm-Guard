#!/usr/bin/env python3
import importlib.util
import os
import secrets
from pathlib import Path

BASE_PATH = Path("/opt/perceptra/darm-codex-bridge/0.1.0/darm_mcp.py")
SPEC = importlib.util.spec_from_file_location("darm_mcp_base", BASE_PATH)
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)

ORIGINAL_CALL = BASE.Gateway.call


def call_with_provenance(self, request):
    if request.get("op") == "ping":
        return ORIGINAL_CALL(self, request)

    envelope_path = os.environ.get("DARM_PROVENANCE_ENVELOPE")
    if not envelope_path:
        return {
            "ok": False,
            "code": "DENY_PROVENANCE_MISSING",
            "retryable": False,
        }

    try:
        delegation = BASE.decode(
            Path(envelope_path).read_bytes()
        )
    except Exception:
        return {
            "ok": False,
            "code": "DENY_PROVENANCE_FORMAT",
            "retryable": False,
        }

    if not isinstance(delegation, dict):
        return {
            "ok": False,
            "code": "DENY_PROVENANCE_FORMAT",
            "retryable": False,
        }

    forwarded = dict(request)
    forwarded["provenance"] = {
        "delegation": delegation,
        "invocation_nonce": secrets.token_hex(16),
    }
    return ORIGINAL_CALL(self, forwarded)


BASE.Gateway.call = call_with_provenance


if __name__ == "__main__":
    BASE.main()
