#!/usr/bin/env python3
import base64
import binascii
import hashlib
import importlib.util
import json
import os
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

BASE_PATH = Path("/usr/lib/darm-pilot/darm_gateway.py")
SPEC = importlib.util.spec_from_file_location("darm_gateway_base", BASE_PATH)
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)

PROVENANCE_CONFIG = Path(
    os.environ.get(
        "DARM_PROVENANCE_CONFIG",
        "/etc/darm/pilot-provenance.json",
    )
)


def load_provenance_config():
    stat = PROVENANCE_CONFIG.stat()
    if stat.st_uid != 0 or stat.st_mode & 0o022:
        raise RuntimeError("untrusted provenance configuration")
    data = json.loads(PROVENANCE_CONFIG.read_text())
    required = {
        "provenance_public_key",
        "provenance_nonce_dir",
        "provenance_agent_id",
        "provenance_parent_id",
    }
    if not required.issubset(data):
        raise RuntimeError("provenance configuration is incomplete")
    return data


PROVENANCE = load_provenance_config()

with open(PROVENANCE["provenance_public_key"], "rb") as stream:
    PUBLIC_KEY = serialization.load_pem_public_key(stream.read())

NONCE_DIR = Path(PROVENANCE["provenance_nonce_dir"])
if not NONCE_DIR.is_dir():
    raise RuntimeError("provenance nonce directory is unavailable")

EXPECTED_AGENT = PROVENANCE["provenance_agent_id"]
EXPECTED_PARENT = PROVENANCE["provenance_parent_id"]


def failure(code, detail):
    return BASE.response(
        False,
        code,
        retryable=False,
        detail=detail,
    )


def canonical_delegation(delegation):
    unsigned = {
        key: value
        for key, value in delegation.items()
        if key != "signature"
    }
    return json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def is_hex(value, length):
    if not isinstance(value, str) or len(value) != length:
        return False
    try:
        int(value, 16)
    except (TypeError, ValueError):
        return False
    return True


def verify_request(uid, request):
    provenance = request.get("provenance")
    if not isinstance(provenance, dict):
        return failure(
            "DENY_PROVENANCE_MISSING",
            "non-control requests require signed provenance",
        )

    delegation = provenance.get("delegation")
    invocation_nonce = provenance.get("invocation_nonce")

    if (
        not isinstance(delegation, dict)
        or not isinstance(invocation_nonce, str)
        or not 32 <= len(invocation_nonce) <= 128
    ):
        return failure("DENY_PROVENANCE_FORMAT", "invalid provenance envelope")

    signature = delegation.get("signature")
    if not isinstance(signature, str):
        return failure("DENY_PROVENANCE_SIGNATURE", "signature is missing")

    try:
        PUBLIC_KEY.verify(
            base64.b64decode(signature, validate=True),
            canonical_delegation(delegation),
        )
    except (
        ValueError,
        TypeError,
        binascii.Error,
        InvalidSignature,
    ):
        return failure(
            "DENY_PROVENANCE_SIGNATURE",
            "delegation signature is invalid",
        )

    if delegation.get("schema") != "darm-provenance-envelope/1":
        return failure("DENY_PROVENANCE_FORMAT", "unsupported envelope schema")

    if delegation.get("agent_id") != EXPECTED_AGENT:
        return failure("DENY_PROVENANCE_IDENTITY", "agent identity mismatch")

    if delegation.get("parent_agent_id") != EXPECTED_PARENT:
        return failure("DENY_PROVENANCE_PARENT", "parent identity mismatch")

    if not isinstance(delegation.get("principal_id"), str):
        return failure("DENY_PROVENANCE_FORMAT", "principal is missing")

    delegation_id = delegation.get("delegation_id")
    if not isinstance(delegation_id, str) or not delegation_id:
        return failure("DENY_PROVENANCE_FORMAT", "delegation is missing")

    issued_at = delegation.get("issued_at")
    expires_at = delegation.get("expires_at")
    if (
        type(issued_at) not in (int, float)
        or type(expires_at) not in (int, float)
        or not issued_at <= time.time() < expires_at
    ):
        return failure(
            "DENY_PROVENANCE_TIME",
            "delegation is expired or not yet valid",
        )

    if not is_hex(delegation.get("source_artifact_sha256"), 64):
        return failure(
            "DENY_PROVENANCE_FORMAT",
            "source artifact hash is invalid",
        )

    scope = delegation.get("scope")
    if not isinstance(scope, dict):
        return failure("DENY_PROVENANCE_SCOPE", "scope is missing")

    operations = scope.get("operations")
    targets = scope.get("targets")
    if (
        not isinstance(operations, list)
        or not isinstance(targets, list)
        or not all(isinstance(item, str) for item in operations)
        or not all(isinstance(item, str) for item in targets)
    ):
        return failure("DENY_PROVENANCE_SCOPE", "scope is malformed")

    operation = request.get("op")
    if operation not in operations:
        return failure(
            "DENY_PROVENANCE_SCOPE",
            "operation is outside the delegated scope",
        )

    requested_targets = []
    target = request.get("target")
    if isinstance(target, str):
        requested_targets.append(target)

    if operation == "rename":
        destination = request.get("destination")
        if isinstance(destination, str):
            requested_targets.append(destination)

    if not requested_targets or any(
        item not in targets for item in requested_targets
    ):
        return failure(
            "DENY_PROVENANCE_TARGET",
            "target is outside the delegated scope",
        )

    reservation_name = hashlib.sha256(
        (delegation_id + "\x00" + invocation_nonce).encode("utf-8")
    ).hexdigest()
    reservation_path = NONCE_DIR / reservation_name

    try:
        fd = os.open(
            reservation_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(
                {
                    "delegation_id": delegation_id,
                    "invocation_nonce": invocation_nonce,
                    "reserved_at_ns": time.time_ns(),
                },
                stream,
                sort_keys=True,
                separators=(",", ":"),
            )
    except FileExistsError:
        return failure(
            "DENY_PROVENANCE_REPLAY",
            "invocation nonce has already been used",
        )
    except OSError:
        return failure(
            "DENY_PROVENANCE_UNAVAILABLE",
            "nonce reservation failed",
        )

    return None


ORIGINAL_DISPATCH = BASE.Gateway.dispatch


def dispatch_with_provenance(self, uid, request):
    if request.get("op") != "ping":
        denial = verify_request(uid, request)
        if denial is not None:
            return denial
    return ORIGINAL_DISPATCH(self, uid, request)


BASE.Gateway.dispatch = dispatch_with_provenance


ORIGINAL_SUMMARY = BASE.request_summary


def request_summary_with_provenance(uid, request, result):
    item = ORIGINAL_SUMMARY(uid, request, result)
    provenance = request.get("provenance")
    item["provenance_present"] = isinstance(provenance, dict)

    if isinstance(provenance, dict):
        delegation = provenance.get("delegation")
        if isinstance(delegation, dict):
            for field in (
                "principal_id",
                "parent_agent_id",
                "agent_id",
                "delegation_id",
                "source_artifact_sha256",
            ):
                value = delegation.get(field)
                if isinstance(value, str):
                    item[field] = value

            item["delegation_sha256"] = hashlib.sha256(
                canonical_delegation(delegation)
            ).hexdigest()

        invocation_nonce = provenance.get("invocation_nonce")
        if isinstance(invocation_nonce, str):
            item["invocation_nonce"] = invocation_nonce

    item["provenance_result_code"] = result.get("code", "INTERNAL")
    return item


BASE.request_summary = request_summary_with_provenance


if __name__ == "__main__":
    BASE.main()
