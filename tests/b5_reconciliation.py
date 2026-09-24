"""B5 target-state reconciliation correspondence and lifecycle tests."""

import hashlib
import json
import os
import sys
import tempfile

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

from darm_guard.broker import (
    AuditLog,
    Broker,
    BrokerConfig,
    _intended_state,
    _reconcile,
    _target_state,
)
from darm_guard.kernel import KernelDecision


class AdmitKernel:
    def decide(self, request):
        return KernelDecision(True)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def check(name, condition, detail=""):
    results.append(bool(condition))
    print(("PASS " if condition else "FAIL ") + name, str(detail)[:160])


results = []


# B5 correspondence against the production helpers.
with tempfile.TemporaryDirectory(prefix="darm-b5-correspondence-") as d:
    target = os.path.join(d, "target.txt")

    before = _target_state(target)
    intended = ("present", digest("B5-INTENDED"))

    with open(target, "w") as f:
        f.write("B5-INTENDED")

    observed = _target_state(target)

    check(
        "production helper confirms intended state",
        before == ("absent", None)
        and observed == intended
        and _reconcile(before, intended, observed) == "confirmedSuccess",
        (before, intended, observed),
    )

    os.remove(target)

    before = _target_state(target)
    observed = _target_state(target)

    check(
        "production helper confirms before state",
        before == ("absent", None)
        and observed == before
        and _reconcile(before, intended, observed) == "confirmedFailure",
        (before, intended, observed),
    )

    with open(target, "w") as f:
        f.write("B5-OTHER")

    observed = _target_state(target)

    check(
        "production helper leaves unexpected state unresolved",
        observed != intended
        and observed != before
        and _reconcile(before, intended, observed) == "unresolved",
        (before, intended, observed),
    )

    unavailable = ("unavailable", "controlled observation failure")

    check(
        "production helper leaves unavailable observation unresolved",
        _reconcile(before, intended, unavailable) == "unresolved",
        _reconcile(before, intended, unavailable),
    )


def make_broker(root):
    workspace = os.path.join(root, "workspace")
    os.mkdir(workspace)

    cfg = BrokerConfig(
        policy={
            "tools": [{
                "tool": "write_file",
                "rules": [
                    {
                        "key": "path",
                        "allowedValues": [],
                        "allowedPrefixes": ["/workspace/"],
                    },
                    {
                        "key": "content",
                        "allowedValues": [],
                        "allowedPrefixes": [""],
                        "payload": True,
                    },
                ],
            }]
        },
        credential_tools=["write_file"],
        registry=[],
        workspace=workspace,
    )

    audit = AuditLog(os.path.join(root, "audit.jsonl"))
    return Broker(cfg, AdmitKernel(), audit), workspace


def proposal(path, content):
    return {
        "tool": "write_file",
        "args": [
            ["path", path],
            ["content", content],
        ],
    }


# B5 lifecycle correspondence.
with tempfile.TemporaryDirectory(prefix="darm-b5-lifecycle-") as d:
    broker, workspace = make_broker(d)

    target = os.path.join(workspace, "success.txt")
    response = broker.handle(
        proposal("/workspace/success.txt", "B5-SUCCESS")
    )

    check(
        "successful write gets confirmedSuccess",
        response.get("effect") == "succeeded"
        and response.get("executed") is True
        and response.get("reconciliation") == "confirmedSuccess"
        and open(target).read() == "B5-SUCCESS",
        response,
    )

    target = os.path.join(workspace, "failure.txt")
    with open(target, "w") as f:
        f.write("B5-BEFORE")

    import darm_guard.broker as broker_module

    original_execute = broker_module._execute

    def forced_failure(cfg, inv):
        return {"error": "controlled B5 execution failure"}

    broker_module._execute = forced_failure

    try:
        response = broker.handle(
            proposal("/workspace/failure.txt", "B5-INTENDED")
        )
    finally:
        broker_module._execute = original_execute

    check(
        "failed write gets confirmedFailure",
        response.get("effect") == "failed"
        and response.get("executed") is False
        and response.get("reconciliation") == "confirmedFailure"
        and open(target).read() == "B5-BEFORE",
        response,
    )

    original_append = AuditLog.append

    def fail_outcome(self, entry):
        if entry.get("event") == "outcome":
            raise PermissionError("controlled B5 outcome-evidence failure")
        return original_append(self, entry)

    AuditLog.append = fail_outcome

    target = os.path.join(workspace, "unrecorded.txt")
    response = broker.handle(
        proposal("/workspace/unrecorded.txt", "B5-UNRECORDED")
    )

    check(
        "unrecorded outcome retains state confirmation",
        response.get("effect") == "succeeded"
        and response.get("executed") is True
        and response.get("evidence") == "outcome_unrecorded"
        and response.get("reconciliation") == "confirmedSuccess"
        and open(target).read() == "B5-UNRECORDED",
        response,
    )

    AuditLog.append = original_append


# B5 is deliberately scoped to write_file.
with tempfile.TemporaryDirectory(prefix="darm-b5-scope-") as d:
    broker, workspace = make_broker(d)

    target = os.path.join(workspace, "read.txt")
    with open(target, "w") as f:
        f.write("B5-READ")

    response = broker.handle({
        "tool": "read_file",
        "args": [["path", "/workspace/read.txt"]],
    })

    check(
        "read_file has no B5 reconciliation claim",
        response.get("executed") is True
        and response.get("content") == "B5-READ"
        and "reconciliation" not in response,
        response,
    )


print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
