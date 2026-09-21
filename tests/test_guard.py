import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from datetime import datetime, timedelta
from darm_guard import DARMGuard, Policy, Credential, Mode, FailureKind, DriftLevel

POLICY = Policy(authorized_tools=frozenset(["file_read", "web_search"]))
CRED = Credential(tools=frozenset(["file_read"]))

def test_observe_never_blocks():
    g = DARMGuard(policy=POLICY, credential=CRED)
    r = g.check({"code_exec"})
    assert r.admitted
    assert r.drift == DriftLevel.VIOLATION

def test_govern_blocks_unknown_tool():
    g = DARMGuard(policy=POLICY, credential=CRED, mode=Mode.GOVERN)
    assert g.check({"file_read"}).admitted
    r = g.check({"code_exec"})
    assert not r.admitted
    assert r.failures[0].kind == FailureKind.OBSERVATION

def test_govern_admits_policy_authorized_drift():
    g = DARMGuard(policy=POLICY, credential=CRED, mode=Mode.GOVERN)
    r = g.check({"web_search"})
    assert r.admitted
    assert r.drift == DriftLevel.DRIFT

def test_temporal_expiry():
    cred = Credential(tools=frozenset(["file_read"]),
                      issued_at=datetime(2026, 9, 1), ttl=timedelta(days=7))
    g = DARMGuard(policy=POLICY, credential=cred, mode=Mode.GOVERN)
    assert g.check({"file_read"}, now=datetime(2026, 9, 5)).admitted
    r = g.check({"file_read"}, now=datetime(2026, 9, 15))
    assert not r.admitted
    assert r.failures[0].kind == FailureKind.TEMPORAL_FRESHNESS

if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("PASS", name)
