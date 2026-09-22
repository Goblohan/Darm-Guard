import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from datetime import datetime, timedelta
from darm_guard import KernelGuard, KernelPolicy, ToolRule, ArgRule

KERNEL = os.environ.get("DARM_KERNEL_PATH", "")

POLICY = KernelPolicy(tools=(
    ToolRule("file_read", (ArgRule("path", allowed_prefixes=("/workspace/",)),)),
    ToolRule("send_email", (ArgRule("to", allowed_values=("team@perceptra.ai",)),)),
))

def guard(**kw):
    kw.setdefault("tools", {"file_read"})
    kw.setdefault("default_provenance", "authoritative")
    return KernelGuard(POLICY, kernel_path=KERNEL, **kw)

def test_admit_allowed_path():
    assert guard().check("file_read", {"path": "/workspace/notes.txt"}).admitted

def test_semantic_forbidden_path():
    d = guard().check("file_read", {"path": "/etc/passwd"})
    assert not d.admitted and d.failure == "semantic"

def test_provenance_untrusted_value():
    d = guard().check("file_read", {"path": "/workspace/notes.txt"},
                      provenance={"path": "untrusted"})
    assert not d.admitted and d.failure == "provenance"

def test_observation_unknown_tool():
    d = guard().check("code_exec", {"cmd": "ls"})
    assert not d.admitted and d.failure == "observation"

def test_authority_not_in_credential():
    d = guard().check("send_email", {"to": "team@perceptra.ai"})
    assert not d.admitted and d.failure == "authority"

def test_temporal_expired():
    g = guard(issued_at=datetime(2026, 9, 1), ttl=timedelta(days=7))
    d = g.check("file_read", {"path": "/workspace/notes.txt"}, now=datetime(2026, 9, 15))
    assert not d.admitted and d.failure == "temporal"

def test_fails_closed_without_kernel():
    g = KernelGuard(POLICY, tools={"file_read"}, default_provenance="authoritative",
                    kernel_path="/nonexistent/darmkernel")
    d = g.check("file_read", {"path": "/workspace/notes.txt"})
    assert not d.admitted and d.error

def test_default_provenance_required():
    try:
        KernelGuard(POLICY, tools={"file_read"}, default_provenance="trusted")
        assert False, "invalid provenance accepted"
    except ValueError:
        pass

if __name__ == "__main__":
    if not KERNEL:
        print("Set DARM_KERNEL_PATH to the darmkernel binary"); sys.exit(2)
    passed = 0
    tests = [(n, f) for n, f in list(globals().items()) if n.startswith("test_")]
    for name, fn in tests:
        try:
            fn(); passed += 1; print("PASS", name)
        except AssertionError as e:
            print("FAIL", name, e)
    print(f"\n{passed}/{len(tests)} passed")
    sys.exit(0 if passed == len(tests) else 1)
