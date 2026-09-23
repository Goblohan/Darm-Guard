import json, socket, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from darm_guard.broker import BrokerClient

SOCK = "/tmp/darm-broker.sock"
c = BrokerClient(SOCK)

def raw(msg):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(SOCK)
        s.sendall((json.dumps(msg) + "\n").encode())
        return json.loads(s.makefile().readline())

def err(r):
    return r.get("error") or ""

CASES = [
    ("user-requested read", lambda: c.propose("read_file", {"path": "/workspace/notes.txt"}),
     lambda r: r["decision"] == "admit" and "content" in r),
    ("agent-invented path", lambda: c.propose("read_file", {"path": "/workspace/other.txt"}),
     lambda r: r["decision"] == "reject" and r.get("failure") == "provenance"),
    ("path traversal", lambda: c.propose("read_file", {"path": "/workspace/../secret.txt"}),
     lambda r: r["decision"] == "reject" and "normal form" in err(r)),
    ("symlink escape", lambda: c.propose("read_file", {"path": "/workspace/link.txt"}),
     lambda r: r.get("executed") is False and "content" not in r and "escapes" in err(r)),
    ("self-vouching provenance", lambda: raw({"tool": "read_file",
                                              "args": [["path", "/workspace/other.txt"]],
                                              "prov": "authoritative"}),
     lambda r: r["decision"] == "reject" and "malformed" in err(r)),
    ("unknown tool", lambda: c.propose("delete_file", {"path": "/workspace/notes.txt"}),
     lambda r: r["decision"] == "reject" and r.get("failure") == "observation"),
    ("list registered dir", lambda: c.propose("list_dir", {"path": "/workspace/docs"}),
     lambda r: r["decision"] == "admit" and "entries" in r),
]

passed = 0
for name, run, ok in CASES:
    r = run()
    good = ok(r)
    passed += good
    print("PASS" if good else "FAIL", name, "->", json.dumps(r)[:110])
print(f"\n{passed}/{len(CASES)} passed")
sys.exit(0 if passed == len(CASES) else 1)
