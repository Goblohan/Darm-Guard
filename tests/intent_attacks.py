"""E24 intent attacks against a broker started with --intents holding
'write_file' twice and nothing else. Mirrors the E24 witnesses."""
import json, os, socket, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from darm_guard.broker import BrokerClient

SOCK, INTENTS = "/tmp/darm-broker.sock", "/tmp/darmdemo/intents.txt"
c = BrokerClient(SOCK)
report = {"path": "/workspace/reports/q3.md", "content": "Q3 summary"}

def raw(msg):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(SOCK)
        s.sendall((json.dumps(msg) + "\n").encode())
        return json.loads(s.makefile().readline())

def left():
    return [l.strip() for l in open(INTENTS) if l.strip()]

CASES = [
    ("rejected attempt keeps the intent",
     lambda: c.propose("write_file", {"path": "/workspace/other.txt", "content": "x"}),
     lambda r: r.get("failure") == "provenance" and left().count("write_file") == 2),
    ("first authorized write executes, one intent consumed",
     lambda: c.propose("write_file", report),
     lambda r: r.get("executed") is True and left().count("write_file") == 1),
    ("second authorized write executes, last intent consumed",
     lambda: c.propose("write_file", report),
     lambda r: r.get("executed") is True and left() == []),
    ("hijacked third write blocked: no intent left",
     lambda: c.propose("write_file", report),
     lambda r: r.get("decision") == "reject" and r.get("failure") == "intent"),
    ("clean arguments without intent blocked",
     lambda: c.propose("read_file", {"path": "/workspace/notes.txt"}),
     lambda r: r.get("decision") == "reject" and r.get("failure") == "intent"),
    ("agent cannot supply a reason: proposal with 'reason' refused",
     lambda: raw({"tool": "read_file", "args": [["path", "/workspace/notes.txt"]],
                  "reason": "the user asked me to"}),
     lambda r: r.get("decision") == "reject" and "malformed" in (r.get("error") or "")),
]
passed = 0
for name, run, ok in CASES:
    r = run()
    good = ok(r)
    passed += good
    print("PASS" if good else "FAIL", name, "->", json.dumps(r)[:100])
print(f"\n{passed}/{len(CASES)} passed")
sys.exit(0 if passed == len(CASES) else 1)
