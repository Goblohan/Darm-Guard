"""P14: repeated argument names are refused before anything evaluates the
proposal, so what is decided and what is executed cannot diverge (execution
reads arguments through a dict, where the last occurrence wins). Pins
parse_proposal's explicit check; it held before this test existed, but
nothing would have noticed its removal. Predictions written first."""
import os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; W = f"{D}/workspace"
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")

print("1. the parser")
check("repeated name refused", B.parse_proposal({"tool": "write_file", "args": [["path", "/a"], ["path", "/b"]]}), None)
check("repeated name, same value, refused too",
      B.parse_proposal({"tool": "write_file", "args": [["path", "/a"], ["path", "/a"]]}), None)
check("distinct names accepted",
      B.parse_proposal({"tool": "write_file", "args": [["path", "/a"], ["content", "x"]]}),
      ("write_file", [("path", "/a"), ("content", "x")]))

print("2. through the broker: one path the policy allows, one it forbids")
A = f"{D}/p14.jsonl"
for f in (A, A + ".key", A + ".pub.json", A + ".legacy.key", A + ".lock"):
    if os.path.exists(f): os.remove(f)
b = B.Broker(cfg, KernelClient(), B.AuditLog(A), None, None, B.Keys.generate())
b.handle({"tool": "write_file", "args": [["path", "/workspace/reports/p14.md"], ["content", "x"]]})
notes = open(f"{W}/notes.txt").read()
control = b.handle({"tool": "delete_file", "args": [["path", "/workspace/notes.txt"]]})
check("control: deleting notes.txt alone is refused by the policy", control.get("failure"), "semantic")
for label, args in (
        ("delete, allowed first", [["path", "/workspace/reports/p14.md"], ["path", "/workspace/notes.txt"]]),
        ("delete, forbidden first", [["path", "/workspace/notes.txt"], ["path", "/workspace/reports/p14.md"]])):
    r = b.handle({"tool": "delete_file", "args": args})
    check(f"{label}: refused as malformed", (r.get("decision"), r.get("effect"), r.get("error")),
          ("reject", "none", "malformed proposal"))
r = b.handle({"tool": "write_file", "args": [["path", "/workspace/reports/p14b.md"],
                                             ["path", "/workspace/notes.txt"], ["content", "OVERWRITTEN"]]})
check("write with two paths: refused as malformed", r.get("error"), "malformed proposal")
check("notes.txt unchanged, the allowed file untouched",
      (open(f"{W}/notes.txt").read() == notes, os.path.exists(f"{W}/reports/p14.md")), (True, True))

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
