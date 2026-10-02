"""Every path-valued argument is checked for normal form before the decision:
a rename's destination containing '..' is refused as malformed, not admitted by
a prefix rule and caught only at execution. Predictions first."""
import json, os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient
D = "/tmp/darmdemo"; A = f"{D}/dest.jsonl"; L = "/workspace/reports/"
for f in (A, A + ".key", A + ".pub.json", A + ".lock"):
    if os.path.exists(f): os.remove(f)
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
b = B.Broker(cfg, KernelClient(), B.AuditLog(A), None, None, B.Keys.generate())
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")
b.handle({"tool": "write_file", "args": [["path", L + "dn.md"], ["content", "inside reports"]]})
r = b.handle({"tool": "rename_file", "args": [["path", L + "dn.md"], ["destination", L + "../dn_escaped.md"]]})
check("1. a '..' destination is refused before the decision",
      (r.get("decision"), r.get("error")), ("reject", "path not in normal form"))
events = [json.loads(l) for l in open(A) if l.strip()]
check("2. nothing was prepared for it (no admission recorded)",
      any(e.get("event") == "prepared" and e.get("request_id") == r.get("request_id") for e in events), False)
check("3. the source is untouched and nothing escaped",
      (os.path.exists(f"{D}/workspace/reports/dn.md"), os.path.exists(f"{D}/workspace/dn_escaped.md")), (True, False))
r = b.handle({"tool": "write_file", "args": [["path", L + "../dn_w.md"], ["content", "x"]]})
check("4. a '..' path is still refused the same way", (r.get("decision"), r.get("error")),
      ("reject", "path not in normal form"))
print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
