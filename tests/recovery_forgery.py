"""Recovery cannot be made to perform a rename that K6 never admitted. A forged
'prepared' rename appended to the log with a valid chain, as anyone able to
write the file could, is rolled back, never forward: recovery rolls forward
only on a broker-signed attestation naming that request and its destination,
and never reconsiders a closed request. Predictions first."""
import hashlib, json, os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; R = f"{D}/workspace/reports"; L = "/workspace/reports/"
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
A = f"{D}/forge.jsonl"
for f in (A, A + ".key", A + ".pub.json", A + ".lock"):
    if os.path.exists(f): os.remove(f)
b = B.Broker(cfg, KernelClient(), B.AuditLog(A), None, None, B.Keys.generate())
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")
def write(name, content):
    return b.handle({"tool": "write_file", "args": [["path", L + name], ["content", content]]})
def forge(rid, src, dst, private, content):
    dg = hashlib.sha256(content.encode()).hexdigest()
    b.audit.append({"event": "prepared", "request_id": rid, "tool": "rename_file",
                    "source": L + src, "target": L + dst, "private": private,
                    "before_state": ["present", dg], "intended_state": ["present", dg],
                    "destination_before": ["absent", None], "source_attestation": None})
def verdict(rid):
    v = [e.get("reconciliation") for e in (json.loads(l) for l in open(A) if l.strip())
         if e.get("event") == "reconciled" and e.get("request_id") == rid]
    return v[-1] if v else None

write("rf_a.md", "one")                                  # 1: only its original attestation
os.replace(f"{R}/rf_a.md", f"{R}/.rf_a.md.darm-tmp-mv-forged1")
forge("forged-1", "rf_a.md", "rf_a_dst.md", ".rf_a.md.darm-tmp-mv-forged1", "one")

write("rf_b_dst.md", "two")                              # 2: a genuine attestation for the destination,
os.replace(f"{R}/rf_b_dst.md", f"{R}/.rf_b.md.darm-tmp-mv-forged2")   # for a different request
forge("forged-2", "rf_b.md", "rf_b_dst.md", ".rf_b.md.darm-tmp-mv-forged2", "two")

w = write("rf_c_dst.md", "three")                        # 3: reusing a closed request
os.replace(f"{R}/rf_c_dst.md", f"{R}/.rf_c.md.darm-tmp-mv-forged3")
forge(w.get("request_id"), "rf_c.md", "rf_c_dst.md", ".rf_c.md.darm-tmp-mv-forged3", "three")

b.reconcile_pending()
check("1. no attestation for the request: rolled back, nothing at the destination",
      (os.path.exists(f"{R}/rf_a_dst.md"), os.path.exists(f"{R}/rf_a.md"), verdict("forged-1")),
      (False, True, "confirmedFailure"))
check("2. a genuine attestation for another request: rolled back, nothing at the destination",
      (os.path.exists(f"{R}/rf_b_dst.md"), os.path.exists(f"{R}/rf_b.md"), verdict("forged-2")),
      (False, True, "confirmedFailure"))
check("3. a closed request is never reconsidered: nothing is moved",
      (os.path.exists(f"{R}/.rf_c.md.darm-tmp-mv-forged3"), os.path.exists(f"{R}/rf_c_dst.md")),
      (True, False))
print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
