"""E30's lineage at runtime: a renamed file's attestation leads back, through
the rename's recorded source attestation, to the write that intended exactly
its content (darm-monitor E30: Lineage, lineage_origin, rename_placed_lineage).
Predictions first."""
import hashlib, json, os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; R = f"{D}/workspace/reports"; L = "/workspace/reports/"
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
A = f"{D}/lineage.jsonl"
for f in (A, A + ".key", A + ".pub.json", A + ".lock"):
    if os.path.exists(f): os.remove(f)
keys = B.Keys.generate()
b = B.Broker(cfg, KernelClient(), B.AuditLog(A), None, None, keys)
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")

C = "content authorized once, then moved"
digest = hashlib.sha256(C.encode()).hexdigest()
w = b.handle({"tool": "write_file", "args": [["path", L + "rl_a.md"], ["content", C]]})
m = b.handle({"tool": "rename_file", "args": [["path", L + "rl_a.md"], ["destination", L + "rl_b.md"]]})
r1, r2 = w.get("request_id"), m.get("request_id")
check("1. write and rename succeed, under different requests", (w.get("effect"), m.get("effect"), r1 != r2),
      ("succeeded", "succeeded", True))

att = B._check_attestation(keys, os.getxattr(f"{R}/rl_b.md", B.XATTR))
check("2. the renamed file is attested by the rename, for its path and content",
      (att["rid"] == r2, att["target"], att["digest"] == digest), (True, L + "rl_b.md", True))

prepared = {e["request_id"]: e for e in (json.loads(l) for l in open(A) if l.strip()) if e.get("event") == "prepared"}
pm = prepared[r2]
src_att = B._check_attestation(keys, pm.get("source_attestation"))
check("3. the rename recorded the source attestation it moved: the write's request, its path, the content",
      (pm.get("source"), src_att and src_att["rid"] == r1, src_att and src_att["target"], src_att and src_att["digest"] == digest),
      (L + "rl_a.md", True, L + "rl_a.md", True))

pw = prepared[r1]
check("4. that request's prepared record is a write that intended exactly this content",
      (pw.get("target"), pw.get("intended_state")), (L + "rl_a.md", ["present", digest]))

chain = [att["rid"], src_att["rid"]] if src_att else [att["rid"]]
check("5. the lineage: [rename, write], ending at the write", chain == [r2, r1], True)

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
