"""A rename attests its destination, so it must only move content the broker
wrote: the source must carry a valid attestation for its own path and current
content (darm-monitor E29: content-faithful renames launder foreign content;
attestation-faithful ones guarantee every attested content came from a write).
Predictions first."""
import os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; R = f"{D}/workspace/reports"
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
A = f"{D}/launder.jsonl"
for f in (A, A + ".key", A + ".pub.json", A + ".lock"):
    if os.path.exists(f): os.remove(f)
b = B.Broker(cfg, KernelClient(), B.AuditLog(A), None, None, B.Keys.generate())
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")
L = "/workspace/reports/"
def rename(a, z):
    return b.handle({"tool": "rename_file", "args": [["path", L + a], ["destination", L + z]]})
def write(a, c):
    return b.handle({"tool": "write_file", "args": [["path", L + a], ["content", c]]})

open(f"{R}/lf_src.md", "w").write("never written by the broker")
r = rename("lf_src.md", "lf_dst.md")
check("1. foreign file: refused, nothing moved",
      (r.get("failure"), os.path.exists(f"{R}/lf_src.md"), os.path.exists(f"{R}/lf_dst.md")),
      ("attestation", True, False))

write("lw_src.md", "written by the broker")
r = rename("lw_src.md", "lw_dst.md")
check("2. broker-written file: renamed", (r.get("effect"), os.path.exists(f"{R}/lw_dst.md")), ("succeeded", True))

write("lt_src.md", "original")
with open(f"{R}/lt_src.md", "w") as fh: fh.write("tampered")          # keeps the attestation
r = rename("lt_src.md", "lt_dst.md")
check("3. tampered file: refused", (r.get("failure"), os.path.exists(f"{R}/lt_dst.md")), ("attestation", False))

write("lm_orig.md", "moved in")
os.replace(f"{R}/lm_orig.md", f"{R}/lm_src.md")                   # outside the broker
r = rename("lm_src.md", "lm_dst.md")
check("4. file moved in from elsewhere: refused", (r.get("failure"), os.path.exists(f"{R}/lm_dst.md")),
      ("attestation", False))

import json
refusals = [e for e in (json.loads(l) for l in open(A) if l.strip())
            if e.get("event") == "decision" and e.get("failure") == "attestation"]
check("5. every refused rename is recorded in the audit log", len(refusals), 3)

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
