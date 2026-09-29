"""A file moved outside the broker onto a path whose log entry expects the same
content: the log comparison passes, so only the attestation's signed path can
catch it. (darm-monitor E27: in B8, identity rests on the log alone; the
runtime also signs the target and checks it against the location.)
Predictions first."""
import os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; R = f"{D}/workspace/reports"
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
AUDIT = f"{D}/moved.jsonl"
for f in (AUDIT, AUDIT + ".key", AUDIT + ".pub.json", AUDIT + ".lock"):
    if os.path.exists(f): os.remove(f)
keys = B.Keys.generate()
b = B.Broker(cfg, KernelClient(), B.AuditLog(AUDIT), None, None, keys)
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")
def write(name, content):
    return b.handle({"tool": "write_file", "args": [["path", "/workspace/reports/" + name], ["content", content]]})
def findings(name):
    return [x["finding"] for x in B.verify_world(cfg, AUDIT, keys)["findings"]
            if x["target"] == "/workspace/reports/" + name]

w1, w2 = write("ma.md", "same content"), write("mb.md", "same content")
check("both written and attested", (w1.get("effect"), w1.get("attested"), w2.get("effect"), w2.get("attested")),
      ("succeeded", True, "succeeded", True))
check("before the move: both clean", (findings("ma.md"), findings("mb.md")), ([], []))
os.replace(f"{R}/ma.md", f"{R}/mb.md")      # outside the broker; the attestation travels with the file
check("after: mb.md flagged exactly by the path check", findings("mb.md"), ["attestation forged or moved"])
check("after: ma.md flagged too (its logged write is gone)", len(findings("ma.md")) > 0, True)

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
