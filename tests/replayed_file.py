"""A file written by the broker, copied aside with its attestation, deleted by
the broker, and copied back: its attestation names its location and was really
minted, so only the log can catch it (darm-monitor B8p: the attestation binds
origin and location; the log binds freshness). Predictions first."""
import os, shutil, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; R = f"{D}/workspace/reports"
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
AUDIT = f"{D}/replay.jsonl"
for f in (AUDIT, AUDIT + ".key", AUDIT + ".pub.json", AUDIT + ".lock"):
    if os.path.exists(f): os.remove(f)
keys = B.Keys.generate()
b = B.Broker(cfg, KernelClient(), B.AuditLog(AUDIT), None, None, keys)
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")
def findings(name):
    return [x["finding"] for x in B.verify_world(cfg, AUDIT, keys)["findings"]
            if x["target"] == "/workspace/reports/" + name]

w = b.handle({"tool": "write_file", "args": [["path", "/workspace/reports/rp.md"], ["content", "once"]]})
check("written and attested", (w.get("effect"), w.get("attested")), ("succeeded", True))
shutil.copy2(f"{R}/rp.md", f"{D}/rp.bak")                 # outside the broker; copy2 keeps the attestation
d = b.handle({"tool": "delete_file", "args": [["path", "/workspace/reports/rp.md"]]})
check("deleted by the broker; verification clean", (d.get("effect"), findings("rp.md")), ("succeeded", []))
shutil.copy2(f"{D}/rp.bak", f"{R}/rp.md")                 # the replay
f = findings("rp.md")
check("after the replay: flagged by the log, exactly", f, ["the log records a deletion but the file exists"])
check("and not by the path check (the attestation names this location)",
      "attestation forged or moved" in f, False)
print(f"  findings: {f}")

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
