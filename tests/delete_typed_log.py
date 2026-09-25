"""verify_world with a typed log (B8). A delete_file outcome record is what
the real tool will append; here it is appended directly, before the tool
exists. Predictions printed next to measurements."""
import os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; WS = f"{D}/workspace"; AUDIT = f"{D}/delete_typed.jsonl"
for f in (AUDIT, AUDIT + ".key", AUDIT + ".lock"):
    if os.path.exists(f):
        os.remove(f)
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
key = os.urandom(32)
broker = B.Broker(cfg, KernelClient(), B.AuditLog(AUDIT), None, None, key)

def write(name, content):
    r = broker.handle({"tool": "write_file",
                       "args": [["path", "/workspace/reports/" + name], ["content", content]]})
    assert r.get("effect") == "succeeded", r
    return "/workspace/reports/" + name, os.path.join(WS, "reports", name)

def log_delete(t, rid):
    broker.audit.append({"event": "outcome", "request_id": rid, "tool": "delete_file",
                         "target": t, "effect": "succeeded"})

def findings(t):
    return [x["finding"] for x in B.verify_world(cfg, AUDIT, key)["findings"] if x["target"] == t]

results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")

print("A: unlogged deletion")
t, real = write("a.md", "A"); os.unlink(real)
check("flagged", findings(t), ["the log records a write but the file is gone"])

print("B: logged deletion")
t, real = write("b.md", "B"); os.unlink(real); log_delete(t, "del-b")
check("flagged", findings(t), [])

print("C: logged deletion, but the file still exists")
t, real = write("c.md", "C"); log_delete(t, "del-c")
check("flagged", findings(t), ["the log records a deletion but the file exists"])

print("D: logged deletion, then a new broker write")
t, real = write("d.md", "D1"); os.unlink(real); log_delete(t, "del-d"); write("d.md", "D2")
check("flagged", findings(t), [])

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
