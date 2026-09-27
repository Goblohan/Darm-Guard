"""Three-state consumption (E24d Part 4) in the broker: an intent is reserved at
admission and settled once the outcome is durable, by B5's verdict on a fresh
observation. Confirmed success spends it; a confirmed non-effect returns it;
anything else keeps it reserved, settled at the next startup. Predictions first."""
import json, os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; W = f"{D}/workspace"; R = f"{W}/reports"
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")
def broker(name, lines, keys=None):
    A, ip = f"{D}/{name}.jsonl", f"{D}/{name}.intents"
    if keys is None:
        for f in (A, A + ".key", A + ".pub.json", A + ".lock", ip, ip + ".reserved"):
            if os.path.exists(f): os.remove(f)
        open(ip, "w").write("".join(l + "\n" for l in lines))
        keys = B.Keys.generate()
    return B.Broker(cfg, KernelClient(), B.AuditLog(A), B.load_intents(ip), ip, keys), ip, keys
def write(b, path, content="x"):
    return b.handle({"tool": "write_file", "args": [["path", path], ["content", content]]})
def left(ip):
    return [l for l in open(ip).read().split("\n") if l.strip()]
def reserved(ip):
    return json.load(open(ip + ".reserved")) if os.path.exists(ip + ".reserved") else {}

print("1. success spends")
b, ip, _ = broker("ts1", ["write_file"])
r = write(b, "/workspace/reports/t1.md")
check("spent, nothing left or reserved",
      (r.get("effect"), r.get("intent_state"), r.get("intent_consumed"), left(ip), reserved(ip)),
      ("succeeded", "spent", "write_file", [], {}))

print("2. P16: a failed effect no longer burns the intent")
x = "/workspace/reports/new/t.md"
b, ip, _ = broker("ts2", [f"write_file path={x}"])
r1 = write(b, x)
check("fails, and the intent is returned", (r1.get("effect"), r1.get("intent_state"), left(ip)),
      ("failed", "returned", [f"write_file path={x}"]))
os.makedirs(f"{R}/new")
r2 = write(b, x)
check("the retry succeeds and spends it", (r2.get("effect"), r2.get("intent_state"), left(ip)),
      ("succeeded", "spent", []))

print("3. a rename refused by an occupied destination returns its intent")
mv = "rename_file path=/workspace/reports/r1.md destination=/workspace/reports/r2.md"
b, ip, _ = broker("ts3", ["write_file", mv])
write(b, "/workspace/reports/r1.md")
open(f"{R}/r2.md", "w").write("someone else's file")
r = b.handle({"tool": "rename_file", "args": [["path", "/workspace/reports/r1.md"],
                                             ["destination", "/workspace/reports/r2.md"]]})
check("refused, returned", (r.get("effect"), r.get("intent_state"), left(ip)), ("failed", "returned", [mv]))

print("4. an error raised after the effect happened")
b, ip, _ = broker("ts4", ["write_file"])
orig = B._execute
def after(*a, **kw):
    orig(*a, **kw)
    return {"error": "simulated failure after the effect"}
B._execute = after
try:
    r = write(b, "/workspace/reports/t4.md", "late")
finally:
    B._execute = orig
check("reported failed, but observed as done: spent, not returned",
      (r.get("effect"), r.get("reconciliation"), r.get("intent_state")), ("failed", "confirmedSuccess", "spent"))

print("5. a crash before any effect")
b, ip, keys = broker("ts5", ["write_file"])
def crash(*a, **kw):
    raise KeyboardInterrupt
B._execute = crash
try:
    write(b, "/workspace/reports/t5.md")
except KeyboardInterrupt:
    pass
finally:
    B._execute = orig
check("left reserved on disk", (len(reserved(ip)), left(ip)), (1, []))
b2, _, _ = broker("ts5", None, keys)
b2.reconcile_pending(); b2.settle_reserved()
check("after restart: returned", (reserved(ip), left(ip)), ({}, ["write_file"]))

print("6. a crash after the effect")
b, ip, keys = broker("ts6", ["write_file"])
def crash_after(*a, **kw):
    orig(*a, **kw)
    raise KeyboardInterrupt
B._execute = crash_after
try:
    write(b, "/workspace/reports/t6.md", "done")
except KeyboardInterrupt:
    pass
finally:
    B._execute = orig
b2, _, _ = broker("ts6", None, keys)
b2.reconcile_pending(); b2.settle_reserved()
check("after restart: spent", (reserved(ip), left(ip)), ({}, []))

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
