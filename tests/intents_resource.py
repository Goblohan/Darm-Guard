"""Per-resource intents in the broker, against E24b's witnesses, plus what
the model leaves to Python (load order, fail-closed loading). Predictions first."""
import os, sys
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
def broker(lines, name):
    A = f"{D}/{name}.jsonl"
    for f in (A, A + ".key", A + ".pub.json", A + ".legacy.key", A + ".lock"):
        if os.path.exists(f): os.remove(f)
    ip = f"{D}/{name}.intents"
    open(ip, "w").write("".join(l + "\n" for l in lines))
    return B.Broker(cfg, KernelClient(), B.AuditLog(A), B.load_intents(ip), ip, B.Keys.generate()), ip
def write(b, name):
    return b.handle({"tool": "write_file", "args": [["path", "/workspace/reports/" + name], ["content", "x"]]})
def left(ip):
    return open(ip).read().splitlines()

print("1. an intent for one file: once")
b, ip = broker(["write_file path=/workspace/reports/ia.md"], "ir1")
r1, r2 = write(b, "ia.md"), write(b, "ia.md")
check("first write succeeds, second refused for want of an intent",
      (r1.get("effect"), r2.get("failure")), ("succeeded", "intent"))
check("the audit record names the intent used", r1.get("intent_consumed"), "write_file path=/workspace/reports/ia.md")
check("nothing left in the intents file", left(ip), [])

print("2. an intent for another file")
b, ip = broker(["write_file path=/workspace/reports/other.md"], "ir2")
check("refused", write(b, "ia.md").get("failure"), "intent")
check("the intent is kept", left(ip), ["write_file path=/workspace/reports/other.md"])

print("3. a tool-only intent, as before")
b, ip = broker(["write_file"], "ir3")
check("one write of any file, then none", (write(b, "ib.md").get("effect"), write(b, "ic.md").get("failure")),
      ("succeeded", "intent"))

print("4. attenuation: an intent for a delete the policy forbids")
b, ip = broker(["delete_file path=/workspace/notes.txt"], "ir4")
r = b.handle({"tool": "delete_file", "args": [["path", "/workspace/notes.txt"]]})
check("refused by the policy, not admitted by the intent", (r.get("decision"), r.get("failure")), ("reject", "semantic"))
check("notes.txt still there, and the intent kept",
      (os.path.exists(f"{W}/notes.txt"), left(ip)), (True, ["delete_file path=/workspace/notes.txt"]))

print("5. load order: broadest first, whatever the file says")
b, ip = broker(["write_file path=/workspace/reports/id.md", "write_file"], "ir5")
check("the tool-wide intent is consumed", write(b, "id.md").get("intent_consumed"), "write_file")
check("the narrower one remains", left(ip), ["write_file path=/workspace/reports/id.md"])

print("6. a rename intent binds both paths")
b, ip = broker(["write_file",
                "rename_file path=/workspace/reports/ie.md destination=/workspace/reports/ie2.md"], "ir6")
write(b, "ie.md")
wrong = b.handle({"tool": "rename_file", "args": [["path", "/workspace/reports/ie.md"],
                                                  ["destination", "/workspace/reports/ie3.md"]]})
right = b.handle({"tool": "rename_file", "args": [["path", "/workspace/reports/ie.md"],
                                                  ["destination", "/workspace/reports/ie2.md"]]})
check("wrong destination refused, right one succeeds", (wrong.get("failure"), right.get("effect")),
      ("intent", "succeeded"))
check("moved where the intent said", (os.path.exists(f"{R}/ie2.md"), os.path.exists(f"{R}/ie3.md")), (True, False))

print("7. malformed intents refuse to load")
bad = ["write_file path", "write_file path=", "write_file path=/workspace/reports/../x.md",
       "write_file path=/workspace/a.md path=/workspace/b.md"]
refused = []
for line in bad:
    try:
        B._parse_intent(line); refused.append(False)
    except ValueError:
        refused.append(True)
check("all four refused", refused, [True, True, True, True])

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
