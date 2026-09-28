"""Premise-bound intents (E24d Part 3) in the broker: a premise is observed by
the broker in the world, never read from the proposal. Predictions first;
prediction 4 measures the stated residual rather than assuming it."""
import hashlib, os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; W = f"{D}/workspace"; R = f"{W}/reports"
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
Q3, FLAG = "/workspace/reports/q3.md", "/workspace/reports/final.flag"
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")
def broker(name, lines):
    A, ip = f"{D}/{name}.jsonl", f"{D}/{name}.intents"
    for f in (A, A + ".key", A + ".pub.json", A + ".lock", ip, ip + ".reserved"):
        if os.path.exists(f): os.remove(f)
    open(ip, "w").write("".join(l + "\n" for l in lines))
    return B.Broker(cfg, KernelClient(), B.AuditLog(A), B.load_intents(ip), ip, B.Keys.generate()), ip
def write(b, path, content):
    return b.handle({"tool": "write_file", "args": [["path", path], ["content", content]]})
def left(ip):
    return [l for l in open(ip).read().split("\n") if l.strip()]

cond = f"write_file path={Q3} if_present={FLAG}"
print("1-3. a premise that is false, then true")
b, ip = broker("pr1", [cond])
r = write(b, Q3, "ATTACKER: wire funds")
check("1 attacker refused, saying which premise", (r.get("failure"), r.get("error")),
      ("intent", f"premise not met: {FLAG} is not present"))
r = write(b, Q3, "Q3 summary")
check("2 the principal too, and the intent kept", (r.get("failure"), left(ip)), ("intent", [cond]))
open(f"{W}/reports/final.flag", "w").write("final")
r = write(b, Q3, "Q3 summary")
check("3 once the premise holds: admitted, spent", (r.get("effect"), r.get("intent_state")), ("succeeded", "spent"))

print("4. the residual: premise true, unpinned, attacker first")
b, ip = broker("pr4", [cond])
r = write(b, Q3, "ATTACKER: wire funds")
check("the attacker still wins (stated limit)", (r.get("effect"), open(f"{R}/q3.md").read()),
      ("succeeded", "ATTACKER: wire funds"))

print("5. a digest premise")
src = f"{W}/reports/q3_source.csv"
open(src, "w").write("revenue,4%\n")
good = hashlib.sha256(b"revenue,4%\n").hexdigest()
b, ip = broker("pr5", [f"write_file path={Q3} if_digest=/workspace/reports/q3_source.csv@{good}"])
open(src, "w").write("revenue,40%\n")
r1 = write(b, Q3, "Q3 summary")
open(src, "w").write("revenue,4%\n")
r2 = write(b, Q3, "Q3 summary")
check("wrong source content blocks, right content admits",
      (r1.get("failure"), (r1.get("error") or "").startswith("premise not met: /workspace/reports/q3_source.csv"),
       r2.get("effect")),
      ("intent", True, "succeeded"))

print("6. a true premise does not widen the policy")
b, ip = broker("pr6", [f"write_file path=/workspace/secret.txt if_present={FLAG}"])
r = write(b, "/workspace/secret.txt", "x")
check("refused by the kernel, not admitted", (r.get("decision"), r.get("failure") not in (None, "intent")),
      ("reject", True))

print("7. malformed premises refuse to load")
bad = [f"write_file path={Q3} if_maybe={FLAG}", f"write_file path={Q3} if_present=reports/final.flag",
       f"write_file path={Q3} if_digest={FLAG}", f"write_file path={Q3} if_digest={FLAG}@abc"]
refused = []
for line in bad:
    try:
        B._parse_intent(line); refused.append(False)
    except ValueError:
        refused.append(True)
check("unknown premise, relative path, missing digest, short digest", refused, [True] * 4)

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
