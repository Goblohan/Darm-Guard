"""In-flight revocation (E24c) in the broker. Predictions first; 4 measures
the stated limit rather than assuming it."""
import os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; R = f"{D}/workspace/reports"
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")
def broker(lines, name):
    A = f"{D}/{name}.jsonl"
    for f in (A, A + ".key", A + ".pub.json", A + ".legacy.key", A + ".lock"):
        if os.path.exists(f): os.remove(f)
    ip, rp = f"{D}/{name}.intents", f"{D}/{name}.revocations"
    open(ip, "w").write("".join(l + "\n" for l in lines)); open(rp, "w").write("")
    b = B.Broker(cfg, KernelClient(), B.AuditLog(A), B.load_intents(ip), ip, B.Keys.generate())
    b.revocations_path = rp
    return b, ip, rp
def write(b, name):
    return b.handle({"tool": "write_file", "args": [["path", "/workspace/reports/" + name], ["content", "x"]]})
def left(p):
    return open(p).read().splitlines()

print("1. revoking everything, through the revocations file")
b, ip, rp = broker(["write_file", "write_file"], "rv1")
open(rp, "a").write("write_file *\n")
check("the next write is refused", write(b, "r1.md").get("failure"), "intent")
check("the intents file is empty: nothing resurrected", left(ip), [])

print("2. a targeted revocation")
b, ip, rp = broker(["write_file path=/workspace/reports/ra.md", "write_file path=/workspace/reports/rb.md"], "rv2")
open(rp, "a").write("write_file path=/workspace/reports/ra.md\n")
check("the revoked file refused, the other allowed",
      (write(b, "ra.md").get("failure"), write(b, "rb.md").get("effect")), ("intent", "succeeded"))

print("3. editing the intents file directly")
b, ip, rp = broker(["write_file", "write_file"], "rv3")
open(ip, "w").write("")                                  # what the 0.13.0 probe did
r = write(b, "r3.md")
check("refused, saying why", (r.get("failure"), "changed outside the broker" in (r.get("error") or "")),
      ("intent", True))
write(b, "r3b.md")
check("the principal's edit is left alone", left(ip), [])

print("4. a revocation arriving while an effect is under way")
b, ip, rp = broker(["write_file", "write_file"], "rv4")
orig = B._execute
def during(*a, **kw):
    open(rp, "a").write("write_file *\n")               # the principal revokes mid-effect
    return orig(*a, **kw)
B._execute = during
try:
    first = write(b, "r4a.md")
finally:
    B._execute = orig
check("the committed write completes (not recalled)", first.get("effect"), "succeeded")
check("the next action is refused", write(b, "r4b.md").get("failure"), "intent")

print("5. a revocation line that cannot be read")
b, ip, rp = broker(["write_file", "write_file"], "rv5")
open(rp, "a").write("write_file path=\n")
check("revokes everything", (write(b, "r5.md").get("failure"), left(ip)), ("intent", []))

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
