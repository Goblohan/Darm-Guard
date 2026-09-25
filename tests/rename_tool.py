"""rename_file, live protocol (step 4a), against predictions written first.
Startup recovery after a crash is step 4b."""
import json, os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; WS = f"{D}/workspace"; R = f"{WS}/reports"; AUDIT = f"{D}/rename_tool.jsonl"
for f in (AUDIT, AUDIT + ".key", AUDIT + ".lock"):
    if os.path.exists(f):
        os.remove(f)
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
key = os.urandom(32)
broker = B.Broker(cfg, KernelClient(), B.AuditLog(AUDIT), None, None, key)

def write(name, content):
    r = broker.handle({"tool": "write_file", "args": [["path", "/workspace/reports/" + name], ["content", content]]})
    assert r.get("effect") == "succeeded", r
def rename(src, dst, **extra):
    return broker.handle(dict({"tool": "rename_file", "args": [["path", "/workspace/reports/" + src],
                                                             ["destination", "/workspace/reports/" + dst]]}, **extra))
def findings(name):
    return [x["finding"] for x in B.verify_world(cfg, AUDIT, key)["findings"]
            if x["target"] == "/workspace/reports/" + name]
def leftovers():
    return [n for n in os.listdir(R) if ".darm-tmp-" in n]
def att_rid(name):
    a = B._check_attestation(key, os.getxattr(f"{R}/{name}", B.XATTR))
    return a and a["rid"]

results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")

print("1. normal")
write("n1.md", "moving")
r = rename("n1.md", "n2.md")
check("effect", r.get("effect"), "succeeded")
check("source absent", os.path.exists(f"{R}/n1.md"), False)
check("destination content", open(f"{R}/n2.md").read(), "moving")
check("both verify clean", (findings("n1.md"), findings("n2.md")), ([], []))
check("reconciliation", r.get("reconciliation"), "confirmedSuccess")
check("destination attests this request", att_rid("n2.md") == r.get("request_id"), True)
check("no private file left", leftovers(), [])

print("2. destination occupied")
write("o1.md", "mine"); write("o2.md", "theirs")
r = rename("o1.md", "o2.md")
check("effect", r.get("effect"), "failed")
check("source restored", open(f"{R}/o1.md").read(), "mine")
check("source verifies clean (original attestation back)", findings("o1.md"), [])
check("destination unchanged", open(f"{R}/o2.md").read(), "theirs")
check("no private file left", leftovers(), [])

print("3. source replaced before the claim")
write("s1.md", "ORIGINAL")
orig = B._execute
def racing(*a, **kw):
    open(f"{R}/s1.md", "w").write("FOREIGN")
    return orig(*a, **kw)
B._execute = racing
try:
    r = rename("s1.md", "s2.md")
finally:
    B._execute = orig
check("effect", r.get("effect"), "failed")
check("foreign content back at the source", open(f"{R}/s1.md").read(), "FOREIGN")
check("destination absent", os.path.exists(f"{R}/s2.md"), False)
check("no private file left", leftovers(), [])

print("4. destination appears during the window")
write("w1.md", "mine")
orig_set = B._set_att
calls = [0]
def late(pfd, name, value):
    orig_set(pfd, name, value)
    calls[0] += 1
    if calls[0] == 1:                                  # right after the re-attestation
        open(f"{R}/w2.md", "w").write("LATE")
B._set_att = late
try:
    r = rename("w1.md", "w2.md")
finally:
    B._set_att = orig_set
check("effect", r.get("effect"), "failed")
check("source restored", open(f"{R}/w1.md").read(), "mine")
check("source verifies clean (original attestation back)", findings("w1.md"), [])
check("the late foreign file untouched", open(f"{R}/w2.md").read(), "LATE")
check("no private file left", leftovers(), [])

print("5. policy")
write("p1.md", "stay")
r = broker.handle({"tool": "rename_file", "args": [["path", "/workspace/reports/p1.md"],
                                                   ["destination", "/workspace/notes2.txt"]]})
check("destination outside the policy rejected", r.get("decision"), "reject")
check("source untouched", open(f"{R}/p1.md").read(), "stay")

print("6. keyed rename, retried")
write("k1.md", "k")
r1 = rename("k1.md", "k2.md", idempotency_key="mv-k")
r2 = rename("k1.md", "k2.md", idempotency_key="mv-k")
prepared = [e for e in map(json.loads, open(AUDIT))
            if e.get("event") == "prepared" and e.get("idempotency_key") == "mv-k"]
check("first", r1.get("effect"), "succeeded")
check("retry", r2.get("effect"), "already_applied")
check("prepared records", len(prepared), 1)

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
