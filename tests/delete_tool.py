"""delete_file, measured against predictions written before implementation."""
import json, os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; WS = f"{D}/workspace"; AUDIT = f"{D}/delete_tool.jsonl"
for f in (AUDIT, AUDIT + ".key", AUDIT + ".pub.json", AUDIT + ".legacy.key", AUDIT + ".lock"):
    if os.path.exists(f):
        os.remove(f)
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
key = B.Keys.generate()
broker = B.Broker(cfg, KernelClient(), B.AuditLog(AUDIT), None, None, key)

def write(name, content):
    r = broker.handle({"tool": "write_file", "args": [["path", "/workspace/reports/" + name], ["content", content]]})
    assert r.get("effect") == "succeeded", r
def delete(path, **extra):
    return broker.handle(dict({"tool": "delete_file", "args": [["path", path]]}, **extra))
def findings(t):
    return [x["finding"] for x in B.verify_world(cfg, AUDIT, key)["findings"] if x["target"] == t]
def leftovers():
    return [n for n in os.listdir(f"{WS}/reports") if ".darm-tmp-" in n]

results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")

print("1. delete a broker-written file")
write("gone.md", "delete me")
r = delete("/workspace/reports/gone.md")
check("effect", r.get("effect"), "succeeded")
check("file absent", os.path.exists(f"{WS}/reports/gone.md"), False)
check("verify_world clean for it", findings("/workspace/reports/gone.md"), [])
check("basis says 'target is absent'", any("target is absent" in c["claim"] for c in r.get("basis", [])), True)

print("2. delete racing a foreign write")
write("race.md", "ORIGINAL")
orig = B._execute
def racing(*a, **kw):
    open(f"{WS}/reports/race.md", "w").write("FOREIGN")
    return orig(*a, **kw)
B._execute = racing
try:
    r = delete("/workspace/reports/race.md")
finally:
    B._execute = orig
check("effect", r.get("effect"), "failed")
check("foreign content restored", open(f"{WS}/reports/race.md").read(), "FOREIGN")
check("no temporary file left", leftovers(), [])

print("3. delete an absent file")
r = delete("/workspace/reports/never.md")
check("effect", r.get("effect"), "failed")
check("error names absence", "absent" in (r.get("error") or ""), True)

print("4. delete a symlink")
os.symlink(f"{D}/secret.txt", f"{WS}/reports/sym.md")
r = delete("/workspace/reports/sym.md")
check("effect", r.get("effect"), "failed")
check("symlink untouched", os.path.islink(f"{WS}/reports/sym.md"), True)
check("its target untouched", os.path.exists(f"{D}/secret.txt"), True)

print("5. traversal, and a delete outside the delete policy")
check("traversal refused", "normal form" in (delete("/workspace/../secret.txt").get("error") or ""), True)
r = delete("/workspace/notes.txt")
check("delete of notes.txt rejected by policy", r.get("decision"), "reject")
check("notes.txt untouched", os.path.exists(f"{WS}/notes.txt"), True)

print("6. keyed delete, retried")
write("keyed.md", "k")
r1 = delete("/workspace/reports/keyed.md", idempotency_key="del-k")
r2 = delete("/workspace/reports/keyed.md", idempotency_key="del-k")
prepared = [e for e in map(json.loads, open(AUDIT))
            if e.get("event") == "prepared" and e.get("idempotency_key") == "del-k"]
check("first", r1.get("effect"), "succeeded")
check("retry", r2.get("effect"), "already_applied")
check("prepared records", len(prepared), 1)

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
