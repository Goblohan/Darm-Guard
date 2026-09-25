"""Recovery's own crash window, and self-renames. Predictions first.
W: crash after the re-attestation; destination then occupied; recovery rolls
   back but crashes between moving the file and restoring its attestation;
   a second recovery repairs it (B9: recovery_crash_window_harmless).
S: a rename onto itself is refused and changes nothing."""
import json, os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; R = f"{D}/workspace/reports"
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
class Crash(BaseException):
    pass
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")
def att_rid(key, path):
    try:
        a = B._check_attestation(key, os.getxattr(path, B.XATTR, follow_symlinks=False))
        return a and a["rid"]
    except OSError:
        return None

audit = f"{D}/window.jsonl"
for f in (audit, audit + ".key", audit + ".lock"):
    if os.path.exists(f):
        os.remove(f)
key = os.urandom(32)
b = B.Broker(cfg, KernelClient(), B.AuditLog(audit), None, None, key)
w = b.handle({"tool": "write_file", "args": [["path", "/workspace/reports/wsrc.md"], ["content", "mine"]]})

print("W: a crash inside recovery's roll-back, then a second recovery")
orig = B._set_att
calls = [0]
def crash_after_reattest(*a, **kw):
    orig(*a, **kw); calls[0] += 1
    if calls[0] == 1:
        raise Crash()
B._set_att = crash_after_reattest
try:
    b.handle({"tool": "rename_file", "args": [["path", "/workspace/reports/wsrc.md"],
                                              ["destination", "/workspace/reports/wdst.md"]]})
except Crash:
    pass
finally:
    B._set_att = orig
rid_rename = [e for e in map(json.loads, open(audit)) if e.get("event") == "prepared"][-1]["request_id"]
open(f"{R}/wdst.md", "w").write("DST FOREIGN")

def crash_before_restore(*a, **kw):
    raise Crash()
B._set_att = crash_before_restore
try:
    B.Broker(cfg, KernelClient(), B.AuditLog(audit), None, None, key).reconcile_pending()
    crashed = False
except Crash:
    crashed = True
finally:
    B._set_att = orig
check("first recovery crashed inside its roll-back", crashed, True)
check("our file back at the source", open(f"{R}/wsrc.md").read(), "mine")
check("still carrying the rename's attestation (the window)", att_rid(key, f"{R}/wsrc.md") == rid_rename, True)

kfd = os.open(audit + ".key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.write(kfd, key); os.close(kfd)
srv = B.serve(cfg, "/tmp/darm-window.sock", audit)
srv.server_close()
verdicts = [e.get("reconciliation") for e in map(json.loads, open(audit)) if e.get("event") == "reconciled"]
# unresolved, not confirmedFailure: failure requires BOTH paths as before, and this test
# put foreign content at the destination (the prediction was first written wrongly)
check("second recovery's verdict", verdicts, ["unresolved"])
check("attestation repaired to the original write", att_rid(key, f"{R}/wsrc.md") == w["request_id"], True)
check("foreign destination untouched", open(f"{R}/wdst.md").read(), "DST FOREIGN")
check("source verifies clean",
      [x for x in B.verify_world(cfg, audit, key)["findings"] if x["target"] == "/workspace/reports/wsrc.md"], [])
check("no private file left", [n for n in os.listdir(R) if ".darm-tmp-" in n], [])

print("S: a rename onto itself")
b2 = B.Broker(cfg, KernelClient(), B.AuditLog(f"{D}/self.jsonl"), None, None, key)
w2 = b2.handle({"tool": "write_file", "args": [["path", "/workspace/reports/self.md"], ["content", "same"]]})
r = b2.handle({"tool": "rename_file", "args": [["path", "/workspace/reports/self.md"],
                                               ["destination", "/workspace/reports/self.md"]]})
check("refused", r.get("effect"), "failed")
check("reason", "same" in (r.get("error") or ""), True)
check("file and attestation unchanged",
      (open(f"{R}/self.md").read(), att_rid(key, f"{R}/self.md") == w2["request_id"]), ("same", True))

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
