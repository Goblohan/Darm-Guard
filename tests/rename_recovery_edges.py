"""Recovery edge cases where the implementation diverged from B9 before
the fix (both confirmed, then fixed); predictions are now B9's:
D1 a blocked roll-back: the file cannot return to an occupied source; B9
   leaves the state unchanged, the implementation is predicted to restore
   the old attestation anyway.
D2 foreign content at the private name (a source replaced just before the
   claim, crash before the inspect); B9 returns it untouched, the
   implementation is predicted to stamp our attestation on it."""
import json, os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; WS = f"{D}/workspace"; R = f"{WS}/reports"
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
class Crash(BaseException):
    pass
results = []
def check(label, got, predicted, note=""):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted}){note}")

def fresh(tag):
    audit = f"{D}/edge_{tag}.jsonl"
    for f in (audit, audit + ".key", audit + ".pub.json", audit + ".legacy.key", audit + ".lock"):
        if os.path.exists(f):
            os.remove(f)
    key = B.Keys.generate()
    return audit, key, B.Broker(cfg, KernelClient(), B.AuditLog(audit), None, None, key)

def crash_rename(b, src, dst, hook, on_call, before_claim=None):
    orig, calls = getattr(B, hook), [0]
    def hooked(*a, **kw):
        if before_claim and calls[0] == 0 and hook == "_renameat2":
            before_claim()
        out = orig(*a, **kw)
        calls[0] += 1
        if calls[0] == on_call:
            raise Crash()
        return out
    setattr(B, hook, hooked)
    try:
        b.handle({"tool": "rename_file", "args": [["path", "/workspace/reports/" + src],
                                                  ["destination", "/workspace/reports/" + dst]]})
    except Crash:
        pass
    finally:
        setattr(B, hook, orig)

def restart(audit, key, tag):
    key.ring.save(audit + ".key", audit + ".pub.json")
    srv = B.serve(cfg, f"/tmp/darm-edge-{tag}.sock", audit)
    srv.server_close()

def prepared_of(audit, tool="rename_file"):
    return [e for e in map(json.loads, open(audit)) if e.get("event") == "prepared" and e.get("tool") == tool][-1]
def att(key, path):
    try:
        return B._check_attestation(key, os.getxattr(path, B.XATTR, follow_symlinks=False))
    except OSError:
        return None

print("D1: crash after the re-attestation; then both source and destination occupied")
audit, key, b = fresh("d1")
w = b.handle({"tool": "write_file", "args": [["path", "/workspace/reports/d1src.md"], ["content", "mine"]]})
crash_rename(b, "d1src.md", "d1dst.md", "_set_att", 1)
p = prepared_of(audit)
open(f"{R}/d1src.md", "w").write("SRC FOREIGN")
open(f"{R}/d1dst.md", "w").write("DST FOREIGN")
priv = f"{R}/{p['private']}"
before_rid = att(key, priv)["rid"]
restart(audit, key, "d1")
verdict = [e.get("reconciliation") for e in map(json.loads, open(audit)) if e.get("event") == "reconciled"]
check("verdict", verdict, ["unresolved"])
check("our file still at the private name (not lost)", open(priv).read() if os.path.exists(priv) else None, "mine")
check("attestation before restart names the rename", before_rid == p["request_id"], True)
a = att(key, priv)
check("attestation after the blocked roll-back unchanged (still names the rename, as B9)",
      a and a["rid"] == p["request_id"], True)

print("D2: the source replaced by foreign content just before the claim; crash before the inspect")
audit, key, b = fresh("d2")
b.handle({"tool": "write_file", "args": [["path", "/workspace/reports/d2src.md"], ["content", "mine"]]})
def replace_source():
    tmp = f"{R}/.d2_foreign_tmp"
    open(tmp, "w").write("FOREIGN REPLACEMENT")
    os.replace(tmp, f"{R}/d2src.md")
crash_rename(b, "d2src.md", "d2dst.md", "_renameat2", 1, before_claim=replace_source)
check("foreign file carries no attestation before restart",
      att(key, f"{R}/{prepared_of(audit)['private']}"), None)
restart(audit, key, "d2")
check("foreign content back at the source", open(f"{R}/d2src.md").read(), "FOREIGN REPLACEMENT")
check("foreign file returned untouched, with no attestation (as B9)",
      att(key, f"{R}/d2src.md"), None)
f = [x["finding"] for x in B.verify_world(cfg, audit, key)["findings"] if x["target"] == "/workspace/reports/d2src.md"]
check("verify_world still flags it", bool(f), True, f"   ({f[0] if f else ''})")

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
