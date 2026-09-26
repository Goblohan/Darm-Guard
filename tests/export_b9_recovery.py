"""Export observations of the running broker's rename recovery for Lean to
check against B9. Usage: python3 tests/export_b9_recovery.py OUT.lean [--corrupt]
Crashes renames at each phase, interferes before restart, restarts, and
records the three slots before and after each recovery. No model logic: the
projection only classifies each slot's content and attestation. It refuses
states B9 cannot represent, including foreign content carrying our
attestation (checked here, since B9 cannot express it)."""
import json, os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

OUT, CORRUPT = sys.argv[1], "--corrupt" in sys.argv
D = "/tmp/darmdemo"; R = f"{D}/workspace/reports"
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
class Crash(BaseException):
    pass

def slot(path, key, ours_digest, write_rid, rename_rid, dst_logical):
    if not os.path.exists(path):
        return None
    import hashlib
    digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
    try:
        a = B._check_attestation(key, os.getxattr(path, B.XATTR, follow_symlinks=False))
    except OSError:
        a = None
    if digest != ours_digest:
        if a is not None:
            sys.exit(f"foreign content at {path} carries our attestation: either recovery "
                     f"stamped it (D2) or it was modified in place (a tamper, outside B9)")
        return "foreign"
    if a and a["rid"] == rename_rid and a.get("target") == dst_logical:
        return "new"
    if a and a["rid"] == write_rid:
        return "old"
    sys.exit(f"our content at {path} with an attestation B9 cannot represent: {a}")

obs, n = [], [0]
def scenario(crash_hook, crash_on, interfere, window=False):
    n[0] += 1; tag = f"s{n[0]}"
    audit = f"{D}/rec_{tag}.jsonl"
    for f in (audit, audit + ".key", audit + ".pub.json", audit + ".legacy.key", audit + ".lock"):
        if os.path.exists(f):
            os.remove(f)
    key = B.Keys.generate()
    b = B.Broker(cfg, KernelClient(), B.AuditLog(audit), None, None, key)
    src, dst = f"{tag}src.md", f"{tag}dst.md"
    w = b.handle({"tool": "write_file", "args": [["path", "/workspace/reports/" + src], ["content", "ours " + tag]]})
    orig, calls = getattr(B, crash_hook), [0]
    def hooked(*a, **kw):
        out = orig(*a, **kw); calls[0] += 1
        if calls[0] == crash_on:
            raise Crash()
        return out
    setattr(B, crash_hook, hooked)
    try:
        b.handle({"tool": "rename_file", "args": [["path", "/workspace/reports/" + src],
                                                  ["destination", "/workspace/reports/" + dst]]})
    except Crash:
        pass
    finally:
        setattr(B, crash_hook, orig)
    p = [e for e in map(json.loads, open(audit)) if e.get("event") == "prepared"][-1]
    def foreign(name, text):
        # a foreign process creates or REPLACES the file (a new file, no attestation),
        # matching B9's foreign; an in-place write would keep our attestation on
        # foreign content, which is tampering (probe P8, B6/B8), outside B9
        tmp = f"{R}/.foreign-{tag}-{name}"
        open(tmp, "w").write(text)
        os.replace(tmp, f"{R}/{name}")
    if "dst" in interfere:
        foreign(dst, "FOREIGN DST")
    if "src" in interfere:
        foreign(src, "FOREIGN SRC")
    ours = p["before_state"][1]
    def state():
        return tuple(slot(f"{R}/{x}", key, ours, w["request_id"], p["request_id"], "/workspace/reports/" + dst)
                     for x in (src, p["private"], dst))
    if window:
        before = state()
        def crash_now(*a, **kw):
            raise Crash()
        B._set_att = crash_now
        try:
            B.Broker(cfg, KernelClient(), B.AuditLog(audit), None, None, key).reconcile_pending()
        except Crash:
            pass
        finally:
            B._set_att = orig if crash_hook == "_set_att" else B.__dict__["_set_att"]
        obs.append(("interrupted", before, state()))
    before = state()
    key.ring.save(audit + ".key", audit + ".pub.json")
    srv = B.serve(cfg, f"/tmp/darm-rec-{tag}.sock", audit)
    srv.server_close()
    obs.append(("full", before, state()))

real_set_att = B._set_att
for hook, on in (("_renameat2", 1), ("_set_att", 1), ("_renameat2", 2)):
    for interfere in ((), ("dst",), ("src",), ("src", "dst")):
        scenario(hook, on, interfere)
        B._set_att = real_set_att
scenario("_set_att", 1, ("dst",), window=True)
B._set_att = real_set_att

if CORRUPT:
    for j in range(len(obs) - 1, -1, -1):
        kind, b_, a_ = obs[j]
        if kind == "full":
            flip = {"new": "old", "old": "new", "foreign": None, None: "foreign"}
            a_ = (a_[0], a_[1], flip[a_[2]])
            obs[j] = (kind, b_, a_)
            print(f"corrupted observation {j}: destination slot altered")
            break

def L_val(v):
    return {None: "none", "old": "some (Val.mine Att.old)", "new": "some (Val.mine Att.new)",
            "foreign": "some Val.foreign"}[v]
def L_fs(s):
    return f"(FS.mk ({L_val(s[0])}) ({L_val(s[1])}) ({L_val(s[2])}))"
ns = "DARM.RecoveryTraceBad" if CORRUPT else "DARM.RecoveryTrace"
body = ",\n".join(f"  Obs.{k} {L_fs(b_)} {L_fs(a_)}" for k, b_, a_ in obs)
kinds = {}
for k, b_, a_ in obs:
    kinds[k] = kinds.get(k, 0) + 1
with open(OUT, "w") as f:
    f.write(f"/-\n  Generated by darm-guard tests/export_b9_recovery.py: {len(obs)} observations {kinds}.\n"
            f"{'  One observation corrupted: the check must fail.' + chr(10) if CORRUPT else ''}-/\n"
            f"import B9RecoveryCheck\n\nnamespace {ns}\nopen DARM.RenameProtocol DARM.RecoveryCheck\n\n"
            f"def observations : List Obs := [\n{body}\n]\n\n"
            f"theorem recovery_{'rejected' if CORRUPT else 'agrees'} : checkObs observations = "
            f"{'false' if CORRUPT else 'true'} := by decide\n\nend {ns}\n")
for k, b_, a_ in obs:
    print(f"  {k:12s} {b_} -> {a_}")
print("observations:", kinds, "->", OUT)
