"""B8 runtime correspondence (sampled). Every request is exactly one B8 step
(brokerWrite or brokerDelete) or a stutter, B8's Consistent holds after each
one, and verify_world reports nothing after each one (the runtime
counterpart of legitimate_ops_never_flagged). The model's log is transcribed
here in chronological order; B8's is its reverse."""
import hashlib, json, os, random, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; WS = f"{D}/workspace"; AUDIT = f"{D}/b8corr.jsonl"
for f in (AUDIT, AUDIT + ".key", AUDIT + ".lock"):
    if os.path.exists(f):
        os.remove(f)
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
key = os.urandom(32)
broker = B.Broker(cfg, KernelClient(), B.AuditLog(AUDIT), None, None, key)

def project():
    log, prepared = [], {}
    if os.path.exists(AUDIT):
        for line in open(AUDIT):
            e = json.loads(line)
            if e.get("event") == "prepared":
                prepared[e["request_id"]] = e
            tool, rid, t = e.get("tool"), e.get("request_id"), e.get("target")
            if tool not in ("write_file", "delete_file") or not t:
                continue
            ok = ((e.get("event") == "outcome" and e.get("effect") == "succeeded") or
                  (e.get("event") == "reconciled" and e.get("reconciliation") == "confirmedSuccess"
                   and rid in prepared))
            if not ok:
                continue
            if tool == "delete_file":
                log.append((rid, t, ("del",)))
            else:
                src = e if e.get("event") == "outcome" else prepared[rid]
                log.append((rid, t, ("write", src["intended_state"][1])))
    files = {}
    for dirpath, _, names in os.walk(WS):
        for n in names:
            p = os.path.join(dirpath, n)
            if os.path.islink(p) or ".darm-tmp-" in n:
                continue
            logical = B.LOGICAL_ROOT + os.path.relpath(p, WS)
            try:
                a = B._check_attestation(key, os.getxattr(p, B.XATTR, follow_symlinks=False))
                att = (a["rid"], a["digest"]) if a and a.get("target") == logical else ("INVALID",)
            except OSError:
                att = None
            files[logical] = (hashlib.sha256(open(p, "rb").read()).hexdigest(), att)
    return (tuple(log), files)

def model_write(w, rid, t, d):
    log, files = w; files = dict(files); files[t] = (d, (rid, d))
    return (log + ((rid, t, ("write", d)),), files)

def model_delete(w, rid, t):
    log, files = w; files = dict(files); files.pop(t, None)
    return (log + ((rid, t, ("del",)),), files)

def consistent(w):
    """B8's Consistent: each target matches its latest log entry."""
    log, files = w
    latest = {}
    for rid, t, op in log:
        latest[t] = (rid, op)
    for t in set(files) | set(latest):
        if t in latest:
            rid, op = latest[t]
            if op[0] == "write" and files.get(t) != (op[1], (rid, op[1])):
                return False
            if op[0] == "del" and t in files:
                return False
        elif files[t][1] is not None:
            return False
    return True

rng = random.Random(8)
names, contents = ["a.md", "b.md", "c.md"], ["x", "y", "z"]
def request():
    k = rng.random()
    if k < 0.35:
        p = {"tool": "write_file", "args": [["path", "/workspace/reports/" + rng.choice(names)],
                                            ["content", rng.choice(contents)]]}
    elif k < 0.65:
        p = {"tool": "delete_file", "args": [["path", "/workspace/reports/" + rng.choice(names)]]}
    elif k < 0.72:
        p = {"tool": "delete_file", "args": [["path", "/workspace/notes.txt"]]}
    else:
        p = {"tool": "read_file", "args": [["path", "/workspace/notes.txt"]]}
    if p["tool"] != "read_file" and rng.random() < 0.3:
        p["idempotency_key"] = f"k{rng.randrange(5)}"
    return p

N = 300
writes = deletes = stutters = violations = unclean = 0
for i in range(N):
    prev = project()
    r = broker.handle(request())
    cur = project()
    if r.get("effect") == "succeeded" and "written" in r:
        ok = cur == model_write(prev, r["request_id"], r["target"], r["intended_state"][1]); writes += ok
    elif r.get("effect") == "succeeded" and r.get("deleted"):
        ok = cur == model_delete(prev, r["request_id"], r["target"]); deletes += ok
    else:
        ok = cur == prev; stutters += ok
    if not ok or not consistent(cur):
        violations += 1
        print(f"VIOLATION at {i}: effect={r.get('effect')} consistent={consistent(cur)}")
    if not B.verify_world(cfg, AUDIT, key)["ok"]:
        unclean += 1
        print(f"verify_world not clean at {i}")
print(f"requests {N}: writes {writes}, deletes {deletes}, stutters {stutters}, "
      f"violations {violations}, verify_world unclean {unclean}")
ok = violations == 0 and unclean == 0 and deletes > 0 and writes > 0 and stutters > 0
print("B8 correspondence:", "HOLDS on this sample" if ok else "FAILS")
sys.exit(0 if ok else 1)
