"""R23 correspondence across a crash. One model brokerWrite (file and log
entry together) becomes two real events: the write, then, after restart,
a reconciled record. Measures B6's Honest under two projections, before
and after reconciliation, and whether the whole sequence is one brokerWrite."""
import hashlib, json, os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; WS = f"{D}/workspace"; AUDIT = f"{D}/r23crash.jsonl"
for f in (AUDIT, AUDIT + ".key", AUDIT + ".pub.json", AUDIT + ".legacy.key", AUDIT + ".lock"):
    if os.path.exists(f):
        os.remove(f)
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
key = B.Keys.generate()

def project(include_reconciled):
    log, prepared = [], {}
    for line in open(AUDIT):
        e = json.loads(line)
        if e.get("event") == "prepared":
            prepared[e["request_id"]] = e
        if e.get("tool") != "write_file" or not e.get("target"):
            continue
        if e.get("event") == "outcome" and e.get("effect") == "succeeded":
            log.append((e["request_id"], e["target"], e["intended_state"][1]))
        elif (include_reconciled and e.get("event") == "reconciled"
              and e.get("reconciliation") == "confirmedSuccess" and e["request_id"] in prepared):
            log.append((e["request_id"], e["target"], prepared[e["request_id"]]["intended_state"][1]))
    files = {}
    for dirpath, _, names in os.walk(WS):
        for n in names:
            p = os.path.join(dirpath, n)
            if os.path.islink(p) or ".darm-tmp-" in n:
                continue
            logical = B.LOGICAL_ROOT + os.path.relpath(p, WS)
            digest = hashlib.sha256(open(p, "rb").read()).hexdigest()
            try:
                a = B._check_attestation(key, os.getxattr(p, B.XATTR, follow_symlinks=False))
                att = (a["rid"], a["digest"]) if a and a.get("target") == logical else ("INVALID",)
            except OSError:
                att = None
            files[logical] = (digest, att)
    return (tuple(log), files)

def honest(w):
    log, files = w
    return all(att is None or (att != ("INVALID",) and digest == att[1] and (att[0], t, att[1]) in log)
               for t, (digest, att) in files.items())

def broker_write(w, rid, t, d):
    log, files = w
    files = dict(files); files[t] = (d, (rid, d))
    return (log + ((rid, t, d),), files)

def verify_ok():
    return B.verify_world(cfg, AUDIT, key)["ok"]

open(AUDIT, "a").close()
before = project(True)

# 1. A write whose outcome record is lost to a crash.
orig = B.Broker._record
def crash(self, rid, event, inv, tool, resp):
    if event == "outcome" and (resp.get("target") or "").endswith("crash.md"):
        raise OSError("simulated crash before the outcome record")
    return orig(self, rid, event, inv, tool, resp)
B.Broker._record = crash
try:
    broker = B.Broker(cfg, KernelClient(), B.AuditLog(AUDIT), None, None, key)
    r = broker.handle({"tool": "write_file",
                       "args": [["path", "/workspace/reports/crash.md"], ["content", "survives the crash"]]})
finally:
    B.Broker._record = orig
rid, t, d = r["request_id"], r["target"], r["intended_state"][1]
print(f"write: effect={r.get('effect')} evidence={r.get('evidence')} attested={r.get('attested')}")

print("\nafter the crash, before restart:")
print(f"  outcome-only projection honest: {honest(project(False))}   (predicted False)")
print(f"  corrected projection honest:    {honest(project(True))}   (predicted False: the unmodelled window)")
print(f"  verify_world ok:                {verify_ok()}   (predicted True: it counts the prepared record)")

# 2. Restart with the same key: startup reconciliation closes the request.
key.ring.save(AUDIT + ".key", AUDIT + ".pub.json")
srv = B.serve(cfg, "/tmp/darm-r23crash.sock", AUDIT)
srv.server_close()
verdicts = [e.get("reconciliation") for e in map(json.loads, open(AUDIT)) if e.get("event") == "reconciled"]
after = project(True)
print(f"\nafter restart (reconciliation: {verdicts}):")
print(f"  outcome-only projection honest: {honest(project(False))}   (predicted False: the gap)")
print(f"  corrected projection honest:    {honest(after)}   (predicted True)")
print(f"  verify_world ok:                {verify_ok()}   (predicted True)")
one_step = after == broker_write(before, rid, t, d)
print(f"  crash + reconciliation == one brokerWrite: {one_step}   (predicted True)")

ok = honest(after) and one_step and verify_ok() and verdicts == ["confirmedSuccess"]
print("\ncorrected correspondence across a crash:", "HOLDS" if ok else "FAILS")
sys.exit(0 if ok else 1)
