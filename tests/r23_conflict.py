"""R23 correspondence under conflicts. A foreign writer races a broker write
(after the before-state is recorded, before the exchange). Case A: the
target exists and is attested; the collision should be exactly one model
directWrite (tamper), no broker step, flagged. Case B: the target is absent
and the foreign writer creates it; predicted to be outside R23's modelled
adversary and not flagged by verify_world."""
import hashlib, json, os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; WS = f"{D}/workspace"; AUDIT = f"{D}/r23conflict.jsonl"
for f in (AUDIT, AUDIT + ".key", AUDIT + ".pub.json", AUDIT + ".legacy.key", AUDIT + ".lock"):
    if os.path.exists(f):
        os.remove(f)
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
key = B.Keys.generate()
broker = B.Broker(cfg, KernelClient(), B.AuditLog(AUDIT), None, None, key)
sha = lambda s: hashlib.sha256(s.encode()).hexdigest()

def project():
    log, prepared = [], {}
    if os.path.exists(AUDIT):
        for line in open(AUDIT):
            e = json.loads(line)
            if e.get("event") == "prepared":
                prepared[e["request_id"]] = e
            if e.get("tool") != "write_file" or not e.get("target"):
                continue
            if e.get("event") == "outcome" and e.get("effect") == "succeeded":
                log.append((e["request_id"], e["target"], e["intended_state"][1]))
            elif (e.get("event") == "reconciled" and e.get("reconciliation") == "confirmedSuccess"
                  and e["request_id"] in prepared):
                log.append((e["request_id"], e["target"], prepared[e["request_id"]]["intended_state"][1]))
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

def honest(w):
    log, files = w
    return all(att is None or (att != ("INVALID",) and dg == att[1] and (att[0], t, att[1]) in log)
               for t, (dg, att) in files.items())

def violations(w):
    """Which files break Honest, so a failure can be attributed."""
    log, files = w
    return sorted(t for t, (dg, att) in files.items()
                  if att is not None and (att == ("INVALID",) or dg != att[1] or (att[0], t, att[1]) not in log))

def tamper(w, t, d2):
    """B6's tamper, transcribed: change an existing file's content, keep its attestation."""
    log, files = w
    if t not in files:
        return w
    files = dict(files); files[t] = (d2, files[t][1])
    return (log, files)

def flagged(t):
    return any(x["target"] == t for x in B.verify_world(cfg, AUDIT, key)["findings"])

race = {"path": None, "content": None}
orig_exec = B._execute
def racing_execute(*a, **kw):
    if race["path"]:
        with open(race["path"], "w") as f:   # in place: keeps any existing attestation
            f.write(race["content"])
        race["path"] = None
    return orig_exec(*a, **kw)
B._execute = racing_execute

def collide(name, broker_content, foreign_content):
    t = "/workspace/reports/" + name
    prev = project()
    race.update(path=os.path.join(WS, "reports", name), content=foreign_content)
    r = broker.handle({"tool": "write_file", "args": [["path", t], ["content", broker_content]]})
    return t, prev, r, project()

results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")

# Case A: an existing, attested target, modified in place by the foreign writer.
broker.handle({"tool": "write_file", "args": [["path", "/workspace/reports/conf.md"], ["content", "ORIGINAL"]]})
t, prev, r, after = collide("conf.md", "BROKER", "FOREIGN")
print("Case A: existing attested target, foreign write in place")
check("broker effect", r.get("effect"), "failed")
check("log unchanged (no broker step)", after[0] == prev[0], True)
check("collision == one directWrite (tamper)", after == tamper(prev, t, sha("FOREIGN")), True)
check("Honest after", honest(after), False)
print("    violating files:", violations(after))
check("verify_world flags it", flagged(t), True)

# Case B: an absent target, created by the foreign writer.
t, prev, r, after = collide("created.md", "BROKER", "FOREIGN NEW")
print("\nCase B: absent target, created by the foreign writer")
check("broker effect", r.get("effect"), "failed")
check("log unchanged (no broker step)", after[0] == prev[0], True)
check("world changed", after != prev, True)
check("collision is a modelled directWrite", after == tamper(prev, t, sha("FOREIGN NEW")), False)
check("created file breaks Honest", t in violations(after), False)
print("    violating files:", violations(after))
check("verify_world flags it", flagged(t), False)

B._execute = orig_exec
print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
