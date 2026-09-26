"""R23 runtime correspondence (sampled). Every request the Python broker
handles must be exactly one R23 brokerStep on the projected world (a
successful write) or a stutter (anything else). Then the runtime
counterpart of R23-C: an A1 violation (direct write) and an A2 violation
(log truncation) are not broker steps, and verify_world flags both.

Evidence stratum: sampled, not proved. brokerWrite below transcribes
B6's definition; a Lean-checked trace certificate is the stronger form."""
import hashlib, json, os, random, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; WS = f"{D}/workspace"; AUDIT = f"{D}/r23.jsonl"
for f in (AUDIT, AUDIT + ".key", AUDIT + ".pub.json", AUDIT + ".legacy.key", AUDIT + ".lock"):
    if os.path.exists(f):
        os.remove(f)
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
key = B.Keys.generate()
broker = B.Broker(cfg, KernelClient(), B.AuditLog(AUDIT), None, None, key)

def project():
    """The real system, projected onto R23's World: (log, files)."""
    # The model's log: successful write outcomes, plus writes closed by
    # startup reconciliation as confirmedSuccess (digest from their prepared
    # record). Shown necessary by tests/r23_crash.py.
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
            digest = hashlib.sha256(open(p, "rb").read()).hexdigest()
            try:
                a = B._check_attestation(key, os.getxattr(p, B.XATTR, follow_symlinks=False))
                att = (a["rid"], a["digest"]) if a and a.get("target") == logical else ("INVALID",)
            except OSError:
                att = None
            files[logical] = (digest, att)
    return (tuple(log), files)

def broker_write(w, rid, t, d):
    """B6's brokerWrite, transcribed: append one entry; set content and attestation together."""
    log, files = w
    files = dict(files); files[t] = (d, (rid, d))
    return (log + ((rid, t, d),), files)

def honest(w):
    """B6's Honest: each attested file matches its attestation, and its request is logged."""
    log, files = w
    for t, (digest, att) in files.items():
        if att is None:
            continue
        if att == ("INVALID",) or digest != att[1] or (att[0], t, att[1]) not in log:
            return False
    return True

rng = random.Random(23)
names, contents = ["a.md", "b.md", "c.md"], ["x", "y", "z"]
def request():
    k = rng.random()
    if k < 0.45:
        p = {"tool": "write_file", "args": [["path", "/workspace/reports/" + rng.choice(names)],
                                            ["content", rng.choice(contents)]]}
    elif k < 0.55:
        p = {"tool": "write_file", "args": [["path", "/workspace/link.txt"], ["content", "x"]]}
    elif k < 0.80:
        p = {"tool": "read_file", "args": [["path", rng.choice(["/workspace/notes.txt",
                                                                "/workspace/reports/a.md"])]]}
    elif k < 0.90:
        p = {"tool": "read_file", "args": [["path", "/workspace/other.txt"]]}
    else:
        p = {"tool": "read_file", "args": [["path", "/workspace/../secret.txt"]]}
    if p["tool"] == "write_file" and rng.random() < 0.3:
        p["idempotency_key"] = f"k{rng.randrange(5)}"
    return p

N = 300
steps = stutters = violations = 0
for i in range(N):
    prev = project()
    r = broker.handle(request())
    cur = project()
    wrote = r.get("effect") == "succeeded" and r.get("target") is not None and "written" in r
    if wrote:
        expected = broker_write(prev, r["request_id"], r["target"], r["intended_state"][1])
        ok = cur == expected
        steps += ok
    else:
        ok = cur == prev
        stutters += ok
    if not ok or not honest(cur):
        violations += 1
        print(f"VIOLATION at {i}: effect={r.get('effect')} wrote={wrote} honest={honest(cur)}")
print(f"requests {N}: broker steps {steps}, stutters {stutters}, violations {violations}")

# Runtime counterpart of R23-C
results = []
last = {}
for rid, t, d in project()[0]:
    last[t] = rid
targets = sorted(last)
tamper_t, trunc_t = targets[0], targets[-1]

prev = project()
with open(os.path.join(WS, tamper_t[len(B.LOGICAL_ROOT):]), "a") as f:
    f.write(" written outside the broker")
cur = project()
found = [x for x in B.verify_world(cfg, AUDIT, key)["findings"] if x["target"] == tamper_t]
a1 = cur[0] == prev[0] and cur != prev and bool(found)
print(f"A1 violation (direct write to {tamper_t}): not a broker step, flagged: {a1}"
      + (f" ({found[0]['finding']})" if found else ""))

prev = project()
rid = last[trunc_t]
kept = [l for l in open(AUDIT).read().splitlines() if json.loads(l).get("request_id") != rid]
open(AUDIT, "w").write("\n".join(kept) + "\n")
cur = project()
found = [x for x in B.verify_world(cfg, AUDIT, key)["findings"] if x["target"] == trunc_t]
a2 = len(cur[0]) != len(prev[0]) + 1 and cur != prev and bool(found)
print(f"A2 violation (log entry of {trunc_t} removed): not a broker step, flagged: {a2}"
      + (f" ({found[0]['finding']})" if found else ""))

ok = violations == 0 and steps > 0 and stutters > 0 and a1 and a2
print("\nR23 correspondence:", "HOLDS on this sample" if ok else "FAILS")
sys.exit(0 if ok else 1)
