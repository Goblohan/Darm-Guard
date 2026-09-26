"""Export a trace from the running broker for Lean to check against B8.
Usage: python3 tests/export_b8_trace.py N OUT.lean [--corrupt]
No model logic here: operations are read from the broker's responses and
the state is projected from the audit log and the files. With --corrupt,
one recorded digest is altered and the theorem states the check fails."""
import hashlib, json, os, random, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

N, OUT, CORRUPT = int(sys.argv[1]), sys.argv[2], "--corrupt" in sys.argv
D = "/tmp/darmdemo"; WS = f"{D}/workspace"; AUDIT = f"{D}/trace_export.jsonl"
for f in (AUDIT, AUDIT + ".key", AUDIT + ".pub.json", AUDIT + ".legacy.key", AUDIT + ".lock"):
    if os.path.exists(f):
        os.remove(f)
open(AUDIT, "a").close()
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
key = B.Keys.generate()
broker = B.Broker(cfg, KernelClient(), B.AuditLog(AUDIT), None, None, key)
NAMES = ["a.md", "b.md", "c.md"]
T = ["/workspace/reports/" + n for n in NAMES]
short = lambda p: p[len(B.LOGICAL_ROOT):]
rids, digs = {}, {}
def rid_n(r):
    rids.setdefault(r, len(rids) + 1); return rids[r]
def dig_s(d):
    digs.setdefault(d, f"d{len(digs)}"); return digs[d]

def snapshot():
    entries, prepared = [], {}
    for line in open(AUDIT):
        e = json.loads(line)
        if e.get("event") == "prepared":
            prepared[e["request_id"]] = e
        tool, rid, t = e.get("tool"), e.get("request_id"), e.get("target")
        if tool not in ("write_file", "delete_file", "rename_file") or not t:
            continue
        if not ((e.get("event") == "outcome" and e.get("effect") == "succeeded") or
                (e.get("event") == "reconciled" and e.get("reconciliation") == "confirmedSuccess")):
            continue
        src = e if e.get("event") == "outcome" else prepared.get(rid, {})
        if tool == "write_file":
            entries.append((rid_n(rid), short(t), ("write", dig_s(src["intended_state"][1]))))
        elif tool == "delete_file":
            entries.append((rid_n(rid), short(t), ("del",)))
        else:
            entries.append((rid_n(rid), short(e["source"]), ("del",)))
            entries.append((rid_n(rid), short(t), ("write", dig_s(src["intended_state"][1]))))
    files = []
    for t in T:
        p = os.path.join(WS, t[len(B.LOGICAL_ROOT):])
        if not os.path.exists(p):
            files.append((short(t), None)); continue
        d = dig_s(hashlib.sha256(open(p, "rb").read()).hexdigest())
        try:
            raw = os.getxattr(p, B.XATTR, follow_symlinks=False)
        except OSError:
            raw = None
        att = None
        if raw is not None:
            a = B._check_attestation(key, raw)
            if not a or a.get("target") != t:
                sys.exit(f"invalid attestation on {t}: not representable in B8")
            att = (rid_n(a["rid"]), dig_s(a["digest"]))
        files.append((short(t), (d, att)))
    return list(reversed(entries)), files

def L_entry(r, t, op):
    return f'Entry.mk {r} "{t}" (Op.write "{op[1]}")' if op[0] == "write" else f'Entry.mk {r} "{t}" Op.del'
def L_file(f):
    if f is None:
        return "none"
    d, att = f
    return f'some (File.mk "{d}" none)' if att is None else f'some (File.mk "{d}" (some ({att[0]}, "{att[1]}")))'
def L_snap(s):
    log, files = s
    return ("Snapshot.mk [" + ", ".join(L_entry(*e) for e in log) + "] ["
            + ", ".join(f'("{t}", {L_file(f)})' for t, f in files) + "]")
def L_op(op):
    if op is None:
        return "none"
    if op[0] == "wr":
        return f'some (BrokerOp.wr {op[1]} "{op[2]}" "{op[3]}")'
    if op[0] == "dl":
        return f'some (BrokerOp.dl {op[1]} "{op[2]}")'
    return f'some (BrokerOp.mv {op[1]} "{op[2]}" "{op[3]}" "{op[4]}")'

SEED = int(os.environ.get("SEED", "9"))
rng = random.Random(SEED)
def request():
    k, n = rng.random(), (lambda: "/workspace/reports/" + rng.choice(NAMES))
    if k < 0.35:
        p = {"tool": "write_file", "args": [["path", n()], ["content", rng.choice(["x", "y", "z"])]]}
    elif k < 0.55:
        p = {"tool": "delete_file", "args": [["path", n()]]}
    elif k < 0.75:
        p = {"tool": "rename_file", "args": [["path", n()], ["destination", n()]]}
    elif k < 0.85:
        p = {"tool": "delete_file", "args": [["path", "/workspace/notes.txt"]]}
    else:
        p = {"tool": "read_file", "args": [["path", "/workspace/notes.txt"]]}
    if p["tool"] != "read_file" and rng.random() < 0.25:
        p["idempotency_key"] = f"k{rng.randrange(4)}"
    return p

if any(f is not None for _, f in snapshot()[1]):
    sys.exit("governed files already present: run tests/setup_demo.sh first")
steps, counts = [], {"wr": 0, "dl": 0, "mv": 0, "none": 0}
for i in range(N):
    r, op, bs = broker.handle(request()), None, []
    if r.get("effect") == "succeeded":
        if "written" in r:
            op = ("wr", rid_n(r["request_id"]), short(r["target"]), dig_s(r["intended_state"][1]))
        elif r.get("deleted"):
            op = ("dl", rid_n(r["request_id"]), short(r["target"]))
        elif r.get("renamed"):
            op = ("mv", rid_n(r["request_id"]), short(r["source"]), short(r["target"]),
                  dig_s(r["intended_state"][1]))
    if op is not None:
        def bstate(s):
            if s is None or s[0] == "absent":
                return None
            if s[0] != "present":
                sys.exit(f"unrepresentable recorded before-state {s}")
            return dig_s(s[1])
        if op[0] == "mv":
            bs = [(short(r["source"]), bstate(r["before_state"])),
                  (short(r["target"]), bstate(r.get("destination_before")))]
        else:
            bs = [(short(r["target"]), bstate(r["before_state"]))]
    counts[op[0] if op else "none"] += 1
    steps.append((op, bs, snapshot()))

if CORRUPT:
    for j in range(len(steps) - 1, -1, -1):
        op_j, bs_j, (log, files) = steps[j]
        k = next((m for m, (_, f) in enumerate(files) if f is not None), None)
        if k is not None:
            t, (d, att) = files[k]
            files = files[:k] + [(t, ("dCORRUPT", att))] + files[k + 1:]
            steps[j] = (op_j, bs_j, (log, files))
            print(f"corrupted step {j}: {t} digest {d} -> dCORRUPT")
            break

CORRUPT_BEFORE, WITH_BEFORE = "--corrupt-before" in sys.argv, "--with-before" in sys.argv
if CORRUPT_BEFORE:
    for j in range(len(steps) - 1, -1, -1):
        op_j, bs_j, snap_j = steps[j]
        k = next((m for m, (_, b) in enumerate(bs_j) if b is not None), None)
        if k is not None:
            tt, b = bs_j[k]
            steps[j] = (op_j, bs_j[:k] + [(tt, "dCORRUPT")] + bs_j[k + 1:], snap_j)
            print(f"corrupted recorded before-state at step {j}: {tt} {b} -> dCORRUPT (after-states untouched)")
            break
bad = CORRUPT or CORRUPT_BEFORE
ns = os.environ.get("NS") or ("DARM.TraceSampleBad" if bad else "DARM.TraceSample")
def L_b(b):
    return "none" if b is None else 'some "' + b + '"'
def L_bs(bs):
    return "[" + ", ".join(f'("{p}", {L_b(b)})' for p, b in bs) + "]"
if WITH_BEFORE:
    ty = "List (Option BrokerOp × List (String × Option String) × Snapshot)"
    body = ",\n".join(f"  ({L_op(op)}, {L_bs(bs)},\n    {L_snap(s)})" for op, bs, s in steps)
    fn = "checkTraceB"
else:
    ty = "List (Option BrokerOp × Snapshot)"
    body = ",\n".join(f"  ({L_op(op)},\n    {L_snap(s)})" for op, bs, s in steps)
    fn = "checkTrace"
note = (" One recorded before-state corrupted, after-states untouched: the check must fail."
        if CORRUPT_BEFORE else " One digest corrupted: the check must fail." if CORRUPT else "")
blind = ("theorem after_only_checker_blind : checkTrace DARM.EffectIntegrity2.empty "
         "(trace.map (fun x => (x.1, x.2.2))) = true := by decide\n\n") if (CORRUPT_BEFORE and WITH_BEFORE) else ""
with open(OUT, "w") as f:
    f.write(f"/-\n  Generated by darm-guard tests/export_b8_trace.py: {N} requests, seed {SEED}.\n"
            f"  Operations {counts}.{note}\n-/\nimport B8TraceCheck\n\nnamespace {ns}\n"
            f"open DARM.EffectIntegrity2 DARM.TraceCheck\n\nset_option maxRecDepth 100000\n"
            f"set_option maxHeartbeats 4000000\n\ndef trace : {ty} := [\n{body}\n]\n\n"
            f"theorem trace_{'rejected' if bad else 'agrees'} : {fn} DARM.EffectIntegrity2.empty trace = "
            f"{'false' if bad else 'true'} := by decide\n\n{blind}end {ns}\n")
print("operations:", counts, "->", OUT)
