"""External audit checkpoints. Predictions written first; prediction 5 is a
stated limit, measured rather than assumed."""
import hashlib, json, os, shutil, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
import darm_guard.checkpoint as C
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; SINK = f"{D}/checkpoints"
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")
def fresh(path):
    for f in (path, path + ".key", path + ".pub.json", path + ".legacy.key", path + ".lock"):
        if os.path.exists(f):
            os.remove(f)
def run_log(path, keys, names):
    fresh(path)
    b = B.Broker(cfg, KernelClient(), B.AuditLog(path), None, None, keys)
    for n in names:
        assert b.handle({"tool": "write_file", "args": [["path", "/workspace/reports/" + n], ["content", n]]})["effect"] == "succeeded"
    return b
def lines(path):
    return open(path).read().splitlines()
def write_lines(path, ls):
    open(path, "w").write("\n".join(ls) + "\n")
def chain_valid(path):
    prev = "0" * 64
    for line in lines(path):
        e = json.loads(line); h = e.pop("entry_hash")
        if e.get("prev_hash") != prev or hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest() != h:
            return False
        prev = h
    return True
def rechain(ls):
    out, prev = [], "0" * 64
    for line in ls:
        e = json.loads(line); e.pop("entry_hash", None); e["prev_hash"] = prev
        h = hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest()
        e["entry_hash"] = h; prev = h
        out.append(json.dumps(e, sort_keys=True))
    return out

shutil.rmtree(SINK, ignore_errors=True)
keys = B.Keys.generate()
auditor = keys.ring.public_only()
L = f"{D}/cp_log.jsonl"
b = run_log(L, keys, ["c1.md", "c2.md", "c3.md"])
cp = C.make_checkpoint(L, keys.ring)
pub = C.publish(cp, SINK)
n = cp["count"]

print("1. public keys only")
check("the checkpoint verifies", auditor.verify_checkpoint(cp), (True, None))
try:
    auditor.sign_checkpoint(cp["genesis"], n, cp["head"]); made = True
except PermissionError:
    made = False
check("an auditor cannot create one", made, False)

print("2. a log that grew")
for m in ("c4.md", "c5.md"):
    assert b.handle({"tool": "write_file", "args": [["path", "/workspace/reports/" + m], ["content", m]]})["effect"] == "succeeded"
r = C.check_log(L, C.load_published(pub), auditor)
check("extends the checkpoint: clean", (r["ok"], r["covered"], r["entries"] > n), (True, n, True))

T = f"{D}/cp_tampered.jsonl"
print("3. truncation below the checkpoint")
write_lines(T, lines(L)[:n - 2])
check("detected", [f["finding"] for f in C.check_log(T, [cp], auditor)["findings"]],
      ["log truncated below a published checkpoint"])

print("4. an early entry rewritten, the whole chain recomputed")
ls = lines(L); e = json.loads(ls[1]); e["tool"] = "read_file"; ls[1] = json.dumps(e, sort_keys=True)
write_lines(T, rechain(ls))
check("the hash chain alone still checks out", chain_valid(T), True)
check("the checkpoint detects it", [f["finding"] for f in C.check_log(T, [cp], auditor)["findings"]],
      ["log rewritten before a published checkpoint"])

print("5. truncation AFTER the last checkpoint (the stated limit)")
write_lines(T, lines(L)[:n + 1])
check("not detected", C.check_log(T, [cp], auditor)["ok"], True)

print("6. a forged checkpoint")
check("count altered: invalid", C.check_log(L, [dict(cp, count=n + 1)], auditor)["findings"][0]["finding"],
      "checkpoint signature invalid")

print("7. a checkpoint for a different log")
L2 = f"{D}/cp_other.jsonl"
run_log(L2, keys, ["o1.md"])
check("rejected", C.check_log(L, [C.make_checkpoint(L2, keys.ring)], auditor)["findings"][0]["finding"],
      "checkpoint is for a different log (or the log's first entry was rewritten)")

print("8. after key rotation")
keys.ring.rotate()
check("the old checkpoint still verifies", C.check_log(L, [cp], keys.ring.public_only())["ok"], True)

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
