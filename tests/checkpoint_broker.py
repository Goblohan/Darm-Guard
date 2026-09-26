"""The broker publishes checkpoints on its own. Predictions written first."""
import json, os, shutil, signal, subprocess, sys, time
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
import darm_guard.checkpoint as C
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")
def fresh(path):
    for f in (path, path + ".key", path + ".pub.json", path + ".legacy.key", path + ".lock"):
        if os.path.exists(f):
            os.remove(f)
def write(b, name):
    r = b.handle({"tool": "write_file", "args": [["path", "/workspace/reports/" + name], ["content", name]]})
    assert r.get("effect") == "succeeded", r
def events(path):
    return [json.loads(l).get("event") for l in open(path) if l.strip()]

keys = B.Keys.generate()
auditor = keys.ring.public_only()

print("1-3. every N records")
S = f"{D}/cp_sink"; shutil.rmtree(S, ignore_errors=True)
L = f"{D}/cpb.jsonl"; fresh(L)
audit = B.AuditLog(L)
audit.checkpointer = C.Checkpointer(keys.ring, S, 4)
b = B.Broker(cfg, KernelClient(), audit, None, None, keys)
for i in range(7):
    write(b, f"k{i}.md")
cps = C.load_published(audit.checkpointer.path_for(audit.genesis))
check("1 published at", [cp["count"] for cp in cps], [4, 8, 12])
r = C.check_log(L, cps, auditor)
check("2 all verify with public keys; covered of entries", (r["ok"], r["covered"], r["entries"]), (True, 12, 14))
check("3 unprotected tail smaller than N", r["entries"] - r["covered"] < 4, True)

print("4. startup")
keys.ring.save(L + ".key", L + ".pub.json")
srv = B.serve(cfg, "/tmp/darm-cpb.sock", L, checkpoint_sink=S, checkpoint_every=4)
srv.server_close()
cps = C.load_published(C.Checkpointer(keys.ring, S, 4).path_for(audit.genesis))
check("a checkpoint covering the existing log", cps[-1]["count"], 14)

print("5. an unreachable sink")
BAD = f"{D}/cp_bad_sink"; F = f"{D}/cpf.jsonl"; fresh(F)
shutil.rmtree(BAD, ignore_errors=True)
open(BAD, "w").write("not a directory")                   # publishing here fails
fa = B.AuditLog(F); fa.checkpointer = C.Checkpointer(keys.ring, BAD, 2)
fb = B.Broker(cfg, KernelClient(), fa, None, None, keys)
write(fb, "f1.md"); write(fb, "f2.md")
ev = events(F)
check("writes still succeed, and the failure is in the log",
      (ev.count("outcome"), "checkpoint_failed" in ev), (2, True))
fail_index = ev.index("checkpoint_failed") + 1
os.remove(BAD)
for i in range(3, 7):
    write(fb, f"f{i}.md")
cps = C.load_published(fa.checkpointer.path_for(fa.genesis))
check("once the sink is back, a checkpoint covers the failure record",
      bool(cps) and cps[-1]["count"] >= fail_index and C.check_log(F, cps, auditor)["ok"], True)

print("6. the real broker, stopped with SIGTERM")
M = f"{D}/cpm.jsonl"; fresh(M); S2 = f"{D}/cp_sink2"; shutil.rmtree(S2, ignore_errors=True)
sock = "/tmp/darm-cpm.sock"
p = subprocess.Popen([sys.executable, "-c", "from darm_guard.broker import main; main()",
                      "--config", f"{D}/config.json", "--registry", f"{D}/registry.txt",
                      "--socket", sock, "--audit", M, "--checkpoint-sink", S2, "--checkpoint-every", "1000"],
                     env=dict(os.environ, PYTHONPATH=ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
# wait for the start record, not the socket: the socket appears before keys,
# the kernel client and reconciliation, and the SIGTERM handler is installed only
# after start is written. Waiting for the socket plus a fixed 0.5 s raced (the gap
# measured 0.36 s, and exceeded 0.5 s under load during a regression run).
deadline = time.time() + 20
while time.time() < deadline and not (os.path.exists(M) and '"start"' in open(M).read()):
    time.sleep(0.05)
p.send_signal(signal.SIGTERM)
p.wait(timeout=10)
ring = B.KeyRing.load(None, M + ".pub.json")
genesis = json.loads(open(M).readline())["entry_hash"]
cps = C.load_published(os.path.join(S2, genesis[:16] + ".checkpoints.jsonl"))
ev = events(M)
check("the log ends with a stop record", ev[-1], "stop")
check("a final checkpoint covers it, and verifies",
      bool(cps) and cps[-1]["count"] == len(ev) and C.check_log(M, cps, ring)["ok"], True)

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
