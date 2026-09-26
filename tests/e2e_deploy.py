"""End-to-end deployment check against the PUBLISHED package, in a fresh
virtual environment: the installed darm-broker command, a real broker process
with intents, revocations and checkpoints, an agent speaking raw JSON over the
socket, and an auditor holding only public keys. Predictions first."""
import hashlib, json, os, shutil, signal, socket, subprocess, sys, time
import darm_guard
import darm_guard.broker as B
import darm_guard.checkpoint as C

D = "/tmp/darmdemo"; R = f"{D}/workspace/reports"
A, SOCK = f"{D}/deploy.jsonl", "/tmp/darm-deploy.sock"
IP, RP, SINK = f"{D}/deploy.intents", f"{D}/deploy.revocations", f"{D}/deploy_sink"
results = []
def check(label, ok, detail=""):
    results.append(bool(ok))
    print(f"{'PASS' if ok else 'FAIL'} {label}" + (f"   [{detail}]" if detail else ""))
def raw(msg):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(SOCK); s.sendall((json.dumps(msg) + "\n").encode())
        return json.loads(s.makefile().readline())
def propose(tool, **args):
    return raw({"tool": tool, "args": [[k, v] for k, v in args.items()]})
def rp(p):
    return "/workspace/reports/" + p

check("the package comes from the fresh virtual environment",
      "/tmp/e2e_venv/" in darm_guard.__file__, f"{darm_guard.__version__} at {os.path.dirname(darm_guard.__file__)}")
cli = shutil.which("darm-broker")
check("the darm-broker command is installed", cli is not None, cli or "not on PATH")

for f in (A, A + ".key", A + ".pub.json", A + ".legacy.key", A + ".lock", SOCK):
    if os.path.exists(f): os.remove(f)
shutil.rmtree(SINK, ignore_errors=True)
open(IP, "w").write("\n".join([
    "write_file",
    f"write_file path={rp('d1.md')}",
    f"rename_file path={rp('d1.md')} destination={rp('d3.md')}",
    f"delete_file path={rp('d3.md')}"]) + "\n")
open(RP, "w").write("")

proc = subprocess.Popen([cli or "darm-broker", "--config", f"{D}/config.json", "--registry", f"{D}/registry.txt",
                         "--socket", SOCK, "--audit", A, "--intents", IP, "--revocations", RP,
                         "--checkpoint-sink", SINK, "--checkpoint-every", "4"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
deadline = time.time() + 20
while time.time() < deadline and not (os.path.exists(A) and '"start"' in open(A).read()):
    if proc.poll() is not None:
        break
    time.sleep(0.05)
check("the broker process started", proc.poll() is None,
      "" if proc.poll() is None else proc.stderr.read().decode()[-200:])

r = propose("write_file", path=rp("d1.md"), content="one")
check("write d1: succeeds on the tool-wide intent (broadest first)",
      r.get("effect") == "succeeded" and r.get("intent_consumed") == "write_file", r.get("intent_consumed"))
r = propose("write_file", path=rp("d2.md"), content="two")
check("write d2: refused, the only write intent left binds d1", r.get("failure") == "intent", r.get("failure"))
r = propose("write_file", path=rp("d1.md"), content="one again")
check("write d1 again: succeeds on the bound intent", r.get("effect") == "succeeded", r.get("intent_consumed"))
r = propose("rename_file", path=rp("d1.md"), destination=rp("d9.md"))
check("rename d1 -> d9: refused, the intent names d3", r.get("failure") == "intent", r.get("failure"))
r = propose("rename_file", path=rp("d1.md"), destination=rp("d3.md"))
check("rename d1 -> d3: succeeds", r.get("effect") == "succeeded" and os.path.exists(f"{R}/d3.md"), r.get("effect"))
r = raw({"tool": "write_file", "args": [["path", rp("d3.md")], ["path", f"/workspace/notes.txt"], ["content", "x"]]})
check("two path arguments: refused as malformed (P14)", r.get("error") == "malformed proposal", r.get("error"))
open(RP, "a").write("delete_file *\n")
r = propose("delete_file", path=rp("d3.md"))
check("after the principal revokes deletes, the delete is refused",
      r.get("failure") == "intent" and os.path.exists(f"{R}/d3.md"), r.get("failure"))
check("the intents file ends empty; the revocations file is untouched",
      open(IP).read().split() == [] and open(RP).read() == "delete_file *\n")

proc.send_signal(signal.SIGTERM)
proc.wait(timeout=15)
events = [json.loads(l).get("event") for l in open(A) if l.strip()]
check("stopped by SIGTERM: the log ends with stop", events[-1] == "stop", events[-1])

cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
auditor = B.Keys(B.KeyRing.load(None, A + ".pub.json"))
genesis = json.loads(open(A).readline())["entry_hash"]
cps = C.load_published(os.path.join(SINK, genesis[:16] + ".checkpoints.jsonl"))
res = C.check_log(A, cps, auditor.ring)
check("checkpoints: several published, the last covers the stop record, all valid",
      len(cps) > 1 and cps[-1]["count"] == len(events) and res["ok"], f"{len(cps)} checkpoints, covered {res['covered']}/{len(events)}")
w = B.verify_world(cfg, A, auditor)
check("the world verifies clean with public keys only", w["ok"], w["findings"][:2])
def chain_ok(lines):
    prev = "0" * 64
    for line in lines:
        e = json.loads(line); h = e.pop("entry_hash")
        if e.get("prev_hash") != prev or hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest() != h:
            return False
        prev = h
    return True
lines = open(A).read().splitlines()
check("the audit hash chain is intact", chain_ok(lines))

forged, prev = [], "0" * 64
for n, line in enumerate(lines):
    e = json.loads(line); e.pop("entry_hash")
    if n == 2:
        e["tampered"] = True
    e["prev_hash"] = prev
    h = hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest(); e["entry_hash"] = h; prev = h
    forged.append(json.dumps(e, sort_keys=True))
T = f"{D}/deploy_forged.jsonl"; open(T, "w").write("\n".join(forged) + "\n")
check("a rewritten log with a recomputed chain: the chain accepts it...", chain_ok(forged))
check("...and the published checkpoints reject it", not C.check_log(T, cps, auditor.ring)["ok"])

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
