"""Phase 1 adversarial probes against the B5 broker.

Each probe prints HELD (the system resisted), EXPOSED (the attack worked, or
the defence does not exist yet), or INCONCLUSIVE (the hook never fired, so the
probe proved nothing). Written to be EXPOSED today; each fix should flip one.
"""
import dataclasses, json, os, sys, threading
from datetime import timedelta

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D, WS, OUT = "/tmp/darmdemo", "/tmp/darmdemo/workspace", "/tmp/darm_outside"
os.makedirs(f"{WS}/reports", exist_ok=True)
os.makedirs(OUT, exist_ok=True)
CFG = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
results = []

def report(name, held, detail="", fired=True):
    status = "INCONCLUSIVE" if not fired else ("HELD" if held else "EXPOSED")
    results.append(status)
    print(f"{status:12s} {name}  {str(detail)[:130]}")

def fresh(audit_name, cfg=None, intents=None):
    path = f"{D}/{audit_name}"
    for p in (path,):
        if os.path.exists(p):
            os.remove(p)
    return B.Broker(cfg or CFG, KernelClient(), B.AuditLog(path), intents), path

def wprop(name, content="probe", **extra):
    return dict({"tool": "write_file",
                 "args": [["path", f"/workspace/reports/{name}"], ["content", content]]}, **extra)

def entries(path):
    return [json.loads(l) for l in open(path) if l.strip()] if os.path.exists(path) else []

def rm(p):
    if os.path.islink(p) or os.path.isfile(p):
        os.remove(p)

# P1: parent directory swapped for a symlink (two windows)
def swap_in():
    os.rename(f"{WS}/reports", f"{WS}/reports_orig")
    os.symlink(OUT, f"{WS}/reports")
def swap_out():
    if os.path.islink(f"{WS}/reports"):
        os.remove(f"{WS}/reports")
        os.rename(f"{WS}/reports_orig", f"{WS}/reports")

# P1a: swapped after the decision, before execution starts
orig_exec, fired = B._execute, [False]
def swap_then_exec(cfg, inv, *rest):
    if any(a["value"].endswith("p1a.md") for a in inv["args"]):
        swap_in(); fired[0] = True
    return orig_exec(cfg, inv, *rest)
rm(f"{OUT}/p1a.md")
B._execute = swap_then_exec
try:
    b, _ = fresh("p1a.jsonl")
    r = b.handle(wprop("p1a.md", "P1A"))
finally:
    B._execute = orig_exec
    swap_out()
esc = os.path.exists(f"{OUT}/p1a.md")
report("P1a symlink swap after decision, before execution", not esc,
       f"wrote outside the workspace: {esc}; effect={r.get('effect')}", fired[0])

# P1b: swapped inside execution, after path resolution, before the write
hook = "_open_parent" if hasattr(B, "_open_parent") else "_real_in_workspace"
orig_h, fired = getattr(B, hook), [False]
def after_resolution(cfg, path):
    res = orig_h(cfg, path)
    if res and path.endswith("p1b.md") and sys._getframe(1).f_code.co_name == "_execute":
        swap_in(); fired[0] = True
    return res
rm(f"{OUT}/p1b.md")
setattr(B, hook, after_resolution)
try:
    b, _ = fresh("p1b.jsonl")
    r = b.handle(wprop("p1b.md", "P1B"))
finally:
    setattr(B, hook, orig_h)
    swap_out()
esc = os.path.exists(f"{OUT}/p1b.md")
report(f"P1b symlink swap inside the resolution-to-write window (hook: {hook})", not esc,
       f"wrote outside the workspace: {esc}; effect={r.get('effect')}", fired[0])

# P2: a foreign writer changes the target between 'prepared' and the effect
orig_exec, fired = B._execute, [False]
def foreign_then_exec(cfg, inv, *rest):
    if any(a["value"].endswith("p2.md") for a in inv["args"]):
        open(f"{WS}/reports/p2.md", "w").write("FOREIGN WRITE")
        fired[0] = True
    return orig_exec(cfg, inv, *rest)
open(f"{WS}/reports/p2.md", "w").write("BEFORE")
B._execute = foreign_then_exec
try:
    b, _ = fresh("p2.jsonl")
    r = b.handle(wprop("p2.md", "BROKER WRITE"))
finally:
    B._execute = orig_exec
final2 = open(f"{WS}/reports/p2.md").read()
flagged = "conflict" in json.dumps(r).lower() and final2 == "FOREIGN WRITE"
report("P2 foreign write between prepared and effect", flagged,
       f"final={open(f'{WS}/reports/p2.md').read()!r}; effect={r.get('effect')}; "
       f"reconciliation={r.get('reconciliation')}", fired[0])

# P3: crash between effect and outcome record, then restart
orig_record, fired = B.Broker._record, [False]
def crash_on_outcome(self, rid, event, inv, tool, resp):
    if event == "outcome":
        fired[0] = True
        raise OSError("simulated crash before the outcome record")
    return orig_record(self, rid, event, inv, tool, resp)
B.Broker._record = crash_on_outcome
try:
    b, a3 = fresh("p3.jsonl")
    r = b.handle(wprop("p3.md", "P3"))
finally:
    B.Broker._record = orig_record
rid = r.get("request_id")
srv = B.serve(CFG, "/tmp/darm-probe3.sock", a3)
srv.server_close()
later = [e.get("event") for e in entries(a3) if e.get("request_id") == rid]
report("P3 restart reconciles a request left prepared-without-outcome",
       any(ev not in ("prepared", "outcome") for ev in later),
       f"records for that request after restart: {later}", fired[0])

# P4: a second broker on the same audit log
a4 = f"{D}/p4.jsonl"
rm(a4)
s1 = B.serve(CFG, "/tmp/darm-probe4a.sock", a4)
try:
    s2 = B.serve(CFG, "/tmp/darm-probe4b.sock", a4)
    s2.server_close()
    second = True
except Exception as e:
    second = False
s1.server_close()
report("P4 second broker refused on the same audit log", not second,
       f"second broker started: {second}")

# P5: clock rolled back resurrects an expired credential
real_dt = B.datetime
class RolledBack(real_dt):
    @classmethod
    def now(cls, tz=None):
        return real_dt.now(tz) - timedelta(hours=3)
cfg5 = dataclasses.replace(CFG, issued_at=real_dt.now() - timedelta(hours=2), ttl_seconds=3600)
b, _ = fresh("p5.jsonl", cfg=cfg5)
r_true = b.handle(wprop("p5a.md"))
B.datetime = RolledBack
try:
    r_rolled = b.handle(wprop("p5b.md"))
finally:
    B.datetime = real_dt
report("P5 clock rollback cannot resurrect an expired credential",
       r_rolled.get("decision") != "admit",
       f"true clock: {r_true.get('decision')}/{r_true.get('failure')}; "
       f"rolled back 3h: {r_rolled.get('decision')}")

# P6: caller identity recorded from the kernel
a6, sock6 = f"{D}/p6.jsonl", "/tmp/darm-probe6.sock"
rm(a6)
srv = B.serve(CFG, sock6, a6)
threading.Thread(target=srv.serve_forever, daemon=True).start()
r = B.BrokerClient(sock6).propose("read_file", {"path": "/workspace/notes.txt"})
srv.shutdown(); srv.server_close()
recs = [e for e in entries(a6) if e.get("request_id") == r.get("request_id")]
has_peer = any(any(k in e for k in ("peer", "peer_uid", "peer_pid", "caller")) for e in recs)
report("P6 caller identity recorded", has_peer, f"record keys: {sorted(recs[0]) if recs else '-'}")

# P7: retry with an idempotency key applies once
b, a7 = fresh("p7.jsonl")
prop = wprop("p7.md", "ONCE", idempotency_key="probe-7")
r1, r2 = b.handle(prop), b.handle(prop)
prepared = [e for e in entries(a7) if e.get("event") == "prepared"]
report("P7 idempotent retry applies once",
       r1.get("effect") == "succeeded" and len(prepared) == 1 and "already" in json.dumps(r2).lower(),
       f"first: {r1.get('effect') or r1.get('error')}; second: {r2.get('effect') or r2.get('error')}; "
       f"prepared records: {len(prepared)}")

# P8, P9: the world checked against the log (Phase 3)
key = B.Keys.generate()
a8 = f"{D}/p8.jsonl"
rm(a8)
b8 = B.Broker(CFG, KernelClient(), B.AuditLog(a8), None, None, key)
r8 = b8.handle(wprop("p8.md", "ATTESTED"))
clean8 = [x for x in B.verify_world(CFG, a8, key)["findings"] if x["target"].endswith("p8.md")]
with open(f"{WS}/reports/p8.md", "a") as f:
    f.write(" tampered outside the broker")
hit8 = [x for x in B.verify_world(CFG, a8, key)["findings"] if x["target"].endswith("p8.md")]
report("P8 governed file changed outside the broker is detected",
       bool(r8.get("attested")) and not clean8 and bool(hit8),
       f"attested={r8.get('attested')}; before tamper: {clean8 or 'clean'}; after: "
       f"{hit8[0]['finding'] if hit8 else 'nothing found'}")

a9 = f"{D}/p9.jsonl"
rm(a9)
b9 = B.Broker(CFG, KernelClient(), B.AuditLog(a9), None, None, key)
b9.handle(wprop("p9a.md", "FIRST"))
r9 = b9.handle(wprop("p9b.md", "SECOND"))
kept = [l for l in open(a9).read().splitlines()
        if json.loads(l).get("request_id") != r9.get("request_id")]
open(a9, "w").write("\n".join(kept) + "\n")
hit9 = [x for x in B.verify_world(CFG, a9, key)["findings"] if x["target"].endswith("p9b.md")]
report("P9 audit tail truncation is detected",
       bool(r9.get("attested")) and bool(hit9),
       f"attested={r9.get('attested')}; after cutting the tail: "
       f"{hit9[0]['finding'] if hit9 else 'nothing found'}")

# P11: a failed keyed attempt must never be reported as already applied
b, _ = fresh("p11.jsonl")
p11 = {"tool": "write_file", "args": [["path", "/workspace/link.txt"], ["content", "x"]],
       "idempotency_key": "p11"}
r1, r2 = b.handle(p11), b.handle(p11)
report("P11 a failed keyed attempt is never reported as already applied",
       r1.get("effect") == "failed" and r2.get("effect") != "already_applied",
       f"first: {r1.get('effect')}; retry: {r2.get('effect')} {r2.get('error') or ''}")

# P12: a key left unresolved by reconciliation must never be reported as already applied
orig_record, fired = B.Broker._record, [False]
def crash_p12(self, rid, event, inv, tool, resp):
    if event == "outcome" and resp.get("idempotency_key") == "p12":
        fired[0] = True
        raise OSError("simulated crash before the outcome record")
    return orig_record(self, rid, event, inv, tool, resp)
B.Broker._record = crash_p12
try:
    b, a12 = fresh("p12.jsonl")
    p12 = wprop("p12.md", "P12", idempotency_key="p12")
    b.handle(p12)
finally:
    B.Broker._record = orig_record
open(f"{WS}/reports/p12.md", "w").write("A THIRD STATE")
srv = B.serve(CFG, "/tmp/darm-probe12.sock", a12)
verdicts = [e.get("reconciliation") for e in entries(a12) if e.get("event") == "reconciled"]
r = srv.broker.handle(p12)
srv.server_close()
report("P12 a key left unresolved by reconciliation is never reported as already applied",
       r.get("effect") != "already_applied",
       f"reconciliation: {verdicts}; retry after restart: {r.get('effect')} {r.get('error') or ''}",
       fired[0])

# P10: 100 simultaneous clients, one intent
a10, sock10, ip = f"{D}/p10.jsonl", "/tmp/darm-probe10.sock", f"{D}/p10_intents.txt"
rm(a10)
open(ip, "w").write("write_file\n")
srv = B.serve(CFG, sock10, a10, intents_path=ip)
threading.Thread(target=srv.serve_forever, daemon=True).start()
out, lock = [], threading.Lock()
def worker(i):
    r = B.BrokerClient(sock10).propose("write_file",
                                        {"path": f"/workspace/reports/p10_{i}.md", "content": "x"})
    with lock:
        out.append(r)
ts = [threading.Thread(target=worker, args=(i,)) for i in range(100)]
for t in ts: t.start()
for t in ts: t.join()
srv.shutdown(); srv.server_close()
spent = sum(r.get("effect") == "succeeded" for r in out)
unknown = sum(r.get("effect") == "unknown" for r in out)
unavail = sum("unavailable" in (r.get("error") or "") for r in out)
report("P10 one intent, 100 clients: one spend, no unknowns, none dropped",
       spent == 1 and unknown == 0 and unavail == 0,
       f"spent={spent} unknown={unknown} unavailable={unavail} of {len(out)}")

print(f"\nHELD {results.count('HELD')}  EXPOSED {results.count('EXPOSED')}  "
      f"INCONCLUSIVE {results.count('INCONCLUSIVE')}  of {len(results)}")
sys.exit(0 if results.count('HELD') == len(results) else 1)
