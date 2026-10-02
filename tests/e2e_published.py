"""End-to-end check of a PUBLISHED darm-guard release, installed from PyPI.

Usage: pip install --target /tmp/e2e darm-guard==X.Y.Z, then
PYTHONPATH=/tmp/e2e python3 tests/e2e_published.py X.Y.Z"""
import hashlib, json, os, socket, sys, threading
import darm_guard, darm_guard.broker as B, darm_guard.install as I

results = []
def check(name, ok, detail=""):
    results.append(bool(ok))
    print(("PASS " if ok else "FAIL ") + name, str(detail)[:110])

check("running the installed package, not the repository",
      darm_guard.__file__.startswith("/tmp/e2e/") and darm_guard.__version__ == sys.argv[1],
      f"{darm_guard.__version__} from {os.path.dirname(darm_guard.__file__)}")
kp = I.verified_kernel_path()
digest = hashlib.sha256(open(kp, "rb").read()).hexdigest() if kp else None
check("kernel installed and its SHA-256 matches the pinned one", digest == I.KERNEL_SHA256, f"{kp}")

D, SOCK = "/tmp/darmdemo", "/tmp/darm-e2e.sock"
import subprocess as _sp   # start from a fresh fixture, as release.sh does, so a rerun
_sp.run([os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup_demo.sh")],
        check=True, stdout=_sp.DEVNULL)   # gives the release's answer whatever earlier runs left
AUDIT = f"{D}/e2e.jsonl"
for f in (AUDIT, AUDIT + ".key", AUDIT + ".pub.json", AUDIT + ".legacy.key", AUDIT + ".lock", f"{D}/workspace/reports/e2e.md"):
    if os.path.exists(f):
        os.remove(f)
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
srv = B.serve(cfg, SOCK, AUDIT)
threading.Thread(target=srv.serve_forever, daemon=True).start()

def send(msg):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect(SOCK)
        s.sendall((json.dumps(msg) + "\n").encode())
        return json.loads(s.makefile().readline())

r = send({"tool": "read_file", "args": [["path", "/workspace/notes.txt"]]})
check("read through the broker", r.get("effect") == "succeeded" and "hello" in r.get("content", ""))

w = {"tool": "write_file", "args": [["path", "/workspace/reports/e2e.md"], ["content", "end to end"]],
     "idempotency_key": "e2e-1"}
r = send(w)
check("attested write succeeded", r.get("effect") == "succeeded" and r.get("attested") is True)
a1 = [c for c in r.get("basis", []) if c["claim"].startswith("no other route")]
check("evidence basis present; the unproved A1 claim cites no theorem",
      len(r.get("basis", [])) >= 4 and a1 and a1[0]["theorems"] == [], f"{len(r.get('basis', []))} claims")
r = send(w)
check("retry with the same key does not write twice", r.get("effect") == "already_applied")

r = send({"tool": "read_file", "args": [["path", "/workspace/other.txt"]]})
check("invented path rejected on provenance", r.get("failure") == "provenance")
r = send({"tool": "read_file", "args": [["path", "/workspace/../secret.txt"]]})
check("traversal refused", "normal form" in (r.get("error") or ""))

key = B._load_or_create_keys(AUDIT)
check("world matches the log", B.verify_world(cfg, AUDIT, key)["ok"])
with open(f"{D}/workspace/reports/e2e.md", "a") as f:
    f.write(" changed outside the broker")
hits = [x for x in B.verify_world(cfg, AUDIT, key)["findings"] if x["target"].endswith("e2e.md")]
check("change outside the broker detected", bool(hits), hits[0]["finding"] if hits else "")

send({"tool": "write_file", "args": [["path", "/workspace/reports/e2e_del.md"], ["content", "bye"]]})
r = send({"tool": "delete_file", "args": [["path", "/workspace/reports/e2e_del.md"]]})
check("delete_file removes a broker-written file",
      r.get("effect") == "succeeded" and not os.path.exists(f"{D}/workspace/reports/e2e_del.md"))
check("verify_world clean after the delete",
      not [x for x in B.verify_world(cfg, AUDIT, key)["findings"] if x["target"].endswith("e2e_del.md")])
r = send({"tool": "delete_file", "args": [["path", "/workspace/notes.txt"]]})
check("delete outside the delete policy rejected; notes.txt survives",
      r.get("decision") == "reject" and os.path.exists(f"{D}/workspace/notes.txt"))

send({"tool": "write_file", "args": [["path", "/workspace/reports/e2e_mv1.md"], ["content", "moving"]]})
r = send({"tool": "rename_file", "args": [["path", "/workspace/reports/e2e_mv1.md"],
                                          ["destination", "/workspace/reports/e2e_mv2.md"]]})
check("rename_file moves a broker-written file",
      r.get("effect") == "succeeded" and not os.path.exists(f"{D}/workspace/reports/e2e_mv1.md")
      and open(f"{D}/workspace/reports/e2e_mv2.md").read() == "moving")
check("verify_world clean for both paths after the rename",
      not [x for x in B.verify_world(cfg, AUDIT, key)["findings"] if "e2e_mv" in x["target"]])
check("no private file left behind",
      not [n for n in os.listdir(f"{D}/workspace/reports") if ".darm-tmp-" in n])

send({"tool": "write_file", "args": [["path", "/workspace/reports/e2e_self.md"], ["content", "stay"]]})
r = send({"tool": "rename_file", "args": [["path", "/workspace/reports/e2e_self.md"],
                                          ["destination", "/workspace/reports/e2e_self.md"]]})
check("a rename onto itself is refused and changes nothing",
      r.get("effect") == "failed" and "same" in (r.get("error") or "")
      and open(f"{D}/workspace/reports/e2e_self.md").read() == "stay")

auditor = B.Keys(B.KeyRing.load(None, AUDIT + ".pub.json"))
raw = os.getxattr(f"{D}/workspace/reports/e2e_mv2.md", B.XATTR)
check("an auditor holding only public keys verifies a governed file",
      B._check_attestation(auditor, raw) is not None and not
      [x for x in B.verify_world(cfg, AUDIT, auditor)["findings"] if x["target"].endswith("e2e_mv2.md")])

from darm_guard.kernel import KernelClient as _KC
def _intent_broker(name, lines):
    a, ip, rp = f"{D}/{name}.jsonl", f"{D}/{name}.intents", f"{D}/{name}.revocations"
    for f in (a, a + ".key", a + ".pub.json", a + ".legacy.key", a + ".lock"):
        if os.path.exists(f):
            os.remove(f)
    open(ip, "w").write("".join(l + "\n" for l in lines)); open(rp, "w").write("")
    b = B.Broker(cfg, _KC(), B.AuditLog(a), B.load_intents(ip), ip, B.Keys.generate())
    b.revocations_path = rp
    return b, ip, rp
def _w(b, name):
    return b.handle({"tool": "write_file", "args": [["path", "/workspace/reports/" + name], ["content", "x"]]})
ib, _, _ = _intent_broker("e2e_int", ["write_file path=/workspace/reports/e2e_i1.md"])
r1, r2 = _w(ib, "e2e_i1.md"), _w(ib, "e2e_i2.md")
check("a per-resource intent authorizes its file only",
      r1.get("effect") == "succeeded" and r1.get("intent_consumed") == "write_file path=/workspace/reports/e2e_i1.md"
      and r2.get("failure") == "intent")
rb, rip, rrp = _intent_broker("e2e_rev", ["write_file", "write_file"])
open(rrp, "a").write("write_file *\n")
r3 = _w(rb, "e2e_r1.md")
check("a revocation is honored, and nothing is resurrected",
      r3.get("failure") == "intent" and open(rip).read().split() == [])

try:
    B.serve(cfg, "/tmp/darm-e2e-2.sock", AUDIT).server_close()
    second = True
except RuntimeError:
    second = False
check("second broker on the same audit log refused", not second)
srv.shutdown(); srv.server_close()

prev, ok = "0" * 64, True
for line in open(AUDIT):
    e = json.loads(line); h = e.pop("entry_hash")
    ok = ok and e["prev_hash"] == prev and hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest() == h
    prev = h
check("audit hash chain intact", ok)

pb, _, _ = _intent_broker("e2e_prem", ["write_file path=/workspace/reports/e2e_p.md if_present=/workspace/reports/e2e_flag"])
flag = os.path.join(cfg.workspace, "reports", "e2e_flag")
if os.path.exists(flag):
    os.remove(flag)
p1 = _w(pb, "e2e_p.md")
open(flag, "w").write("final")
p2 = _w(pb, "e2e_p.md")
check("a premise-bound intent: refused while its premise is false, redeemed once it holds",
      p1.get("failure") == "intent" and "premise not met" in (p1.get("error") or "")
      and p2.get("effect") == "succeeded", repr(p1.get("error")))

la = f"{D}/e2e_launder.jsonl"
for f in (la, la + ".key", la + ".pub.json", la + ".lock"):
    if os.path.exists(f):
        os.remove(f)
lb = B.Broker(cfg, _KC(), B.AuditLog(la), None, None, B.Keys.generate())
open(os.path.join(cfg.workspace, "reports", "e2e_foreign.md"), "w").write("never written by the broker")
lr = lb.handle({"tool": "rename_file", "args": [["path", "/workspace/reports/e2e_foreign.md"],
                                                ["destination", "/workspace/reports/e2e_laundered.md"]]})
check("a rename refuses a file the broker did not write (no laundering)",
      lr.get("failure") == "attestation"
      and not os.path.exists(os.path.join(cfg.workspace, "reports", "e2e_laundered.md")), lr.get("failure"))
for f in (os.path.join(cfg.workspace, "reports", "e2e_foreign.md"), la, la + ".key", la + ".pub.json", la + ".lock"):
    if os.path.exists(f):
        os.remove(f)

import dataclasses
fa = f"{D}/e2e_fresh.jsonl"
for f in (fa, fa + ".key", fa + ".pub.json", fa + ".lock"):
    if os.path.exists(f):
        os.remove(f)
fb = B.Broker(dataclasses.replace(cfg, read_requires_attestation=True), _KC(), B.AuditLog(fa),
              None, None, B.Keys.generate())
fp = os.path.join(cfg.workspace, "reports", "e2e_fresh.md")
FL = "/workspace/reports/e2e_fresh.md"
fb.handle({"tool": "write_file", "args": [["path", FL], ["content", "version one"]]})
old_bytes, old_att = open(fp).read(), os.getxattr(fp, B.XATTR)
fb.handle({"tool": "write_file", "args": [["path", FL], ["content", "version two"]]})
cur = fb.handle({"tool": "read_file", "args": [["path", FL]]})
with open(fp, "w") as fh:
    fh.write(old_bytes)
os.setxattr(fp, B.XATTR, old_att)
rest = fb.handle({"tool": "read_file", "args": [["path", FL]]})
check("a current read is attributed; a restored one is refused (read freshness)",
      (cur.get("read_attestation") or {}).get("attributed") is True and rest.get("failure") == "attestation",
      rest.get("error"))
for f in (fp, fa, fa + ".key", fa + ".pub.json", fa + ".lock"):   # leave no stale file behind
    if os.path.exists(f):
        os.remove(f)

ka = f"{D}/e2e_k6.jsonl"
for f in (ka, ka + ".key", ka + ".pub.json", ka + ".lock"):
    if os.path.exists(f):
        os.remove(f)
kb = B.Broker(cfg, _KC(), B.AuditLog(ka), None, None, B.Keys.generate())
KP = "/workspace/reports/e2e_k6.md"
kargs = [["path", KP], ["content", "k6"]]
kw = kb.handle({"tool": "write_file", "args": kargs})
kprep = [e for e in (json.loads(l) for l in open(ka) if l.strip())
         if e.get("event") == "prepared" and e.get("request_id") == kw.get("request_id")]
kd = _KC().decide({"policy": cfg.policy,
                   "credential": {"tools": list(cfg.credential_tools), "expired": cfg.expired(None)},
                   "registry": {"values": sorted(cfg.registry), "prefixes": list(cfg.patterns)},
                   "proposal": {"tool": "write_file", "args": kargs}})
check("the kernel canonicalizes: what was prepared is exactly the kernel's invocation (by hash)",
      kw.get("effect") == "succeeded" and bool(kprep) and kd.invocation is not None
      and kprep[0].get("invocation_hash") == B.invocation_hash(kd.invocation), kw.get("effect"))
kn = kb.handle({"tool": "write_file", "args": [["path", "//workspace/reports/e2e_k6b.md"], ["content", "x"]]})
check("a path POSIX keeps but normalPath refuses ('//...') is refused before the decision",
      kn.get("error") == "path not in normal form", kn.get("error"))
for f in (os.path.join(cfg.workspace, "reports", "e2e_k6.md"), ka, ka + ".key", ka + ".pub.json", ka + ".lock"):
    if os.path.exists(f):
        os.remove(f)

from darm_guard.coverage import coverage, kernel_adapter
rows = coverage(kernel_adapter)
check("the coverage map: every case self-checked, every dimension covered, the untrusted payload admitted",
      all(r["kernel"] == "ok" for r in rows)
      and [r["gate"] for r in rows if r["expected"] != "admit"] == ["covers"] * 6
      and rows[-1]["gate"] == "argument-aware (admits)", f"{len(rows)} cases")

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
