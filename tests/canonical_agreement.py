"""The broker executes the kernel's canonical invocation (darm-monitor K6) and
cross-checks its own canonicalization against it on every request: a
disagreement refuses before any effect. Predictions first."""
import json, os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; R = f"{D}/workspace/reports"; L = "/workspace/reports/"
A = f"{D}/agree.jsonl"
for f in (A, A + ".key", A + ".pub.json", A + ".lock"):
    if os.path.exists(f): os.remove(f)
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
b = B.Broker(cfg, KernelClient(), B.AuditLog(A), None, None, B.Keys.generate())
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")

w = b.handle({"tool": "write_file", "args": [["path", L + "ca.md"], ["content", "agreed"]]})
prep = [e for e in (json.loads(l) for l in open(A) if l.strip())
        if e.get("event") == "prepared" and e.get("request_id") == w.get("request_id")]
check("1. a normal write is admitted and performed", w.get("effect"), "succeeded")
# ask the real kernel directly, with the request the broker sends, and compare
# the hash of the invocation it returns with the one recorded as prepared
args = [["path", L + "ca.md"], ["content", "agreed"]]
kd = KernelClient().decide({"policy": cfg.policy,
                            "credential": {"tools": list(cfg.credential_tools), "expired": cfg.expired(None)},
                            "registry": {"values": sorted(cfg.registry), "prefixes": list(cfg.patterns)},
                            "proposal": {"tool": "write_file", "args": args}})
check("2. what was prepared is exactly the kernel's invocation (by hash), with the path derived",
      (bool(prep) and kd.invocation is not None
       and prep[0].get("invocation_hash") == B.invocation_hash(kd.invocation),
       [a.get("prov") for a in (kd.invocation or {}).get("args", []) if a.get("key") == "path"]),
      (True, ["derived"]))

real = B.assign_prov
B.assign_prov = lambda registry, value, patterns=(): "authoritative"   # the broker's rule, broken
try:
    r = b.handle({"tool": "write_file", "args": [["path", L + "ca2.md"], ["content", "x"]]})
finally:
    B.assign_prov = real
check("3. a broker whose canonicalization disagrees with the kernel is refused",
      (r.get("decision"), "differs" in (r.get("error") or "")), ("reject", True))
check("4. and nothing was written", os.path.exists(f"{R}/ca2.md"), False)
print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
