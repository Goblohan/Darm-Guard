"""One refusal per dimension, each built so that ONLY that dimension can refuse,
each asserting the exact failure class. Written after the mutation gate showed
that disabling the credential check or deny-by-default passed the whole gate:
other checks refused those cases for other reasons. Predictions first."""
import dataclasses, os, sys
from datetime import datetime, timedelta
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"
CFG = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")
def broker(name, cfg):
    A = f"{D}/dim_{name}.jsonl"
    for f in (A, A + ".key", A + ".pub.json", A + ".lock"):
        if os.path.exists(f): os.remove(f)
    return B.Broker(cfg, KernelClient(), B.AuditLog(A), None, None, B.Keys.generate())
def refusal(b, tool, args):
    r = b.handle({"tool": tool, "args": [[k, v] for k, v in args]})
    return r.get("decision"), r.get("failure")

report = [("path", "/workspace/reports/dim.md"), ("content", "x")]
no_write = dataclasses.replace(CFG, credential_tools=tuple(t for t in CFG.credential_tools if t != "write_file"))
expired = dataclasses.replace(CFG, issued_at=datetime.now() - timedelta(hours=2), ttl_seconds=3600)

check("control: the report write is admitted", refusal(broker("ok", CFG), "write_file", report)[0], "admit")
check("authority: tool in the policy, not in the credential",
      refusal(broker("auth", no_write), "write_file", report), ("reject", "authority"))
check("temporal: the credential has expired", refusal(broker("temp", expired), "write_file", report),
      ("reject", "temporal"))
check("observation: a tool the policy does not list",
      refusal(broker("obs", CFG), "shell_exec", [("path", "/workspace/notes.txt")]), ("reject", "observation"))
check("semantic: an unruled argument with a trusted (registered) value",
      refusal(broker("sem", CFG), "write_file", report + [("mode", "/workspace/notes.txt")]), ("reject", "semantic"))
check("provenance: an unregistered path",
      refusal(broker("prov", CFG), "write_file", [("path", "/workspace/other.txt"), ("content", "x")]),
      ("reject", "provenance"))

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
