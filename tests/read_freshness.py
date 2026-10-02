"""A read is attributed only if it is current: content and attestation that
were genuine once, restored after the broker replaced or deleted them, are
refused, because only the log binds freshness (darm-monitor B8p
replay_accepted_by_attestation_caught_by_log; E33's gate needs it).
Predictions first."""
import dataclasses, json, os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; R = f"{D}/workspace/reports"; L = "/workspace/reports/"
cfg = dataclasses.replace(B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt"),
                          read_requires_attestation=True)
A = f"{D}/freshness.jsonl"
for f in (A, A + ".key", A + ".pub.json", A + ".lock"):
    if os.path.exists(f): os.remove(f)
b = B.Broker(cfg, KernelClient(), B.AuditLog(A), None, None, B.Keys.generate())
results, responses = [], []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")
def call(tool, *args):
    r = b.handle({"tool": tool, "args": [list(a) for a in args]})
    responses.append(r)
    return r
def read(name):
    return call("read_file", ("path", L + name))
def save(name):
    return open(f"{R}/{name}").read(), os.getxattr(f"{R}/{name}", B.XATTR)
def restore(name, saved):
    with open(f"{R}/{name}", "w") as fh:
        fh.write(saved[0])
    os.setxattr(f"{R}/{name}", B.XATTR, saved[1])

w = call("write_file", ("path", L + "rf_fresh.md"), ("content", "current"))
r = read("rf_fresh.md")
check("1. a fresh write, read back: attributed to its request",
      ((r.get("read_attestation") or {}).get("attributed"), (r.get("read_attestation") or {}).get("rid") == w.get("request_id")),
      (True, True))

call("write_file", ("path", L + "rf_super.md"), ("content", "version one"))
v1 = save("rf_super.md")
call("write_file", ("path", L + "rf_super.md"), ("content", "version two"))
restore("rf_super.md", v1)
r = read("rf_super.md")
check("2. superseded content restored with its genuine attestation: refused",
      (r.get("failure"), "latest entry" in (r.get("error") or "")), ("attestation", True))

call("write_file", ("path", L + "rf_del.md"), ("content", "deleted later"))
saved = save("rf_del.md")
call("delete_file", ("path", L + "rf_del.md"))
restore("rf_del.md", saved)
r = read("rf_del.md")
check("3. content restored after the broker deleted it: refused",
      (r.get("failure"), "latest entry" in (r.get("error") or "")), ("attestation", True))

call("write_file", ("path", L + "rf_src.md"), ("content", "moved by the broker"))
m = call("rename_file", ("path", L + "rf_src.md"), ("destination", L + "rf_dst.md"))
r = read("rf_dst.md")
check("4. a renamed file, read at its destination: attributed to the rename",
      ((r.get("read_attestation") or {}).get("attributed"), (r.get("read_attestation") or {}).get("rid") == m.get("request_id")),
      (True, True))

flagged = {x["target"] for x in B.verify_world(cfg, A, b.key)["findings"]}
check("5. verify_world flags both restored paths (one reading of the log)",
      {L + "rf_super.md", L + "rf_del.md"} <= flagged, True)

def serializable(x):
    try:
        json.dumps(x); return True
    except TypeError:
        return False
check("6. every response is JSON, with no raw attestation bytes",
      all(serializable(x) and "_raw_attestation" not in x for x in responses), True)

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
