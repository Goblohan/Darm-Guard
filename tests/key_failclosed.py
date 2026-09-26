"""The broker fails closed without a signing key, and a rename whose signing
fails is rolled back. Found by the 0.12.0 release check. Predictions first."""
import os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; R = f"{D}/workspace/reports"
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")
def fresh(path):
    for f in (path, path + ".key", path + ".pub.json", path + ".legacy.key", path + ".lock"):
        if os.path.exists(f):
            os.remove(f)

A = f"{D}/failclosed.jsonl"; fresh(A)
B.Keys.generate().ring.save(A + ".key", A + ".pub.json")
os.remove(A + ".key")                                # the private key is lost; the public ring survives

print("1. loading a public ring with no private key")
try:
    B._load_or_create_keys(A); msg = None
except RuntimeError as e:
    msg = str(e)
check("refuses, naming the missing key", msg is not None and "private signing key" in msg, True)

print("2. serve in that state")
try:
    B.serve(cfg, "/tmp/darm-failclosed.sock", A); started = True
except RuntimeError:
    started = False
check("refuses to start", started, False)
fresh(A)
try:
    srv = B.serve(cfg, "/tmp/darm-failclosed.sock", A); srv.server_close(); restarted = True
except Exception as e:
    restarted = f"{type(e).__name__}: {e}"
check("releases its lock: a corrected start succeeds", restarted, True)

print("3. building a broker with a verify-only ring")
try:
    B.Broker(cfg, KernelClient(), B.AuditLog(f"{D}/failclosed2.jsonl"), None, None,
             B.Keys.generate().public_only()); built = True
except ValueError:
    built = False
check("refused", built, False)

print("4. a rename whose signing fails")
keys = B.Keys.generate()
b = B.Broker(cfg, KernelClient(), B.AuditLog(f"{D}/failclosed3.jsonl"), None, None, keys)
w = b.handle({"tool": "write_file", "args": [["path", "/workspace/reports/fc1.md"], ["content", "stay"]]})
orig = B._attestation
def broken(*a, **kw):
    raise PermissionError("signing unavailable")
B._attestation = broken
try:
    r = b.handle({"tool": "rename_file", "args": [["path", "/workspace/reports/fc1.md"],
                                                  ["destination", "/workspace/reports/fc2.md"]]})
finally:
    B._attestation = orig
check("rename failed", r.get("effect"), "failed")
check("file back at the source, destination absent",
      (open(f"{R}/fc1.md").read(), os.path.exists(f"{R}/fc2.md")), ("stay", False))
fs = [x for x in B.verify_world(cfg, f"{D}/failclosed3.jsonl", keys)["findings"] if "fc1" in x["target"]]
check("the source verifies clean (original attestation intact)", fs, [])
check("no private file left", [n for n in os.listdir(R) if ".darm-tmp-" in n], [])

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
