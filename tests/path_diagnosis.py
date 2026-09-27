"""A refused path is described by its actual cause, not by one fixed message
(earlier versions reported a missing directory as 'escapes workspace or crosses
a symlink'). Every case is still refused. Predictions first."""
import os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; W = f"{D}/workspace"; R = f"{W}/reports"
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
A = f"{D}/diag.jsonl"
for f in (A, A + ".key", A + ".pub.json", A + ".lock"):
    if os.path.exists(f): os.remove(f)
b = B.Broker(cfg, KernelClient(), B.AuditLog(A), None, None, B.Keys.generate())
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")
def write(path):
    r = b.handle({"tool": "write_file", "args": [["path", path], ["content", "x"]]})
    return r.get("effect"), r.get("error")

os.symlink(W, f"{R}/link")                       # a directory symlink, pointing inside
open(f"{R}/afile", "w").write("not a directory")
os.symlink(f"{W}/notes.txt", f"{R}/l.md")        # the target itself a symlink

check("a missing directory", write("/workspace/reports/new/x.md"),
      ("failed", "a directory on the path does not exist: new"))
check("a symlinked directory", write("/workspace/reports/link/x.md"),
      ("failed", "the path crosses a symlink: link"))
check("a file where a directory should be", write("/workspace/reports/afile/x.md"),
      ("failed", "a component of the path is not a directory: afile"))
check("the target is a symlink", write("/workspace/reports/l.md"),
      ("failed", "the target is a symlink"))
check("observation names the cause too", B._observe(cfg, "/workspace/reports/new/x.md"),
      ("unavailable", "a directory on the path does not exist: new"))
check("nothing written through the symlinks",
      (os.path.exists(f"{W}/x.md"), open(f"{W}/notes.txt").read() == "hello from notes\n"), (False, True))

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
