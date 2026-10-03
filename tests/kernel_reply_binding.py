"""A kernel reply answers only the request that carries its nonce
(darm-monitor K7, reply_names_its_request): a wrong or missing nonce is
refused, and a stale reply, a genuine admission for an earlier request read
as the answer to a later one, is refused and the kernel restarted.
Predictions first."""
import json, os, stat, sys, tempfile
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
from darm_guard.kernel import KernelClient

tmp = tempfile.mkdtemp(prefix="binding-")
def stand_in(body):
    p = os.path.join(tmp, f"k{len(os.listdir(tmp))}")
    open(p, "w").write("#!/usr/bin/env python3\nimport json, sys\nfirst = True\nfor _l in sys.stdin:\n"
                       "    n = json.loads(_l).get('nonce')\n" + body)
    os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC)
    return p
def admits(path, k=None):
    c = k or KernelClient(path=path, timeout=1.0)
    d = c.decide({"probe": True})
    if k is None:
        c.close()
    return bool(d)
out = "    print(json.dumps(r), flush=True)\n"
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")

check("1. a reply carrying this request's nonce: admitted",
      admits(stand_in("    r = {'decision': 'admit', 'nonce': n}\n" + out)), True)
check("2. a reply carrying another nonce: refused",
      admits(stand_in("    r = {'decision': 'admit', 'nonce': 'stale'}\n" + out)), False)
check("3. a reply carrying no nonce: refused",
      admits(stand_in("    r = {'decision': 'admit'}\n" + out)), False)
desync = stand_in("    r = {'decision': 'admit', 'nonce': n}\n" + out +
                  "    if first:\n        print(json.dumps(r), flush=True)\n        first = False\n")
k = KernelClient(path=desync, timeout=1.0)
seq = (admits(desync, k), admits(desync, k), admits(desync, k))
k.close()
check("4. out of step: a stale admission for the first request, read as the second's answer, is refused; "
      "the kernel restarts and the third is admitted", seq, (True, False, True))
print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
