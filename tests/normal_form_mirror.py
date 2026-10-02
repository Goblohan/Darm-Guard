"""The broker's normal form is K6's normalPath, checked exhaustively against the
real kernel: every string up to length 6 over '/', '.', 'a' (1093 strings) is
sent as a one-argument proposal; the kernel answers 'malformed proposal'
exactly when normalPath fails, and the broker's port must agree on all of them.
Predictions first."""
import itertools, os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

k = KernelClient()
strings = ["".join(t) for n in range(7) for t in itertools.product("/.a", repeat=n)]
disagree, kernel_normal = [], 0
for s in strings:
    d = k.decide({"policy": {"tools": []}, "credential": {"tools": [], "expired": False},
                  "registry": {"values": [], "prefixes": []},
                  "proposal": {"tool": "t", "args": [["path", s]]}})
    kn = d.error != "malformed proposal"
    kernel_normal += kn
    if kn != B.path_in_normal_form(s):
        disagree.append(s)
k.close()
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")
check(f"1. strings checked", len(strings), 1093)
check("2. the kernel judged both kinds (not vacuous)", 0 < kernel_normal < len(strings), True)
check("3. strings where the broker and the kernel disagree", disagree[:10], [])
print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
