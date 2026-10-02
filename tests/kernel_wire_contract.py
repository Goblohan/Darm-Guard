"""K5's one Python-side assumption, checked exhaustively: KernelClient.decide
admits exactly when pyAdmits does (the reply is an object whose "decision" is
exactly "admit"), and the real kernel's replies are exactly what decisionJson4
renders (darm-monitor K5WireContract). Predictions first."""
import json, os, stat, sys, tempfile
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
from darm_guard.kernel import KernelClient, KernelGuard, KernelPolicy, ToolRule, ArgRule

FAILURES = ["temporal", "observation", "authority", "semantic", "provenance"]
tmp = tempfile.mkdtemp(prefix="wire-")


def stand_in(reply, mode="print"):
    """A stand-in kernel that answers every request with one fixed reply."""
    p = os.path.join(tmp, f"k{len(os.listdir(tmp))}")
    body = {"print": f"    sys.stdout.write({reply!r} + chr(10)); sys.stdout.flush()",
            "silent": "    time.sleep(5)",
            "exit": "    sys.exit(0)"}[mode]
    open(p, "w").write(f"#!/usr/bin/env python3\nimport sys, time\nfor _ in sys.stdin:\n{body}\n")
    os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC)
    return p


def admits(reply, mode="print"):
    c = KernelClient(path=stand_in(reply, mode), timeout=1.0)
    try:
        return bool(c.decide({"probe": True}))
    except Exception as e:
        return f"raised {type(e).__name__}"
    finally:
        c.close()


cases = [('{"decision":"admit"}', True),
         ('{"decision":"admit","failure":"authority"}', True)]
cases += [(json.dumps({"decision": "reject", "failure": f}, separators=(",", ":")), False)
          for f in FAILURES]
cases += [('{"decision":"reject","error":"cannot parse"}', False),
          ('{"decision":"Admit"}', False), ('{"decision":"admit "}', False),
          ('{"decision":true}', False), ('{"failure":"admit"}', False), ('{}', False),
          ('["decision","admit"]', False), ('"admit"', False), ('1', False),
          ('not json', False)]
results = []


def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")


bad = [(r, got) for r, want in cases for got in [admits(r)] if got != want]
check(f"1. every reply class decoded as pyAdmits does ({len(cases)} classes)", bad, [])
check("2. a kernel that stays silent past the timeout: rejected", admits("", "silent"), False)
check("3. a kernel that exits: rejected", admits("", "exit"), False)

g = KernelGuard(KernelPolicy((ToolRule("t", (ArgRule("k", ("v",)),)),)), ["t"], "authoritative")
rendered = {'{"decision":"admit"}'} | {'{"decision":"reject","failure":"%s"}' % f for f in FAILURES}
a, r = g.check("t", {"k": "v"}), g.check("t", {"k": "w"})
check("4. the real kernel's replies are exactly what decisionJson4 renders",
      (bool(a), a.raw in rendered, bool(r), r.raw in rendered), (True, True, False, True))
g.close()

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
