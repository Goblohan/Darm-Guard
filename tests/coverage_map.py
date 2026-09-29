"""The coverage map, on gates with known answers: the kernel covers every
dimension and admits an untrusted payload; allow_all covers nothing. And every
case passes the kernel's self-check (refused in exactly its own dimension).
Predictions first."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from darm_guard.coverage import coverage, kernel_adapter
from darm_guard.verify import allow_all

results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")

k = coverage(kernel_adapter)
check("every case passes the kernel self-check", all(r["kernel"] == "ok" for r in k), True)
check("the kernel covers every refusal dimension",
      [r["gate"] for r in k if r["expected"] not in ("admit",)], ["covers"] * 6)
check("the kernel admits the control and the untrusted payload",
      [r["gate"] for r in k if r["expected"] == "admit"], ["admits", "argument-aware (admits)"])
a = coverage(allow_all)
check("allow_all misses every refusal dimension",
      [r["gate"] for r in a if r["expected"] != "admit"], ["MISSES"] * 6)

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
