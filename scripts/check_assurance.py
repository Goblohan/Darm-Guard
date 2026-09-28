#!/usr/bin/env python3
"""Check the assurance graph (assurance/claims.json). Every claim must cite:
Lean theorems that exist in darm-monitor at the pinned commit (or say
"modelled": false), runtime tests that exist and run in the gate, implementation
functions that exist, and a stated limitation. Fails on any gap, so the graph
cannot go stale. Usage:
  scripts/check_assurance.py [--monitor PATH] [--claims FILE]
Without --monitor, darm-monitor is cloned from the recorded repository."""
import argparse, json, os, re, subprocess, sys, tempfile

repo = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ap = argparse.ArgumentParser()
ap.add_argument("--monitor"); ap.add_argument("--claims", default=os.path.join(repo, "assurance", "claims.json"))
a = ap.parse_args()
doc = json.load(open(a.claims))
mon, commit = a.monitor, doc["darm_monitor"]["commit"]
if not mon:
    mon = tempfile.mkdtemp(prefix="darm-monitor-")
    subprocess.run(["git", "clone", "--quiet", doc["darm_monitor"]["repo"], mon], check=True)
gate = open(os.path.join(repo, ".github", "workflows", "probes.yml")).read()
modules = {}
def module_text(m):
    if m not in modules:
        r = subprocess.run(["git", "-C", mon, "show", f"{commit}:GRBS/{m}.lean"], capture_output=True, text=True)
        modules[m] = r.stdout if r.returncode == 0 else None
    return modules[m]
failures = 0
for c in doc["claims"]:
    problems = []
    if not c.get("lean") and c.get("modelled") is not False:
        problems.append("no Lean theorem cited, and not marked \"modelled\": false")
    for m in c.get("lean", []):
        text = module_text(m["module"])
        if text is None:
            problems.append(f"module {m['module']} not found at {commit}")
            continue
        for th in m["theorems"]:
            if not re.search(rf"^\s*theorem\s+{re.escape(th)}\b", text, re.M):
                problems.append(f"theorem {m['module']}.{th} not found at {commit}")
    for t in c.get("tests", []):
        if not os.path.exists(os.path.join(repo, t)):
            problems.append(f"test {t} does not exist")
        elif os.path.basename(t) not in gate:
            problems.append(f"test {t} is not run by the gate")
    for impl in c.get("implementation", []):
        path, _, fn = impl.partition(":")
        full = os.path.join(repo, path)
        if not os.path.exists(full):
            problems.append(f"implementation {path} does not exist")
        elif fn and not re.search(rf"^\s*(def|class)\s+{re.escape(fn)}\b", open(full).read(), re.M):
            problems.append(f"implementation {path}:{fn} not found")
    for field in ("claim", "correspondence", "counterexample", "limitation"):
        if not c.get(field, "").strip():
            problems.append(f"missing {field}")
    failures += bool(problems)
    print(("ok      " if not problems else "FAILED  ") + c["id"])
    for p in problems:
        print("          " + p)
n = len(doc["claims"])
print(f"\n{n - failures}/{n} claims fully cited (darm-monitor at {commit})")
sys.exit(1 if failures else 0)
