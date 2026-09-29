#!/usr/bin/env python3
"""Run the gate (.github/workflows/probes.yml) as CI does: from a clean clone of
the committed tree, every step in order, stopping at the first failure.
Two things CI's disposable runners do implicitly are done here explicitly:
installs go into a private virtual environment (never into yours), and brokers
a step leaves running in the background are stopped before and after.
Usage: scripts/ci_local.py   (commit first: uncommitted changes are not included)"""
import os, re, shutil, subprocess, sys
repo = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ci = "/tmp/darm-ci-local"

def stop_brokers():
    subprocess.run(["pkill", "-f", "darm_guard.broker import main|darm-broker"])

stop_brokers()
shutil.rmtree(ci, ignore_errors=True)
subprocess.run(["git", "clone", "-q", repo, ci], check=True)
os.chdir(ci)
venv = os.path.join(ci, ".venv")
if subprocess.run([sys.executable, "-m", "venv", venv], capture_output=True).returncode != 0:
    shutil.rmtree(venv, ignore_errors=True)
    subprocess.run([sys.executable, "-m", "virtualenv", "--quiet", venv], check=True)
env = dict(os.environ, VIRTUAL_ENV=venv, PATH=os.path.join(venv, "bin") + os.pathsep + os.environ["PATH"])
env.pop("PYTHONPATH", None)

lines = open(".github/workflows/probes.yml").read().split("\n")
steps, i = [], 0
while i < len(lines):
    m = re.match(r"\s*- name: (.*)", lines[i])
    if not m:
        i += 1; continue
    name, cmd, j = m.group(1), None, i + 1
    while j < len(lines) and not re.match(r"\s*- name:", lines[j]):
        if re.match(r"\s*run: \|\s*$", lines[j]):
            body, ind, k = [], None, j + 1
            while k < len(lines):
                if lines[k].strip() == "":
                    body.append(""); k += 1; continue
                cur = re.match(r"(\s*)", lines[k]).group(1)
                if ind is None:
                    ind = cur
                if not lines[k].startswith(ind):
                    break
                body.append(lines[k][len(ind):]); k += 1
            cmd = "\n".join(body)
        else:
            r1 = re.match(r"\s*run: (.+)$", lines[j])
            if r1:
                cmd = r1.group(1)
        j += 1
    if cmd:
        steps.append((name, cmd))
    i = j
LOG = "/tmp/darm-ci-local.log"
log = open(LOG, "w")
for name, cmd in steps:
    r = subprocess.run(["bash", "-c", cmd.replace("python ", "python3 ")],
                       capture_output=True, text=True, env=env)
    print(("ok      " if r.returncode == 0 else "FAILED  ") + name)
    log.write(f"=== {name} (exit {r.returncode}) ===\n{r.stdout}{r.stderr}\n"); log.flush()
    if r.returncode:
        print((r.stdout + r.stderr)[-1500:]); print(f"full output of every step: {LOG}")
        stop_brokers(); sys.exit(1)
stop_brokers()
print(f"all {len(steps)} steps passed")
