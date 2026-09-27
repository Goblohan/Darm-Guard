#!/usr/bin/env python3
"""Run the gate (.github/workflows/probes.yml) exactly as CI does: from a clean
clone of the committed tree, every step in order, stopping at the first
failure. Usage (from the repository): scripts/ci_local.py
Uncommitted changes are NOT included; commit first, as CI would see it."""
import os, re, shutil, subprocess, sys
repo = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ci = "/tmp/darm-ci-local"
shutil.rmtree(ci, ignore_errors=True)
subprocess.run(["git", "clone", "-q", repo, ci], check=True)
os.chdir(ci)
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
for name, cmd in steps:
    r = subprocess.run(["bash", "-c", cmd.replace("python ", "python3 ")], capture_output=True, text=True)
    print(("ok      " if r.returncode == 0 else "FAILED  ") + name)
    if r.returncode:
        print((r.stdout + r.stderr)[-1500:]); sys.exit(1)
print(f"all {len(steps)} steps passed")
