#!/usr/bin/env python3
"""Figures for Darm-Guard, generated from its own checkers, with the commit.
Usage: scripts/stats.py [--monitor=PATH] [--json]"""
import ast, glob, json, os, re, subprocess, sys
MON = next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--monitor=")),
           os.path.expanduser("~/darm-monitor"))
def run(*c):
    return subprocess.run([sys.executable, *c], capture_output=True, text=True).stdout
def find(pat, text, default="?"):
    m = re.search(pat, text, re.M)
    return m.groups() if m else (default,)
assur = run("scripts/check_assurance.py", "--monitor", MON)
mut = next(len(n.value.keys) for n in ast.walk(ast.parse(open("scripts/mutation_gate.py").read()))
           if isinstance(n, ast.Assign) and any(getattr(t, "id", None) == "MUTATIONS" for t in n.targets))
s = {"commit": subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip(),
     "version": find(r'^version = "([^"]+)"', open("pyproject.toml").read())[0],
     "kernel": find(r'^KERNEL_VERSION = "([^"]+)"', open("darm_guard/install.py").read())[0],
     "claims fully cited": "/".join(find(r"(\d+)/(\d+) claims fully cited", assur)),
     "pinned darm-monitor": find(r"claims fully cited \(darm-monitor at (\w+)\)", assur)[0],
     "theorem and runtime evidence": "/".join(find(r"assurance completeness: (\d+)/(\d+)", assur)),
     "guarantees backed": "/".join(find(r"guarantees backed:\s+(\d+)/(\d+)", assur)),
     "bridges": (run("scripts/check_bridges.py").splitlines() or ["?"])[0].replace("bridges: ", ""),
     "effect sites": (run("scripts/check_effect_sites.py").strip().splitlines() or ["?"])[-1].replace("effect sites: ", ""),
     "mutations": mut,
     "test files": len(glob.glob("tests/*.py")),
     "named gate steps (probes.yml)": len(re.findall(r"^\s*- name:", open(".github/workflows/probes.yml").read(), re.M))}
if "--json" in sys.argv:
    print(json.dumps(s, indent=1)); sys.exit(0)
for k, v in s.items():
    print(f"{k:32} {v}")
