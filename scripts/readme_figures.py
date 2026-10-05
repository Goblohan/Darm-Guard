#!/usr/bin/env python3
"""The README's evidence table, generated from the repository: package and
kernel version from their own files, claims and bridges from the assurance
graph, effect sites from the effect-surface gate, mutations from the mutation
gate's own table, gate steps from the workflow. --write fills the block between
the figures markers; --check fails if the README's block differs.
Usage: scripts/readme_figures.py --write | --check"""
import ast, json, re, subprocess, sys

def run(*c):
    return subprocess.run([sys.executable, *c], capture_output=True, text=True).stdout

version = re.search(r'^version = "([^"]+)"', open("pyproject.toml").read(), re.M)[1]
kernel = re.search(r'^KERNEL_VERSION = "([^"]+)"', open("darm_guard/install.py").read(), re.M)[1]
claims = len(json.load(open("assurance/claims.json"))["claims"])
guarantees = sum(1 for l in open("THREAT_MODEL.md") if l.startswith("|") and "claim:" in l)
bridges = (run("scripts/check_bridges.py").splitlines() or ["?"])[0].replace("bridges: ", "")
sites = (run("scripts/check_effect_sites.py").strip().splitlines() or ["?"])[-1].replace("effect sites: ", "")
sites = sites.split(";")[0]
mutations = next(len(n.value.keys) for n in ast.walk(ast.parse(open("scripts/mutation_gate.py").read()))
                 if isinstance(n, ast.Assign) and any(getattr(t, "id", None) == "MUTATIONS" for t in n.targets))
steps = len(re.findall(r"^\s*- name:", open(".github/workflows/probes.yml").read(), re.M))

block = "\n".join([
    "<!-- figures:start -->",
    "| | |",
    "| --- | --- |",
    f"| Package / kernel | {version} / {kernel} |",
    f"| Claims, each citing its theorems and tests | {claims} |",
    f"| Threat-model guarantees, each backed by a claim | {guarantees} |",
    f"| Bridges from model to code | {bridges} |",
    f"| Effect sites | {sites} |",
    f"| Mutations, each caught by a test | {mutations} |",
    f"| Gate steps run on every push | {steps} |",
    "<!-- figures:end -->"])

readme = open("README.md").read()
m = re.search(r"<!-- figures:start -->.*?<!-- figures:end -->", readme, re.S)
if not m:
    sys.exit("README has no figures block")
if "--write" in sys.argv:
    open("README.md", "w").write(readme[:m.start()] + block + readme[m.end():])
    print(block)
elif m.group(0) != block:
    print("README figures are out of date; run scripts/readme_figures.py --write")
    print(block)
    sys.exit(1)
else:
    print("README figures match the repository")
