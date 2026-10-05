#!/usr/bin/env python3
"""Every workflow file is valid YAML. GitHub rejects an invalid workflow without running
any of its steps, so a gate that only runs the steps cannot see the error: this checks
the files themselves. With PyYAML installed, each file is parsed; without it, each line
is checked for the commonest mistake, an unquoted value containing ': ' (block scalars,
such as a run: | script, are skipped). Usage: scripts/check_workflows.py"""
import glob, re, sys

files = sorted(glob.glob(".github/workflows/*.yml") + glob.glob(".github/workflows/*.yaml"))
problems = []
try:
    import yaml
    for f in files:
        try:
            yaml.safe_load(open(f))
        except yaml.YAMLError as e:
            problems.append(f"{f}: {' '.join(str(e).split())}")
    how = "parsed with PyYAML"
except ImportError:
    how = "checked line by line (PyYAML not installed)"
    KEY = re.compile(r"^(\s*)(?:-\s+)?([\w.-]+):\s+(.*)$")
    for f in files:
        block = None
        for n, line in enumerate(open(f), 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            indent = len(line) - len(line.lstrip())
            if block is not None:
                if indent > block:
                    continue
                block = None
            m = KEY.match(line.rstrip("\n"))
            if not m:
                continue
            value = m.group(3).strip()
            if value in ("|", ">", "|-", ">-", "|+", ">+"):
                block = len(m.group(1)); continue
            if value[:1] in ("'", '"', "{", "[", "&", "*", "!"):
                continue
            if ": " in value.split(" #")[0]:
                problems.append(f"{f}:{n}: unquoted value contains ': ', which YAML reads as a new key: "
                                f"{line.strip()[:80]}")
for p in problems:
    print("INVALID", p)
print(f"{len(files)} workflow files {how}: {len(problems)} problems")
sys.exit(1 if problems else 0)
