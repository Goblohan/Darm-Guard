"""EVALUATING.md stays true to the repository: every file it links to or names exists,
every darm-guard subcommand it uses exists, and every console command it runs is one
this package installs. Predictions first."""
import os, re, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
text = open(os.path.join(ROOT, "EVALUATING.md")).read()
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")

links = [l for l in re.findall(r"\]\(([^)#]+)\)", text) if not l.startswith("http")]
missing = sorted({l for l in links if not os.path.exists(os.path.join(ROOT, l))})
check(f"every relative link exists ({len(set(links))} linked)", missing, [])
named = set(re.findall(r"\b((?:scripts|tests|deploy|assurance|darm_guard)/[\w./-]+\.\w+)", text))
missing = sorted(n for n in named if not os.path.exists(os.path.join(ROOT, n)))
check(f"every file it names exists ({len(named)} named)", missing, [])
cli = open(os.path.join(ROOT, "darm_guard", "cli.py")).read()
subs = set(re.findall(r'add_parser\("([\w-]+)"', cli))
used = set(re.findall(r"darm-guard (\w[\w-]*)", text)) - {"demo"} | ({"demo"} if "darm-guard demo" in text else set())
check("every darm-guard subcommand it uses exists", sorted(used - subs), [])
scripts = set(re.findall(r'^([\w-]+) = "', open(os.path.join(ROOT, "pyproject.toml")).read(), re.M))
cmds = set(re.findall(r"^\s{4}(darm-[\w-]+)", text, re.M))
check("every console command it runs is installed by this package", sorted(cmds - scripts), [])
print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
