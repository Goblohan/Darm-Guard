"""darm-guard audit and report, on the evidence of a real run: the demo's, kept. report must show
what the agent tried, refusals included, with paths and URLs but never content or credentials;
audit must hold on the chain, find the demo's edit made outside the broker, and catch a log whose
entry was changed. Predictions first."""
import os, re, shutil, subprocess, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
env = dict(os.environ, PYTHONPATH=ROOT)
cli = [sys.executable, "-m", "darm_guard.cli"]
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")

demo = subprocess.run(cli + ["demo", "--keep"], env=env, capture_output=True, text=True)
d = re.search(r"Kept for inspection: (\S+)", demo.stdout).group(1)
audit, cfg, reg = (os.path.join(d, f) for f in ("audit.jsonl", "config.json", "registry.txt"))
token = open(os.path.join(d, "api-token")).read().strip()
try:
    rep = subprocess.run(cli + ["report", "--audit", audit], env=env, capture_output=True, text=True).stdout
    check("report shows a refused write with its path and reason",
          bool(re.search(r"REFUSED\s+write_file\s+/workspace/reports/q4\.md .*\(intent\)", rep)), True)
    check("report shows a refused fetch with its URL", "/admin/keys" in rep and "/v1/status" in rep, True)
    check("report names the extra field a self-labelled proposal sent", "[sent extra fields: provenance]" in rep, True)
    log = open(audit).read()
    check("neither the log nor the report holds file content or the API token",
          ("Q3 numbers" in log, token in log, token in rep), (False, False, False))
    r = subprocess.run(cli + ["audit", "--audit", audit], env=env, capture_output=True, text=True)
    check("audit, chain only: it holds", (r.returncode, "hash chain: intact" in r.stdout), (0, True))
    r = subprocess.run(cli + ["audit", "--audit", audit, "--config", cfg, "--registry", reg],
                       env=env, capture_output=True, text=True)
    check("audit with the workspace: the demo's edit outside the broker is found",
          (r.returncode, bool(re.search(r"q3\.md: .*outside the broker", r.stdout))), (1, True))
    bad = audit + ".edited"
    lines = open(audit).read().splitlines()
    lines[3] = lines[3].replace('"ts": "', '"ts": "1', 1)      # every entry has a timestamp: change it
    open(bad, "w").write("\n".join(lines) + "\n")
    r = subprocess.run(cli + ["audit", "--audit", bad], env=env, capture_output=True, text=True)
    check("audit of a log with one entry changed: broken, and says where",
          (r.returncode, "entry 4" in r.stdout), (1, True))
finally:
    shutil.rmtree(d, ignore_errors=True)
print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
