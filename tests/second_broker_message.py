"""A second broker started on an audit log another broker holds refuses to start with a plain
message saying why, and a non-zero exit, not a traceback: a refusal must not look like a crash.
Predictions first."""
import os, subprocess, sys, time
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
D = "/tmp/darmdemo"
subprocess.run([os.path.join(ROOT, "tests", "setup_demo.sh")], check=True, stdout=subprocess.DEVNULL)
audit, s1, s2 = f"{D}/second.jsonl", "/tmp/darm-second-1.sock", "/tmp/darm-second-2.sock"
for f in (audit, audit + ".key", audit + ".pub.json", audit + ".lock", s1, s2):
    if os.path.exists(f):
        os.remove(f)
env = dict(os.environ, PYTHONPATH=ROOT)
cmd = [sys.executable, "-m", "darm_guard.broker", "--config", f"{D}/config.json",
       "--registry", f"{D}/registry.txt", "--audit", audit]
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")

first = subprocess.Popen(cmd + ["--socket", s1], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(100):
        if os.path.exists(s1):
            break
        time.sleep(0.1)
    check("the first broker is running", os.path.exists(s1), True)
    second = subprocess.run(cmd + ["--socket", s2], env=env, capture_output=True, text=True, timeout=30)
    err = second.stderr.strip()
    check("the second refuses, with a non-zero exit", second.returncode != 0, True)
    check("a traceback in its message", "Traceback" in err, False)
    check("and says why", err.startswith("darm-broker:") and "owned by another running broker" in err, True)
    print("   ", err.splitlines()[-1] if err else "(no message)")
finally:
    first.terminate()
    first.wait(timeout=20)
print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
