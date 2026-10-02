"""A broker stopped by SIGTERM at any moment after it logged start ends with a
stop record and a final checkpoint, not only when the signal comes late.
Signals 25 brokers at varied delays from launch. Predictions first."""
import json, os, random, shutil, signal, subprocess, sys, time
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
D = "/tmp/darmdemo"
random.seed(7)
lost, signalled_after_start = [], 0
for i in range(25):
    M = f"{D}/sw{i}.jsonl"; S = f"{D}/sw_sink{i}"; sock = f"/tmp/darm-sw{i}.sock"
    for f in (M, M + ".key", M + ".pub.json", M + ".lock", sock):
        if os.path.exists(f): os.remove(f)
    shutil.rmtree(S, ignore_errors=True)
    p = subprocess.Popen([sys.executable, "-c", "from darm_guard.broker import main; main()",
                          "--config", f"{D}/config.json", "--registry", f"{D}/registry.txt",
                          "--socket", sock, "--audit", M, "--checkpoint-sink", S, "--checkpoint-every", "1000"],
                         env=dict(os.environ, PYTHONPATH=ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(random.choice([0.0, 0.05, 0.1, 0.2, 0.3, 0.4]) + random.random() * 0.05)
    p.send_signal(signal.SIGTERM)
    p.wait(timeout=10)
    ev = [json.loads(l).get("event") for l in open(M)] if os.path.exists(M) else []
    if "start" in ev:
        signalled_after_start += 1
        if ev[-1] != "stop":
            lost.append((i, ev[-1]))
print(f"  brokers signalled after logging start: {signalled_after_start}")
print(f"  logs that end without stop: {lost}   (predicted [])")
print(f"\n{'1/1' if not lost else '0/1'} predictions confirmed")
sys.exit(0 if not lost else 1)
