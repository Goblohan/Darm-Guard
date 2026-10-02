"""A broker stopped by SIGTERM at any moment after it logged start ends with a
stop record and a final checkpoint. Signals are aimed at the window: each
broker is watched until start appears, then signalled 0-10 ms later (a few
are signalled early, during set-up). The test fails if too few signals land
after start, so it cannot pass without exercising the window. Predictions first."""
import json, os, random, shutil, signal, subprocess, sys, time
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
D = "/tmp/darmdemo"
random.seed(7)
lost, after_start = [], 0

def events(M):
    try:
        return [json.loads(l).get("event") for l in open(M) if l.strip()]
    except (OSError, ValueError):
        return []

for i in range(25):
    M = f"{D}/sw{i}.jsonl"; S = f"{D}/sw_sink{i}"; sock = f"/tmp/darm-sw{i}.sock"
    for f in (M, M + ".key", M + ".pub.json", M + ".lock", sock):
        if os.path.exists(f): os.remove(f)
    shutil.rmtree(S, ignore_errors=True)
    p = subprocess.Popen([sys.executable, "-c", "from darm_guard.broker import main; main()",
                          "--config", f"{D}/config.json", "--registry", f"{D}/registry.txt",
                          "--socket", sock, "--audit", M, "--checkpoint-sink", S, "--checkpoint-every", "1000"],
                         env=dict(os.environ, PYTHONPATH=ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if i % 5 == 0:
        time.sleep(random.random() * 0.2)                    # early: during set-up
    else:
        deadline = time.time() + 20
        while time.time() < deadline and "start" not in events(M):
            time.sleep(0.001)
        time.sleep(random.choice([0.0, 0.0005, 0.001, 0.002, 0.005, 0.01]))   # the window
    p.send_signal(signal.SIGTERM)
    p.wait(timeout=10)
    ev = events(M)
    if "start" in ev:
        after_start += 1
        if ev[-1] != "stop":
            lost.append((i, ev[-1]))

results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")
check("1. enough signals landed after start to exercise the window (at least 15 of 25)", after_start >= 15, True)
check("2. every log with a start record ends with stop", lost, [])

# deterministic: the broker pauses 0.5 s between start and the try, and the
# signal comes 0.1 s into the pause, so it always lands in the window
M = f"{D}/sw_det.jsonl"; S = f"{D}/sw_det_sink"; sock = "/tmp/darm-swdet.sock"
for f in (M, M + ".key", M + ".pub.json", M + ".lock", sock):
    if os.path.exists(f): os.remove(f)
shutil.rmtree(S, ignore_errors=True)
p = subprocess.Popen([sys.executable, "-c", "from darm_guard.broker import main; main()",
                      "--config", f"{D}/config.json", "--registry", f"{D}/registry.txt",
                      "--socket", sock, "--audit", M, "--checkpoint-sink", S, "--checkpoint-every", "1000"],
                     env=dict(os.environ, PYTHONPATH=ROOT, DARM_TEST_PAUSE_AFTER_START="0.5"),
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
deadline = time.time() + 20
while time.time() < deadline and "start" not in events(M):
    time.sleep(0.001)
time.sleep(0.1)
p.send_signal(signal.SIGTERM)
p.wait(timeout=10)
check("3. a signal inside a widened window after start still ends in stop", events(M)[-1:], ["stop"])
print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
