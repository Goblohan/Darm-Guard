"""The README's quick start, run exactly as the README states it: the shell
block under 'Quick start: the broker' (setup, then the broker, started in the
background), then the Python block as the agent. Passes only if the file the
example writes holds what the example wrote. If the README's example and the
package drift apart, this fails. Predictions first."""
import os, re, signal, subprocess, sys, time
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
readme = open(os.path.join(ROOT, "README.md")).read()
sec = readme.split("## Quick start: the broker", 1)[1].split("\n## ", 1)[0]
blocks, cur = [], []
for line in sec.split("\n"):           # indented code blocks, in order
    if line.startswith("    "):
        cur.append(line[4:])
    elif cur and line.strip():
        blocks.append(cur); cur = []
if cur:
    blocks.append(cur)
shell, python = blocks[0], blocks[1]
cmds = " ".join(shell).replace("\\ ", " ").split("\n")
cmds = re.split(r"(?<!\\)\n", "\n".join(shell).replace("\\\n", " "))
setup = [c for c in cmds if not c.strip().startswith("darm-broker")]
broker = [c for c in cmds if c.strip().startswith("darm-broker")]
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")
check("the README's quick start has a setup command, a broker command and a Python block",
      (len(setup) >= 1, len(broker) == 1, len(python) >= 2), (True, True, True))
sock = re.search(r"--socket\s+(\S+)", broker[0]).group(1)
if os.path.exists(sock):
    os.remove(sock)
for c in setup:
    subprocess.run(c, shell=True, cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
target = "/tmp/darmdemo/workspace/reports/q3.md"
if os.path.exists(target):
    os.remove(target)
proc = subprocess.Popen(broker[0], shell=True, cwd=ROOT, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, start_new_session=True)
try:
    for _ in range(100):
        if os.path.exists(sock):
            break
        time.sleep(0.1)
    exec("\n".join(python), {})
    check("the example's write landed: the file holds 'hello'",
          open(target).read() if os.path.exists(target) else None, "hello")
finally:
    os.killpg(proc.pid, signal.SIGTERM)
    proc.wait(timeout=20)
print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
