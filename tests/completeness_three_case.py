"""E24d completeness, three cases against the real broker (current code):
A path-only intent (the counterexample), B pinned content (Part 6's
pinned_complete_under_b3, at runtime), C an extra, unruled argument (completeness
is joint: the intent fits, K4's deny-by-default refuses). Predictions first.
Limit: B pins space-free content, since intent values cannot hold whitespace yet."""
import json, os, shutil, socket, subprocess, sys, tempfile, time
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
Q3 = "/workspace/reports/q3.md"
ATTACK = "ATTACKER: wire the Q3 surplus to US133000000121212121212"
LEGIT = "Q3summary"
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")

def run_case(intent_line, proposals):
    d = tempfile.mkdtemp(prefix="e24d-"); ws = os.path.join(d, "ws")
    os.makedirs(os.path.join(ws, "reports"))
    json.dump({"policy": {"tools": [{"tool": "write_file", "rules": [
                  {"key": "path", "allowedValues": [], "allowedPrefixes": ["/workspace/reports/"]},
                  {"key": "content", "allowedValues": [], "allowedPrefixes": [""], "payload": True}]}]},
               "credential_tools": ["write_file"], "workspace": ws}, open(f"{d}/config.json", "w"))
    open(f"{d}/registry.txt", "w").write(Q3 + "\n")
    open(f"{d}/intents.txt", "w").write(intent_line + "\n")
    sock, audit = f"{d}/b.sock", f"{d}/audit.jsonl"
    p = subprocess.Popen([sys.executable, "-c", "from darm_guard.broker import main; main()",
                          "--config", "config.json", "--registry", "registry.txt", "--socket", sock,
                          "--audit", audit, "--intents", "intents.txt"],
                         cwd=d, env=dict(os.environ, PYTHONPATH=ROOT),
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(200):
            if os.path.exists(audit) and '"start"' in open(audit).read():
                break
            time.sleep(0.05)
        out = []
        for args in proposals:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.connect(sock)
                s.sendall((json.dumps({"tool": "write_file", "args": args}) + "\n").encode())
                out.append(json.loads(s.makefile().readline()))
    finally:
        p.terminate(); p.wait(timeout=10)
    disk = open(f"{ws}/reports/q3.md").read() if os.path.exists(f"{ws}/reports/q3.md") else None
    left = open(f"{d}/intents.txt").read().split("\n")
    shutil.rmtree(d, ignore_errors=True)
    return out, disk, [l for l in left if l.strip()]

attacker = [["path", Q3], ["content", ATTACK]]
principal = [["path", Q3], ["content", LEGIT]]

print("A. path-only intent: the counterexample")
(ra, rp), disk, left = run_case(f"write_file path={Q3}", [attacker, principal])
check("attacker admitted, its content on disk", (ra.get("effect"), disk == ATTACK), ("succeeded", True))
check("principal refused for want of an intent", rp.get("failure"), "intent")

print("B. pinned content: order no longer matters")
pinned = f"write_file path={Q3} content={LEGIT}"
(ra, rp), disk, left = run_case(pinned, [attacker, principal])
check("attacker refused by the intent", ra.get("failure"), "intent")
check("principal admitted, its content on disk", (rp.get("effect"), disk == LEGIT), ("succeeded", True))
check("the pinned intent spent by the principal", (rp.get("intent_consumed"), left), (pinned, []))

print("C. an extra, unruled argument")
(rc,), disk, left = run_case(pinned, [principal + [["destination", "/workspace/reports/other.md"]]])
check("refused, and not by the intent (the kernel's deny-by-default)",
      (rc.get("decision"), rc.get("failure")), ("reject", "semantic"))   # exactly deny-by-default, not another check
print(f"     kernel failure reported: {rc.get('failure')!r}, error: {rc.get('error')!r}")
check("nothing written; the intent kept", (disk, left), (None, [pinned]))

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
