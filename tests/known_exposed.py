"""Findings whose current verdict is recorded, not hidden. Each probe runs
against the real broker (current code) and its verdict is compared with the
expectation table. Any flip, in either direction, fails the gate with a message,
so a fix (or a regression) is recorded when it happens, together with the
threat model.

P15b  redemption race, path-only intent, content unknown: EXPOSED by theorem
      (E24d no_exact_rule); closable only by pinning content or by lineage.
P16   an admitted write whose effect fails still spends the intent: EXPOSED
      until three-state consumption (E24d no_burn / unknown_holds / success_spends)."""
import json, os, shutil, socket, subprocess, sys, tempfile, time
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
EXPECT = {"P15b": "EXPOSED", "P16": "HOLD"}   # P16 closed by three-state consumption

def run(intent_line, steps):
    d = tempfile.mkdtemp(prefix="known-"); ws = os.path.join(d, "ws")
    os.makedirs(os.path.join(ws, "reports"))
    json.dump({"policy": {"tools": [{"tool": "write_file", "rules": [
                  {"key": "path", "allowedValues": [], "allowedPrefixes": ["/workspace/reports/"]},
                  {"key": "content", "allowedValues": [], "allowedPrefixes": [""], "payload": True}]}]},
               "credential_tools": ["write_file"], "workspace": ws}, open(f"{d}/config.json", "w"))
    open(f"{d}/registry.txt", "w").write("/workspace/reports/q3.md\n/workspace/reports/new/x.md\n")
    open(f"{d}/intents.txt", "w").write(intent_line + "\n")
    sock, audit = f"{d}/b.sock", f"{d}/audit.jsonl"
    p = subprocess.Popen([sys.executable, "-c", "from darm_guard.broker import main; main()",
                          "--config", "config.json", "--registry", "registry.txt", "--socket", sock,
                          "--audit", audit, "--intents", "intents.txt"],
                         cwd=d, env=dict(os.environ, PYTHONPATH=ROOT),
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    out = []
    try:
        for _ in range(200):
            if os.path.exists(audit) and '"start"' in open(audit).read():
                break
            time.sleep(0.05)
        for step in steps:
            if callable(step):
                step(ws); continue
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.connect(sock)
                s.sendall((json.dumps({"tool": "write_file", "args": step}) + "\n").encode())
                out.append(json.loads(s.makefile().readline()))
    finally:
        p.terminate(); p.wait(timeout=10)
    shutil.rmtree(d, ignore_errors=True)
    return out

def p15b():
    q3 = "/workspace/reports/q3.md"
    atk, legit = run(f"write_file path={q3}",
                     [[["path", q3], ["content", "ATTACKER: wire funds"]], [["path", q3], ["content", "Q3 summary"]]])
    if atk.get("effect") == "succeeded" and legit.get("failure") == "intent":
        return "EXPOSED", "attacker's write redeemed the path-only intent; principal refused"
    if legit.get("effect") == "succeeded" and atk.get("effect") != "succeeded":
        return "HOLD", "principal's write redeemed it"
    return "INCONCLUSIVE", json.dumps([atk, legit])[:200]

def p16():
    x = "/workspace/reports/new/x.md"
    first, second = run(f"write_file path={x}",
                        [[["path", x], ["content", "one"]],
                         lambda ws: os.makedirs(os.path.join(ws, "reports", "new")),
                         [["path", x], ["content", "two"]]])
    if first.get("effect") == "failed" and first.get("intent_consumed") and second.get("failure") == "intent":
        return "EXPOSED", f"failed effect spent the intent (first error: {first.get('error')!r})"
    if first.get("effect") == "failed" and second.get("effect") == "succeeded":
        return "HOLD", "the failed effect returned the intent; the retry succeeded"
    return "INCONCLUSIVE", json.dumps([first, second])[:200]

flips = 0
for name, probe in (("P15b", p15b), ("P16", p16)):
    verdict, why = probe()
    ok = verdict == EXPECT[name]
    flips += not ok
    print(f"{'as recorded' if ok else 'FLIPPED    '} {name}: {verdict} (expected {EXPECT[name]}): {why}")
    if not ok:
        print(f"    -> update EXPECT['{name}'] and THREAT_MODEL.md together, in the commit that changed it")
sys.exit(1 if flips else 0)
