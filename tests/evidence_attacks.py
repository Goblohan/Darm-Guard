"""Evidence-before-effect tests (DARM Guard 0.7.1). Starts its own brokers."""
import json, os, socket, subprocess, sys, threading, time
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
from darm_guard.broker import BrokerClient

D, SOCK = "/tmp/darmdemo", "/tmp/darm-broker.sock"
results = []

def check(name, ok, detail=""):
    results.append(bool(ok))
    print(("PASS " if ok else "FAIL ") + name, str(detail)[:110])

def start(audit, *extra):
    if os.path.exists(SOCK):
        os.remove(SOCK)
    p = subprocess.Popen([sys.executable, "-c", "from darm_guard.broker import main; main()",
                          "--config", f"{D}/config.json", "--registry", f"{D}/registry.txt",
                          "--audit", audit, *extra],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=ROOT)
    for _ in range(50):
        if (os.path.exists(SOCK) and os.path.exists(audit)) or p.poll() is not None:
            break
        time.sleep(0.1)
    time.sleep(0.3)
    return p

def stop(p):
    p.terminate()
    p.wait()

def raw(data):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect(SOCK)
        s.sendall(data)
        return json.loads(s.makefile().readline())

def entries(path):
    return [json.loads(l) for l in open(path) if l.strip()]

c = BrokerClient(SOCK)

# 1. unwritable audit: nothing performed
a1, target = f"{D}/ev1.jsonl", f"{D}/workspace/reports/ev1.md"
for f in (a1, target):
    if os.path.exists(f):
        os.chmod(f, 0o644); os.remove(f)
p = start(a1)
os.chmod(a1, 0o444)
r = c.propose("write_file", {"path": "/workspace/reports/ev1.md", "content": "x"})
check("unwritable audit: nothing performed",
      r.get("effect") == "none" and not os.path.exists(target), r)
os.chmod(a1, 0o644)
stop(p)

# 2-4. evidence pairing, duplicate keys, oversized request
a2 = f"{D}/ev2.jsonl"
if os.path.exists(a2):
    os.remove(a2)
p = start(a2)
r = c.propose("write_file", {"path": "/workspace/reports/ev2.md", "content": "paired"})
ev = [e for e in entries(a2) if e.get("request_id") == r.get("request_id")]
check("admitted request: prepared then outcome, same request_id",
      r.get("effect") == "succeeded" and r.get("evidence") == "recorded"
      and [e["event"] for e in ev] == ["prepared", "outcome"], [e["event"] for e in ev])
r = raw((json.dumps({"tool": "write_file", "args": [["path", "/workspace/reports/a.md"],
                                                   ["path", "/workspace/other.txt"]]}) + "\n").encode())
check("duplicate argument keys refused", "malformed" in (r.get("error") or ""), r)
r = raw(b"x" * (1 << 20) + b"xx\n")
check("oversized request refused", "too large" in (r.get("error") or ""), r)
stop(p)

# 5. tampered audit: broker refuses to start
lines = open(a2).read().splitlines()
e = json.loads(lines[1]); e["decision"] = "reject"
lines[1] = json.dumps(e, sort_keys=True)
open(a2, "w").write("\n".join(lines) + "\n")
p = start(a2)
time.sleep(0.5)
check("tampered audit: broker refuses to start", p.poll() is not None, f"exit={p.poll()}")
if p.poll() is None:
    stop(p)

# 6. sent but no reply: unknown, never reject
fake = "/tmp/darm-fake.sock"
if os.path.exists(fake):
    os.remove(fake)
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(fake); srv.listen(1)
def swallow():
    conn, _ = srv.accept(); conn.recv(65536); conn.close()
threading.Thread(target=swallow, daemon=True).start()
r = BrokerClient(fake).propose("read_file", {"path": "/workspace/notes.txt"})
check("sent but no reply: unknown, never reject",
      r.get("decision") == "unknown" and r.get("effect") == "unknown", r)
srv.close()

# 7. nothing sent: reject, effect none
r = BrokerClient("/tmp/no-such-darm.sock").propose("read_file", {"path": "/workspace/notes.txt"})
check("nothing sent: reject, effect none",
      r.get("decision") == "reject" and r.get("effect") == "none", r)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
