"""Runs inside a container whose only channel is the broker socket.
Exits 0 only if the broker route works and every bypass attempt fails.
Evidence for A2 in this reference deployment, not a proof for others."""
import json, socket, sys

SOCK = "/sock/broker.sock"
results = []


def check(name, ok):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name, flush=True)


def propose(tool, args):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(SOCK)
        msg = {"tool": tool, "args": [[k, v] for k, v in args.items()]}
        s.sendall((json.dumps(msg) + "\n").encode())
        return json.loads(s.makefile().readline())


def fails(fn):
    try:
        fn()
        return False
    except Exception:
        return True


r = propose("read_file", {"path": "/workspace/notes.txt"})
check("broker route works: registered read", r.get("executed") is True and "hello" in r.get("content", ""))
r = propose("read_file", {"path": "/workspace/invented.txt"})
check("broker still enforces: invented path rejected", r.get("decision") == "reject")
r = propose("write_file", {"path": "/workspace/reports/ci.md", "content": "written by confined agent"})
check("broker route works: write under registered pattern", r.get("executed") is True)
r = propose("read_file", {"path": "/workspace/reports/ci.md"})
check("broker read-back of the written file", r.get("content") == "written by confined agent")

check("bypass blocked: direct read of workspace file",
      fails(lambda: open("/tmp/darmdemo/workspace/notes.txt").read()))
check("bypass blocked: direct read of secret", fails(lambda: open("/tmp/darmdemo/secret.txt").read()))
check("bypass blocked: read the broker's attestation key",
      fails(lambda: open("/tmp/darmdemo/audit.jsonl.key", "rb").read()))
check("bypass blocked: write to filesystem", fails(lambda: open("/agent_out.txt", "w").write("x")))
check("bypass blocked: outbound network",
      fails(lambda: socket.create_connection(("1.1.1.1", 443), timeout=3).close()))
check("bypass blocked: DNS", fails(lambda: socket.getaddrinfo("github.com", 443)))

print(f"{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
