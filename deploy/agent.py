"""The agent's side of the deployment. Its container has no network, a read-only filesystem,
no workspace and no darm-guard: the broker's socket is its only channel. Exits 0 only if the
broker route works and each listed bypass attempt fails. Evidence for complete mediation in this
deployment, not a proof for others: a container escape would be a failure of the isolation
layer, not of DARM."""
import errno, json, os, socket, stat, sys

SOCK = "/sock/broker.sock"
results = []


def check(n, tried, ok, what):
    results.append(bool(ok))
    print(f"{'ok ' if ok else 'FAIL'}  {n}. {tried}\n       {what}\n", flush=True)


def propose(tool, args):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect(SOCK)
        s.sendall((json.dumps({"tool": tool, "args": [[k, str(v)] for k, v in args.items()]}) + "\n").encode())
        return json.loads(s.makefile().readline())


def blocked(fn):
    try:
        fn()
        return False, "it succeeded"
    except Exception as e:
        return True, f"{type(e).__name__}: {e}"


def blocked_as(expected, fn):
    try:
        fn()
        return False, "it succeeded"
    except expected as e:
        return True, f"{type(e).__name__}: {e}"
    except Exception as e:
        return False, f"unexpected {type(e).__name__}: {e}"


def network_blocked(fn):
    try:
        fn()
        return False, "connection unexpectedly succeeded"
    except socket.gaierror as e:
        expected = e.errno in (socket.EAI_AGAIN, socket.EAI_NONAME)
        return expected, f"{type(e).__name__}: {e}"
    except OSError as e:
        expected = e.errno in (
            errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN,
            errno.EACCES, errno.EPERM,
        )
        return expected, f"{type(e).__name__}: {e}"
    except Exception as e:
        return False, f"unexpected {type(e).__name__}: {e}"


print("The agent, in its own container. Its only channel is the broker's socket: no network, no token.\n", flush=True)

r = propose("write_file", {"path": "/workspace/reports/hello.md", "content": "written by the confined agent"})
check(1, "Write /workspace/reports/hello.md through the broker.",
      r.get("effect") == "succeeded" and r.get("attested") is True,
      f"Admitted and written ({r.get('effect')}), and signed by the broker.")
r = propose("read_file", {"path": "/workspace/reports/hello.md"})
check(2, "Read it back through the broker.", r.get("content") == "written by the confined agent",
      f"Got back {r.get('content')!r}.")
r = propose("read_file", {"path": "/workspace/invented.txt"})
check(3, "Read a path the principal never registered.", r.get("decision") == "reject",
      f"Refused ({r.get('failure') or r.get('error')}): the broker still enforces the policy.")

r = propose("http_get", {"url": "https://api.internal:8443/v1/status"})
body = json.loads(r.get("body") or "{}")
check(4, "Fetch https://api.internal:8443/v1/status through the broker.",
      r.get("effect") == "succeeded" and body.get("authorized") is True and "Bearer" not in json.dumps(r),
      f"Fetched (status {r.get('status')}), and the API was authorized, with a token this container has never seen.")

ok, why = blocked_as(FileNotFoundError, lambda: open("/data/workspace/notes.txt").read())
check(5, "Read the workspace directly, bypassing the broker.", ok,
      f"Blocked ({why}): the workspace is not in this container at all.")
ok, why = network_blocked(lambda: socket.create_connection(("1.1.1.1", 443), timeout=3))
check(6, "Open a network connection.", ok, f"Blocked ({why}): the container has no network.")
ok, why = blocked(lambda: open("/tmp/escape.txt", "w").write("x"))
check(7, "Write to the root filesystem at /tmp/escape.txt.", ok, f"Blocked ({why}): the root filesystem path is read-only.")
ok, why = blocked(lambda: __import__("darm_guard"))
check(8, "Use the broker's own code or the kernel directly.", ok,
      f"Blocked ({why}): neither darm-guard nor the kernel is installed here.")

try:
    os.unlink(SOCK)
except OSError as e:
    unlink_denied = e.errno in (errno.EROFS, errno.EACCES, errno.EPERM)
    unlink_detail = f"{type(e).__name__}: {e}"
except Exception as e:
    unlink_denied = False
    unlink_detail = f"unexpected {type(e).__name__}: {e}"
else:
    unlink_denied = False
    unlink_detail = "unlink unexpectedly succeeded"

socket_intact = os.path.exists(SOCK) and stat.S_ISSOCK(os.stat(SOCK).st_mode)
check(9, "Try to unlink the broker socket path.",
      unlink_denied and socket_intact,
      f"Denied ({unlink_detail}); socket remains present: {socket_intact}.")

try:
    r = propose("read_file", {"path": "/workspace/notes.txt"})
    broker_alive = "hello" in r.get("content", "")
    broker_detail = f"broker response received: {broker_alive}"
except Exception as e:
    broker_alive = False
    broker_detail = f"{type(e).__name__}: {e}"
check(10, "Use the broker after the unlink attempt.",
      broker_alive, broker_detail)

def try_direct_workspace_write():
    with open("/data/workspace/reports/hello.md", "w") as f:
        f.write("DIRECT_BYPASS")


ok, why = blocked_as(FileNotFoundError, try_direct_workspace_write)
check(11, "Try to write the governed report directly.",
      ok, f"Blocked ({why}): the workspace is absent from the agent container.")

try:
    r = propose("read_file", {"path": "/workspace/reports/hello.md"})
    unchanged = r.get("content") == "written by the confined agent"
    detail = f"broker read-back unchanged: {unchanged}"
except Exception as e:
    unchanged = False
    detail = f"{type(e).__name__}: {e}"
check(12, "Verify the report after the direct-write attempt.",
      unchanged, detail)

r = propose("http_get", {"url": "https://example.com/"})
check(13, "Try a URL outside the configured API prefix.",
      r.get("decision") == "reject"
      and r.get("failure") == "semantic"
      and r.get("effect") == "none",
      f"Policy refusal: decision={r.get('decision')}, "
      f"failure={r.get('failure')}, effect={r.get('effect')}.")

ok, why = network_blocked(
    lambda: socket.create_connection(("api.internal", 8443), timeout=3).close()
)
check(14, "Connect directly to the approved API, bypassing the broker.", ok,
      f"Blocked ({why}): the agent has no network route to the API.")

try:
    with open("/data/secrets/api-token") as token_file:
        token_file.read()
    token_absent = False
    token_detail = "read unexpectedly succeeded"
except FileNotFoundError as e:
    token_absent = True
    token_detail = f"{type(e).__name__}: {e}"
except Exception as e:
    token_absent = False
    token_detail = f"unexpected failure: {type(e).__name__}: {e}"

check(15, "Try to read the broker API token directly.",
      token_absent,
      f"Token path absent from agent container: {token_detail}.")

print(f"{sum(results)}/{len(results)} checks behaved as described: the broker is this agent's only route to the governed workspace and approved API.",
      flush=True)
sys.exit(0 if all(results) else 1)
