"""The agent's side of the deployment. Its container has no network, a read-only filesystem,
no workspace and no darm-guard: the broker's socket is its only channel. Exits 0 only if the
broker route works and every bypass attempt fails. Evidence for complete mediation in this
deployment, not a proof for others: a container escape would be a failure of the isolation
layer, not of DARM."""
import hashlib, json, socket, sys

SOCK = "/sock/broker.sock"
results = []
APPROVED_CONTENT = "written by the confined agent"
WRITE_INTENT = ("write_file path=/workspace/reports/hello.md content_sha256="
                + hashlib.sha256(APPROVED_CONTENT.encode()).hexdigest())


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


def refused_for_intent(response):
    return (response.get("decision"), response.get("failure"), response.get("effect")) == (
        "reject", "intent", "none")


print("The agent, in its own container. Its only channel is the broker's socket: no network, no token.\n", flush=True)

r = propose("read_file", {"path": "/workspace/notes.txt"})
check(10, "Read a registered, policy-allowed path without a matching intent.",
      refused_for_intent(r), f"decision={r.get('decision')}, failure={r.get('failure')}, effect={r.get('effect')}")
r = propose("write_file", {"path": "/workspace/reports/other.md", "content": APPROVED_CONTENT})
check(11, "Use the write intent for another policy-allowed path.",
      refused_for_intent(r), f"decision={r.get('decision')}, failure={r.get('failure')}, effect={r.get('effect')}")
r = propose("write_file", {"path": "/workspace/reports/hello.md", "content": "substituted content"})
check(12, "Substitute content before the write intent is consumed.",
      refused_for_intent(r), f"decision={r.get('decision')}, failure={r.get('failure')}, effect={r.get('effect')}")

r = propose("write_file", {"path": "/workspace/reports/hello.md", "content": APPROVED_CONTENT})
check(1, "Write /workspace/reports/hello.md through the broker.",
      r.get("effect") == "succeeded" and r.get("attested") is True
      and r.get("intent_state") == "spent" and r.get("intent_consumed") == WRITE_INTENT,
      f"effect={r.get('effect')}, attested={r.get('attested')}, intent_state={r.get('intent_state')}")
r = propose("write_file", {"path": "/workspace/reports/hello.md", "content": APPROVED_CONTENT})
check(13, "Repeat the exact write after its intent was spent (no idempotency key).",
      refused_for_intent(r), f"decision={r.get('decision')}, failure={r.get('failure')}, effect={r.get('effect')}")
r = propose("read_file", {"path": "/workspace/reports/hello.md"})
check(2, "Read it back through the broker.", r.get("content") == APPROVED_CONTENT
      and r.get("intent_state") == "spent"
      and r.get("intent_consumed") == "read_file path=/workspace/reports/hello.md",
      f"Got back {r.get('content')!r}.")
r = propose("read_file", {"path": "/workspace/invented.txt"})
check(3, "An intent cannot authorize a path absent from the provenance registry.",
      (r.get("decision"), r.get("failure"), r.get("effect")) == ("reject", "provenance", "none"),
      f"Refused ({r.get('failure') or r.get('error')}): the broker still enforces the policy.")

r = propose("http_get", {"url": "https://api.internal:8443/v1/status"})
body = json.loads(r.get("body") or "{}")
check(4, "Fetch https://api.internal:8443/v1/status through the broker.",
      r.get("effect") == "succeeded" and body.get("authorized") is True and "Bearer" not in json.dumps(r)
      and r.get("intent_state") == "spent"
      and r.get("intent_consumed") == "http_get url=https://api.internal:8443/v1/status",
      f"Fetched (status {r.get('status')}), and the API was authorized, with a token this container has never seen.")
r = propose("http_get", {"url": "https://api.internal:8443/v1/status"})
check(14, "Repeat the API request after its intent was spent.",
      refused_for_intent(r), f"decision={r.get('decision')}, failure={r.get('failure')}, effect={r.get('effect')}")

ok, why = blocked(lambda: open("/data/workspace/notes.txt").read())
check(5, "Read the workspace directly, bypassing the broker.", ok,
      f"Blocked ({why}): the workspace is not in this container at all.")
ok, why = blocked(lambda: socket.create_connection(("1.1.1.1", 443), timeout=3))
check(6, "Open a network connection.", ok, f"Blocked ({why}): the container has no network.")
ok, why = blocked(lambda: open("/tmp/escape.txt", "w").write("x"))
check(7, "Write to its own filesystem, to stage anything.", ok, f"Blocked ({why}): the filesystem is read-only.")
ok, why = blocked(lambda: __import__("darm_guard"))
check(8, "Use the broker's own code or the kernel directly.", ok,
      f"Blocked ({why}): neither darm-guard nor the kernel is installed here.")


# Regression: connecting is allowed, modifying the socket directory is not.
def socket_directory_readonly(directory="/sock"):
    import errno, os, tempfile
    try:
        fd, name = tempfile.mkstemp(prefix=".darm-write-probe-", dir=directory)
    except OSError as exc:
        return exc.errno == errno.EROFS, f"{type(exc).__name__}: {exc}"
    else:
        os.close(fd)
        os.unlink(name)
        return False, "Created an entry beside the socket, then removed it."

ok, why = socket_directory_readonly()
check(9, "Create an entry beside the broker socket.", ok, why)


print(f"{sum(results)}/{len(results)} deployment checks passed (bounded test evidence, not a proof of complete mediation).",
      flush=True)
sys.exit(0 if all(results) else 1)
