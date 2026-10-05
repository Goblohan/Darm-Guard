"""darm-guard demo: the broker governing an agent's file tools, start to finish,
in a temporary directory, in one command.

The broker is started exactly as darm-broker starts it (serve: the same locks,
keys, intents and recovery), on a background thread so nothing is left running.
Each step says what the agent tried, what happened, and why; the command exits
non-zero if any step does not behave as stated, so it doubles as a test."""
import hashlib, json, os, shutil, socket, sys, tempfile, threading

from . import broker as B
from . import install as I

WRITE_OK = "/workspace/reports/q3.md"


def _fixture(d):
    """A workspace, a policy, a registry and the principal's intents, written for this demo."""
    os.makedirs(os.path.join(d, "workspace", "reports"))
    os.makedirs(os.path.join(d, "workspace", "secrets"))
    config = {"policy": {"tools": [
        {"tool": "read_file", "rules": [{"key": "path", "allowedValues": [], "allowedPrefixes": ["/workspace/reports/"]}]},
        {"tool": "write_file", "rules": [
            {"key": "path", "allowedValues": [], "allowedPrefixes": ["/workspace/reports/"]},
            {"key": "content", "allowedValues": [], "allowedPrefixes": [""], "payload": True}]}]},
        "credential_tools": ["read_file", "write_file"],
        "workspace": os.path.join(d, "workspace")}
    with open(os.path.join(d, "config.json"), "w") as f:
        json.dump(config, f, indent=1)
    with open(os.path.join(d, "registry.txt"), "w") as f:
        f.write("/workspace/reports/*\n/workspace/secrets/key.txt\n")
    with open(os.path.join(d, "intents.txt"), "w") as f:
        f.write(f"write_file path={WRITE_OK}\nwrite_file path=/workspace/secrets/key.txt\nread_file\n")


def _raw(sock, msg):
    """Send a proposal over the socket directly, as an agent bypassing the client could."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect(sock)
        s.sendall((json.dumps(msg) + "\n").encode())
        return json.loads(s.makefile().readline())


def _why(r):
    return r.get("failure") or r.get("error") or r.get("effect") or "?"


def run(keep=False):
    kernel = I.verified_kernel_path()
    if not kernel:
        print("The DARM kernel is not installed, so the broker cannot decide anything and will not run.\n"
              "Install it, then run the demo again:\n\n    darm-guard-install-kernel\n    darm-guard demo")
        return 2

    d = tempfile.mkdtemp(prefix="darm-demo-")
    sock, audit = os.path.join(d, "broker.sock"), os.path.join(d, "audit.jsonl")
    _fixture(d)
    cfg = B.BrokerConfig.load(os.path.join(d, "config.json"), os.path.join(d, "registry.txt"))
    srv = B.serve(cfg, sock, audit, intents_path=os.path.join(d, "intents.txt"))
    srv.broker.audit.append({"event": "start", "config_sha256": B.sha256_file(os.path.join(d, "config.json")),
                             "registry_sha256": B.sha256_file(os.path.join(d, "registry.txt"))})
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    agent = B.BrokerClient(sock)
    results = []

    def step(n, tried, ok, what, why):
        results.append(bool(ok))
        print(f"{'ok ' if ok else 'FAIL'}  {n}. {tried}\n       {what}. {why}\n")

    print(f"DARM Guard demo, in {d}\n")
    print("The principal allows reads and writes under /workspace/reports/ only, and has given three\n"
          f"single-use intents: write {WRITE_OK}, write /workspace/secrets/key.txt, and one read.\n"
          "The agent holds only a socket. Everything below goes through the broker and the kernel.\n")
    try:
        r = agent.propose("write_file", {"path": WRITE_OK, "content": "Q3 numbers"})
        step(1, f"The agent writes {WRITE_OK}.",
             r.get("decision") == "admit" and r.get("effect") == "succeeded" and r.get("attested") is True,
             "Admitted, written, and the file signed with the request that wrote it",
             f"Its intent is now spent ({r.get('intent_consumed', 'none')}).")

        r = agent.propose("read_file", {"path": WRITE_OK})
        step(2, "The agent reads it back.",
             r.get("decision") == "admit" and r.get("content") == "Q3 numbers",
             f"Admitted; it gets back exactly what was written ({r.get('content')!r})",
             "The read is checked against the signature and the log, so stale or substituted content is refused.")

        real4 = os.path.join(d, "workspace", "reports", "q4.md")
        r = agent.propose("write_file", {"path": "/workspace/reports/q4.md", "content": "unasked"})
        step(3, "The agent writes /workspace/reports/q4.md, which the principal never asked for.",
             r.get("decision") != "admit" and r.get("failure") == "intent" and not os.path.exists(real4),
             f"Refused ({_why(r)}); nothing was written",
             "The policy allows the path, but no intent covers it: no action without the principal's authorization.")

        realk = os.path.join(d, "workspace", "secrets", "key.txt")
        r = agent.propose("write_file", {"path": "/workspace/secrets/key.txt", "content": "x"})
        step(4, "The agent writes /workspace/secrets/key.txt. The principal even gave an intent for it.",
             r.get("decision") != "admit" and r.get("failure") != "intent" and not os.path.exists(realk),
             f"Refused by the kernel ({_why(r)}); nothing was written",
             "The path is outside the policy, and an intent cannot widen the policy (darm-monitor E24b).")

        r = agent.propose("read_file", {"path": "/workspace/reports/../secrets/key.txt"})
        step(5, "The agent reads /workspace/reports/../secrets/key.txt.",
             r.get("decision") != "admit" and "normal form" in (r.get("error") or ""),
             f"Refused before any decision ({_why(r)})",
             "Paths must be in normal form, so '..' cannot climb out of an allowed prefix.")

        r = _raw(sock, {"tool": "write_file", "args": [["path", "/workspace/reports/q5.md"], ["content", "x"]],
                        "provenance": "authoritative"})
        step(6, "The agent bypasses the client and labels its own proposal 'authoritative'.",
             r.get("decision") != "admit" and not os.path.exists(os.path.join(d, "workspace", "reports", "q5.md")),
             f"Refused ({_why(r)})",
             "Proposals are exactly {tool, args}; the broker assigns provenance itself, from the principal's registry.")

        auditor = B.Keys(B.KeyRing.load(None, audit + ".pub.json"))
        v = B.verify_world(cfg, audit, auditor)
        step(7, "An auditor holding only the public key checks the workspace against the log.",
             v["ok"], "Clean: every file matches the request that wrote it",
             "Checking needs only the public key, so the evidence cannot be forged by whoever checks it.")

        with open(os.path.join(d, "workspace", "reports", "q3.md"), "a") as f:
            f.write(" (edited by hand)")
        hits = [x for x in B.verify_world(cfg, audit, auditor)["findings"] if x["target"].endswith("q3.md")]
        step(8, "Someone edits q3.md directly, outside the broker. The auditor checks again.",
             bool(hits), f"Detected: {hits[0]['finding'] if hits else 'nothing found'}",
             "A change that bypasses the broker does not carry its signature, so it shows.")
    finally:
        srv.shutdown()
        srv.broker.audit.append({"event": "stop"})
        srv.server_close()

    prev, chain = "0" * 64, True
    for line in open(audit):
        e = json.loads(line)
        h = e.pop("entry_hash")
        chain = chain and e["prev_hash"] == prev and \
            hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest() == h
        prev = h
    step(9, "The audit log is checked end to end.", chain,
         "Its hash chain is intact", "Every request above, admitted or refused, is recorded in order.")

    print(f"{sum(results)}/{len(results)} steps behaved as described.\n")
    print("Not shown here: that the agent has no other route to the files. That is complete mediation,\n"
          "which a deployment provides (for example a container with only the broker's socket). Only the\n"
          "file tools are governed. See LIMITATIONS.md for every claim's limits.")
    if keep:
        print(f"\nKept for inspection: {d}")
    else:
        shutil.rmtree(d, ignore_errors=True)
    return 0 if all(results) else 1
