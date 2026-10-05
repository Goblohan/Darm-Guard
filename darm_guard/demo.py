"""darm-guard demo: the broker governing an agent's file tools and its HTTP requests, start
to finish, in a temporary directory, in one command.

The broker is started exactly as darm-broker starts it (serve: the same locks,
keys, intents and recovery), on a background thread so nothing is left running.
For the network steps, the demo starts a small HTTPS server of its own, on this
machine only, with a certificate made for the occasion, so nothing leaves the
machine. Each step says what the agent tried, what happened, and why; the command
exits non-zero if any step does not behave as stated, so it doubles as a test."""
import datetime, hashlib, ipaddress, json, os, shutil, socket, ssl, tempfile, threading, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import broker as B
from . import install as I

WRITE_OK = "/workspace/reports/q3.md"
METADATA = "https://169.254.169.254/latest/meta-data/"


def _tls_server(d):
    """A local HTTPS server standing in for an API: a self-signed certificate for 127.0.0.1,
    made here, and a record of every request it receives."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "darm-guard demo API")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                           critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = os.path.join(d, "api-cert.pem"), os.path.join(d, "api-key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    received = []

    class Api(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            auth = self.headers.get("Authorization")
            received.append((self.path, auth))
            if self.path == "/v1/whoami":
                body = {"you_sent": auth}                 # an API that echoes the credential back
            else:
                body = {"status": "ok", "authorized": auth is not None}
            data = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Api)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"https://127.0.0.1:{srv.server_address[1]}", cert_path, received


def _fixture(d, api, cert, token):
    """A workspace, a policy, a registry, the principal's intents and API token, written for this demo."""
    os.makedirs(os.path.join(d, "workspace", "reports"))
    os.makedirs(os.path.join(d, "workspace", "secrets"))
    config = {"policy": {"tools": [
        {"tool": "read_file", "rules": [{"key": "path", "allowedValues": [], "allowedPrefixes": ["/workspace/reports/"]}]},
        {"tool": "write_file", "rules": [
            {"key": "path", "allowedValues": [], "allowedPrefixes": ["/workspace/reports/"]},
            {"key": "content", "allowedValues": [], "allowedPrefixes": [""], "payload": True}]},
        {"tool": "http_get", "rules": [
            {"key": "url", "allowedValues": [], "allowedPrefixes": [api + "/v1/", "https://169.254.169.254/"]}]}]},
        "credential_tools": ["read_file", "write_file", "http_get"],
        "workspace": os.path.join(d, "workspace"),
        "http": {"credentials": [{"prefix": api + "/v1/", "header": "Authorization", "value_file": token}],
                 "allow_private": ["127.0.0.1"], "cafile": cert, "timeout": 5}}
    with open(os.path.join(d, "config.json"), "w") as f:
        json.dump(config, f, indent=1)
    with open(os.path.join(d, "registry.txt"), "w") as f:
        # the metadata address is registered by mistake, to show the broker refuses it anyway
        f.write(f"/workspace/reports/*\n/workspace/secrets/key.txt\n{api}/v1/*\nhttps://169.254.169.254/*\n")
    with open(os.path.join(d, "intents.txt"), "w") as f:
        f.write(f"write_file path={WRITE_OK}\nwrite_file path=/workspace/secrets/key.txt\nread_file\n"
                "http_get\nhttp_get\nhttp_get\n")
    with open(token, "w") as f:
        f.write(f"Bearer demo-{uuid.uuid4().hex}\n")


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
    token = os.path.join(d, "api-token")              # the principal's, outside the workspace
    api_srv, api, cert, received = _tls_server(d)
    _fixture(d, api, cert, token)
    secret = open(token).read().strip()
    cfg = B.BrokerConfig.load(os.path.join(d, "config.json"), os.path.join(d, "registry.txt"))
    srv = B.serve(cfg, sock, audit, intents_path=os.path.join(d, "intents.txt"))
    srv.broker.audit.append({"event": "start", "config_sha256": B.sha256_file(os.path.join(d, "config.json")),
                             "registry_sha256": B.sha256_file(os.path.join(d, "registry.txt"))})
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    agent = B.BrokerClient(sock)
    results = []

    def step(tried, ok, what, why):
        results.append(bool(ok))
        print(f"{'ok ' if ok else 'FAIL'}  {len(results)}. {tried}\n       {what}. {why}\n")

    print(f"DARM Guard demo, in {d}\n")
    print("The principal allows reads and writes under /workspace/reports/ only, and has given three\n"
          f"single-use intents for files: write {WRITE_OK}, write /workspace/secrets/key.txt, and one read.\n"
          "The agent holds only a socket. Everything below goes through the broker and the kernel.\n")
    try:
        r = agent.propose("write_file", {"path": WRITE_OK, "content": "Q3 numbers"})
        step(f"The agent writes {WRITE_OK}.",
             r.get("decision") == "admit" and r.get("effect") == "succeeded" and r.get("attested") is True,
             "Admitted, written, and the file signed with the request that wrote it",
             f"Its intent is now spent ({r.get('intent_consumed', 'none')}).")

        r = agent.propose("read_file", {"path": WRITE_OK})
        step("The agent reads it back.",
             r.get("decision") == "admit" and r.get("content") == "Q3 numbers",
             f"Admitted; it gets back exactly what was written ({r.get('content')!r})",
             "The read is checked against the signature and the log, so stale or substituted content is refused.")

        real4 = os.path.join(d, "workspace", "reports", "q4.md")
        r = agent.propose("write_file", {"path": "/workspace/reports/q4.md", "content": "unasked"})
        step("The agent writes /workspace/reports/q4.md, which the principal never asked for.",
             r.get("decision") != "admit" and r.get("failure") == "intent" and not os.path.exists(real4),
             f"Refused ({_why(r)}); nothing was written",
             "The policy allows the path, but no intent covers it: no action without the principal's authorization.")

        realk = os.path.join(d, "workspace", "secrets", "key.txt")
        r = agent.propose("write_file", {"path": "/workspace/secrets/key.txt", "content": "x"})
        step("The agent writes /workspace/secrets/key.txt. The principal even gave an intent for it.",
             r.get("decision") != "admit" and r.get("failure") != "intent" and not os.path.exists(realk),
             f"Refused by the kernel ({_why(r)}); nothing was written",
             "The path is outside the policy, and an intent cannot widen the policy (darm-monitor E24b).")

        r = agent.propose("read_file", {"path": "/workspace/reports/../secrets/key.txt"})
        step("The agent reads /workspace/reports/../secrets/key.txt.",
             r.get("decision") != "admit" and "normal form" in (r.get("error") or ""),
             f"Refused before any decision ({_why(r)})",
             "Paths must be in normal form, so '..' cannot climb out of an allowed prefix.")

        r = _raw(sock, {"tool": "write_file", "args": [["path", "/workspace/reports/q5.md"], ["content", "x"]],
                        "provenance": "authoritative"})
        step("The agent bypasses the client and labels its own proposal 'authoritative'.",
             r.get("decision") != "admit" and not os.path.exists(os.path.join(d, "workspace", "reports", "q5.md")),
             f"Refused ({_why(r)})",
             "Proposals are exactly {tool, args}; the broker assigns provenance itself, from the principal's registry.")

        print(f"Now the network. The principal registered {api}/v1/, an API this demo started on this\n"
              "machine, keeps its API token in a file the agent cannot read, and gave three single-use\n"
              "intents for http_get.\n")
        r = agent.propose("http_get", {"url": api + "/v1/status"})
        body = json.loads(r.get("body") or "{}")
        step(f"The agent fetches {api}/v1/status.",
             r.get("decision") == "admit" and r.get("status") == 200 and body.get("authorized") is True
             and secret not in json.dumps(r),
             f"Admitted and fetched (status {r.get('status')}); the API received the principal's token",
             "The broker attached it; the agent never held it, and nothing it got back contains it.")

        r = agent.propose("http_get", {"url": api + "/v1/whoami"})
        step(f"The agent fetches {api}/v1/whoami, which echoes back whatever credential it received.",
             r.get("decision") == "admit" and received[-1][1] == secret and secret not in json.dumps(r)
             and "withheld" in (r.get("body") or ""),
             f"The API echoed the token; the agent got {r.get('body')}",
             "The broker withholds the credential even when the remote side sends it back.")

        n = len(received)
        r = agent.propose("http_get", {"url": api + "/admin/keys"})
        step(f"The agent fetches {api}/admin/keys, a path the principal never registered.",
             r.get("decision") != "admit" and len(received) == n,
             f"Refused by the kernel ({_why(r)}); nothing was sent",
             "Only registered URLs are reachable, so an injected instruction to call elsewhere goes nowhere.")

        disguised = api + "@attacker.example/v1/"     # the API's address as userinfo: the host is attacker.example
        r = agent.propose("http_get", {"url": disguised})
        step(f"The agent fetches {disguised}, which looks like the API but is attacker.example.",
             r.get("decision") != "admit" and "normal form" in (r.get("error") or "") and len(received) == n,
             f"Refused before any decision ({_why(r)})",
             "URLs must be in normal form, so a disguised host cannot pass a prefix rule.")

        r = agent.propose("http_get", {"url": METADATA})
        step(f"The agent fetches {METADATA}, the cloud metadata service, which the principal registered by mistake.",
             r.get("decision") == "admit" and r.get("effect") == "failed" and "link-local" in (r.get("error") or ""),
             "Admitted by the kernel, then refused by the broker before anything was sent",
             "Loopback, private and metadata addresses are refused unless the principal allows them by name.")

        auditor = B.Keys(B.KeyRing.load(None, audit + ".pub.json"))
        v = B.verify_world(cfg, audit, auditor)
        step("An auditor holding only the public key checks the workspace against the log.",
             v["ok"], "Clean: every file matches the request that wrote it",
             "Checking needs only the public key, so the evidence cannot be forged by whoever checks it.")

        with open(os.path.join(d, "workspace", "reports", "q3.md"), "a") as f:
            f.write(" (edited by hand)")
        hits = [x for x in B.verify_world(cfg, audit, auditor)["findings"] if x["target"].endswith("q3.md")]
        step("Someone edits q3.md directly, outside the broker. The auditor checks again.",
             bool(hits), f"Detected: {hits[0]['finding'] if hits else 'nothing found'}",
             "A change that bypasses the broker does not carry its signature, so it shows.")
    finally:
        srv.shutdown()
        srv.broker.audit.append({"event": "stop"})
        srv.server_close()
        api_srv.shutdown()

    prev, chain = "0" * 64, True
    for line in open(audit):
        e = json.loads(line)
        h = e.pop("entry_hash")
        chain = chain and e["prev_hash"] == prev and \
            hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest() == h
        prev = h
    step("The audit log is checked end to end.", chain and secret not in open(audit).read(),
         "Its hash chain is intact, and the API token appears nowhere in it",
         "Every request above, admitted or refused, file or network, is recorded in order.")

    print(f"{sum(results)}/{len(results)} steps behaved as described.\n")
    print("Not shown here: that the agent has no other route to the files or the network. That is\n"
          "complete mediation, which a deployment provides (for example a container with no network and\n"
          "only the broker's socket; see deploy/). Only the file tools and http_get are governed.\n"
          "See LIMITATIONS.md for every claim's limits.")
    if keep:
        print(f"\nKept for inspection: {d}")
    else:
        shutil.rmtree(d, ignore_errors=True)
    return 0 if all(results) else 1
