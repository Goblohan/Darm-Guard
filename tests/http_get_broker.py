"""http_get through the broker, end to end: proposal, URL normal form, provenance, the kernel,
intents, the log, the network and back, against a local TLS server. Predictions first."""
import json, os, ssl, subprocess, sys, tempfile, threading, time
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")

d = tempfile.mkdtemp(prefix="darm-http-")
cert, key = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout", key,
                "-out", cert, "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
               check=True, capture_output=True)
received = []
send_boundary_received = threading.Event()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def do_GET(self):
        received.append((self.path, self.headers.get("Authorization")))
        if self.path == "/api/send-boundary":
            send_boundary_received.set()
            return
        if self.path == "/api/slow":
            time.sleep(3)
        if self.path == "/api/redirect":
            self.send_response(302); self.send_header("Location", "https://elsewhere.example/"); self.end_headers(); return
        if self.path == "/api/echo-location":
            self.send_response(302)
            self.send_header("Location", "https://elsewhere.example/?echo=" + self.headers.get("Authorization", ""))
            self.end_headers()
            return
        body = ("token was " + str(self.headers.get("Authorization"))).encode() if self.path == "/api/echo" \
            else b'{"status": "ok"}'
        self.send_response(200)
        self.send_header("Content-Type", self.headers.get("Authorization", "") if self.path == "/api/echo-type" else "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); sctx.load_cert_chain(cert, key)
srv.socket = sctx.wrap_socket(srv.socket, server_side=True)
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = f"https://127.0.0.1:{srv.server_address[1]}"
os.makedirs(os.path.join(d, "workspace"))
token = os.path.join(d, "token"); open(token, "w").write("Bearer s3cr3t-token\n")
config = {"policy": {"tools": [{"tool": "http_get", "rules": [
              {"key": "url", "allowedValues": [], "allowedPrefixes": [base + "/api/"]}]}]},
          "credential_tools": ["http_get"], "workspace": os.path.join(d, "workspace"),
          "http": {"credentials": [{"prefix": base + "/api/", "header": "Authorization", "value_file": token}],
                   "allow_private": ["127.0.0.1"], "cafile": cert, "timeout": 1.5}}
json.dump(config, open(os.path.join(d, "config.json"), "w"))
open(os.path.join(d, "registry.txt"), "w").write(base + "/api/*\n")
cfg = B.BrokerConfig.load(os.path.join(d, "config.json"), os.path.join(d, "registry.txt"))
audit = os.path.join(d, "audit.jsonl")
b = B.Broker(cfg, KernelClient(), B.AuditLog(audit))
get = lambda url, **extra: b.handle(dict({"tool": "http_get", "args": [["url", url]]}, **extra))

r = get(base + "/api/status")
check("a registered URL: admitted, fetched, and the body returned",
      (r.get("decision"), r.get("effect"), r.get("status"), r.get("body")), ("admit", "succeeded", 200, '{"status": "ok"}'))
check("the server received the principal's credential", received[-1], ("/api/status", "Bearer s3cr3t-token"))
check("nothing the agent receives contains the credential", "s3cr3t" in json.dumps(r), False)
check("the server's certificate is on record in the response", len(r.get("server", {}).get("cert_sha256", "")), 64)
r = get(base + "/api/echo")
check("a credential the server echoes is withheld from the agent", ("s3cr3t" in json.dumps(r), "withheld" in r.get("body", "")), (False, True))
for path, field in (("/api/echo-location", "location"), ("/api/echo-type", "content_type")):
    r = get(base + path)
    check("literal header echo withheld through broker: " + field,
          ("s3cr3t" in json.dumps(r), "withheld" in r.get(field, "")), (False, True))
n = len(received)
for label, url in (("an unregistered URL", base + "/admin/keys"),
                   ("a dot segment climbing out of /api/", base + "/api/../admin"),
                   ("a disguised host", f"https://127.0.0.1:{srv.server_address[1]}@attacker.example/api/"),
                   ("plain http", base.replace("https", "http") + "/api/status")):
    r = get(url)
    check(f"{label}: refused", (r.get("decision"), r.get("effect")), ("reject", "none"))
r = b.handle({"tool": "http_get", "args": [["url", base + "/api/status"], ["header", "X-Evil: 1"]]})
check("an argument besides url: refused", r.get("error"), "http_get takes exactly one argument, url")
check("and none of those refusals reached the server", len(received) - n, 0)
r = get(base + "/api/redirect")
check("a redirect: reported with its location, not followed",
      (r.get("status"), r.get("location"), [p for p, _ in received].count("/api/redirect")), (302, "https://elsewhere.example/", 1))
r = get(base + "/api/slow", idempotency_key="slow-1")
check("sent, no answer in time: effect unknown, not failed", (r.get("decision"), r.get("effect")), ("admit", "unknown"))
r = get(base + "/api/slow", idempotency_key="slow-1")
check("its idempotency key stays unresolved: a retry is refused, not re-sent",
      (r.get("effect"), "unresolved" in (r.get("error") or "")), ("none", True))

log = open(audit).read()
entries = [json.loads(l) for l in log.splitlines() if l.strip()]
prep = [e for e in entries if e["event"] == "prepared" and e.get("tool") == "http_get"]
outc = [e for e in entries if e["event"] == "outcome" and e.get("tool") == "http_get"]
check("each of the 6 admitted calls had its URL recorded before it was sent", (len(prep), all(e.get("url", "").startswith(base) for e in prep)), (6, True))
check("each outcome records status, body hash and server, not the body",
      (outc[0]["remote"]["status"], len(outc[0]["remote"]["body_sha256"]), "body" in outc[0]["remote"]), (200, 64, False))
check("the credential appears nowhere in the log", "s3cr3t" in log, False)
check("verify_world is not confused by remote calls", B.verify_world(cfg, audit, None)["ok"], True)

ib_intents = os.path.join(d, "intents.txt"); open(ib_intents, "w").write(f"http_get url={base}/api/status\n")
ib = B.Broker(cfg, KernelClient(), B.AuditLog(os.path.join(d, "audit2.jsonl")), B.load_intents(ib_intents), ib_intents)
r1 = ib.handle({"tool": "http_get", "args": [["url", base + "/api/status"]]})
r2 = ib.handle({"tool": "http_get", "args": [["url", base + "/api/status"]]})
check("an intent for one exact URL authorizes one call", (r1.get("effect"), r2.get("failure")), ("succeeded", "intent"))

# The remote receives the request, but the transport reports an exception at
# the send boundary. Keep the intent reserved and refuse a keyed retransmission.
uncertain_url = base + "/api/send-boundary"
uncertain_intents = os.path.join(d, "uncertain-intents.txt")
open(uncertain_intents, "w").write(f"http_get url={uncertain_url}\n")
ub = B.Broker(cfg, KernelClient(), B.AuditLog(os.path.join(d, "uncertain.jsonl")),
              B.load_intents(uncertain_intents), uncertain_intents)
real_endheaders = B.http_get.http.client.HTTPConnection.endheaders
def sent_then_error(conn, *args, **kwargs):
    real_endheaders(conn, *args, **kwargs)
    raise OSError("injected error after send")
proposal = {"tool": "http_get", "args": [["url", uncertain_url]], "idempotency_key": "send-error"}
with patch.object(B.http_get.http.client.HTTPConnection, "endheaders", sent_then_error):
    uncertain = ub.handle(proposal)
check("post-send error: remote received it, effect unknown, intent reserved",
      (send_boundary_received.wait(2), uncertain.get("effect"), bool(ub._reserved)), (True, "unknown", True))
retry = ub.handle(proposal)
check("ambiguous send: keyed retry does not send again",
      (retry.get("effect"), "unresolved" in retry.get("error", ""),
       sum(path == "/api/send-boundary" for path, _ in received)), ("none", True, 1))
srv.shutdown()
print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
