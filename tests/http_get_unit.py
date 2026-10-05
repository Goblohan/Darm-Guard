"""Governed GET, its network side: URL normal form, address checks and the fetch itself,
against a local TLS server the test starts. Predictions first; no internet needed."""
import json, os, socket, ssl, subprocess, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from darm_guard import http_get as H

results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")

# ---- normal form: accepted exactly as given, or refused (never repaired)
NORMAL = ["https://api.example.com/", "https://api.example.com/v1/items?id=7&x=a%20b",
          "https://api.example.com:8443/v1/", "https://127.0.0.1:9000/x", "https://localhost:8443/"]
NOT_NORMAL = ["http://api.example.com/",              # https only
              "HTTPS://api.example.com/",             # scheme case
              "https://API.example.com/",             # host case
              "https://api.example.com",              # no path: '/' is the normal form
              "https://api.example.com:443/",         # default port
              "https://api.example.com@attacker.example/",   # credentials / disguised host
              "https://user:pw@api.example.com/",
              "https://api.example.com.attacker.example/"[:0] or "https://api.example.com./",  # trailing dot
              "https://api.example.com/v1/../admin",  # dot segments
              "https://api.example.com/v1/./x",
              "https://api.example.com//x",           # empty segment
              "https://api.example.com/%7Euser",      # needless encoding of an unreserved character
              "https://api.example.com/a%2fb",        # lowercase hex, and an encoded slash
              "https://api.example.com/a%2Fb",        # an encoded slash
              "https://api.example.com/x#frag",       # fragment
              "https://api.example.com/x?",           # bare '?'
              "https://api.example.com/x y",          # whitespace
              "https://api.example.com\\x",           # backslash
              "https://[::1]/",                       # IPv6 literal (not in v1)
              "https://0177.0.0.1/",                  # octal IPv4, which resolvers read as 127.0.0.1
              "https://0x7f.0.0.1/",                  # hex IPv4
              "https://2130706433/",                  # IPv4 as one decimal integer
              "https://127.1/",                       # shortened IPv4
              "https://api.123/",                     # a numeric top-level label
              "https://exämple.com/",                 # non-ASCII (IDN must be punycode)
              "https://api.example.com:080/"]         # leading zero in port
check("normal URLs accepted", [u for u in NORMAL if not H.normal_url(u)], [])
check("non-normal URLs refused", [u for u in NOT_NORMAL if H.normal_url(u)], [])
check("a prefix rule cannot be fooled by a suffix host: 'api.example.com.attacker.example' is normal, "
      "but does not start with 'https://api.example.com/'",
      (H.normal_url("https://api.example.com.attacker.example/"),
       "https://api.example.com.attacker.example/".startswith("https://api.example.com/")), (True, False))

# ---- addresses
check("loopback, private, link-local (metadata), unspecified refused; public allowed",
      [bool(H.address_refused(ip, "h", ())) for ip in
       ("127.0.0.1", "10.1.2.3", "192.168.0.1", "169.254.169.254", "0.0.0.0", "::1", "::ffff:10.0.0.1", "93.184.216.34")],
      [True, True, True, True, True, True, True, False])
check("an address the principal allows by name or by IP", 
      (H.address_refused("127.0.0.1", "localhost", ["localhost"]), H.address_refused("127.0.0.1", "h", ["127.0.0.1"])),
      ("", ""))

# ---- a local TLS server, its own certificate, and a record of what it received
d = tempfile.mkdtemp()
cert, key = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout", key,
                "-out", cert, "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
               check=True, capture_output=True)
received = []

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def do_GET(self):
        received.append((self.path, self.headers.get("Authorization")))
        if self.path == "/slow":
            time.sleep(3)
        if self.path == "/redirect":
            self.send_response(302); self.send_header("Location", "https://elsewhere.example/"); self.end_headers(); return
        body = {"/ok": b'{"status": "ok"}', "/echo": ("you sent " + str(self.headers.get("Authorization"))).encode(),
                "/big": b"x" * 5000}.get(self.path, b"?")
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); sctx.load_cert_chain(cert, key)
srv.socket = sctx.wrap_socket(srv.socket, server_side=True)
threading.Thread(target=srv.serve_forever, daemon=True).start()
port = srv.server_address[1]
base = f"https://127.0.0.1:{port}"
secret = os.path.join(d, "token"); open(secret, "w").write("Bearer s3cr3t-token\n")
creds = [{"prefix": base + "/", "header": "Authorization", "value_file": secret}]
kw = dict(credentials=creds, allow_private=["127.0.0.1"], cafile=cert, timeout=1.5)

r = H.fetch(base + "/ok", **kw)
check("a decided GET succeeds, with the server's certificate on record",
      (r["outcome"], r.get("status"), r.get("body"), len(r.get("server", {}).get("cert_sha256", ""))),
      ("succeeded", 200, '{"status": "ok"}', 64))
check("the server received the principal's credential", received[-1], ("/ok", "Bearer s3cr3t-token"))
check("the result returned to the agent contains no credential", "s3cr3t" in json.dumps(r), False)
r = H.fetch(base + "/echo", **kw)
check("a credential the server echoes back is withheld from the agent",
      (r.get("body"), "s3cr3t" in json.dumps(r)), ("you sent " + H.WITHHELD, False))
r = H.fetch(base + "/redirect", **kw)
check("a redirect is returned, not followed",
      (r.get("status"), r.get("location"), [p for p, _ in received].count("/redirect")),
      (302, "https://elsewhere.example/", 1))
r = H.fetch(base + "/big", **dict(kw, max_body=1000))
check("a body over the limit is truncated, and says so", (len(r.get("body", "")), r.get("truncated")), (1000, True))
n = len(received)
r = H.fetch(base + "/ok", **dict(kw, allow_private=[]))
check("loopback not allowed by the principal: refused, and nothing sent",
      (r["outcome"], "loopback" in r.get("error", ""), len(received) - n), ("failed", True, 0))
r = H.fetch(base + "/slow", **kw)
check("sent, but no answer in time: the outcome is unknown, not failed", r["outcome"], "unknown")
fake = lambda answers: (lambda host, port, proto=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in answers])
r = H.fetch("https://api.example.com/", resolver=fake(["10.0.0.5"]))
check("a public-looking name resolving to a private address is refused", ("private" in r.get("error", ""), r["outcome"]), (True, "failed"))
r = H.fetch("https://api.example.com/", resolver=fake(["93.184.216.34", "169.254.169.254"]))
check("if any answer is refused, the call is refused (no picking the safe one)", "link-local" in r.get("error", ""), True)
r = H.fetch("https://api.example.com@127.0.0.1/", **kw)
check("a non-normal URL is refused even if it reached fetch", (r["outcome"], r.get("error")), ("failed", "url not in normal form"))
srv.shutdown()
print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
