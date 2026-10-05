"""A stand-in API for the deployment: HTTPS on api.internal:8443, with a certificate made at start
and written to /certs, where the broker reads it as the CA it trusts. It reports whether a request
carried a credential, never the credential itself."""
import datetime, json, os, ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.internal")])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("api.internal")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))
os.makedirs("/certs", exist_ok=True)
key_path = "/tmp/api-key.pem"
with open(key_path, "wb") as f:
    f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))
with open("/certs/api-cert.pem.tmp", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
os.replace("/certs/api-cert.pem.tmp", "/certs/api-cert.pem")   # the broker never sees half a file


class Api(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        data = json.dumps({"status": "ok", "path": self.path,
                           "authorized": self.headers.get("Authorization") is not None}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


srv = ThreadingHTTPServer(("0.0.0.0", 8443), Api)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/certs/api-cert.pem", key_path)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print("api.internal:8443 serving", flush=True)
srv.serve_forever()
