"""Re-attesting legacy files without laundering, retiring the old secret, and
key rotation. Predictions written first."""
import hashlib, hmac, json, os, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; R = f"{D}/workspace/reports"
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")
def fresh(path):
    for f in (path, path + ".key", path + ".pub.json", path + ".legacy.key", path + ".lock"):
        if os.path.exists(f):
            os.remove(f)
def att(name):
    return json.loads(os.getxattr(f"{R}/{name}", B.XATTR))
def findings(keys, audit, name):
    return [x["finding"] for x in B.verify_world(cfg, audit, keys)["findings"]
            if x["target"] == "/workspace/reports/" + name]
def to_v1(keys, name):
    a = att(name)
    mac = hmac.new(keys.legacy, f"{a['rid']}|{a['target']}|{a['digest']}".encode(), hashlib.sha256).hexdigest()
    os.setxattr(f"{R}/{name}", B.XATTR, json.dumps({"rid": a["rid"], "target": a["target"],
                                                    "digest": a["digest"], "mac": mac}, sort_keys=True).encode())

print("A. re-attesting legacy files, without laundering")
A = f"{D}/stage4a.jsonl"; fresh(A)
keys = B.Keys.generate(); keys.legacy = os.urandom(32)
b = B.Broker(cfg, KernelClient(), B.AuditLog(A), None, None, keys)
for n, c in (("sa.md", "legit"), ("sb.md", "will be tampered"), ("sc.md", "already v2")):
    assert b.handle({"tool": "write_file", "args": [["path", "/workspace/reports/" + n], ["content", c]]})["effect"] == "succeeded"
to_v1(keys, "sa.md"); to_v1(keys, "sb.md")
with open(f"{R}/sb.md", "a") as f:
    f.write(" TAMPERED")                                  # in place: the v1 attestation stays
res = b.reattest_legacy()
check("A1 legitimate upgraded, tampered refused", (res["upgraded"], res["refused"]),
      (["/workspace/reports/sa.md"], ["/workspace/reports/sb.md"]))
check("A2 upgraded file now v2 under the active key", (att("sa.md").get("v"), att("sa.md").get("kid") == keys.ring.active), (2, True))
check("A2 tampered file still v1 and still flagged",
      ("mac" in att("sb.md"), findings(keys, A, "sb.md")), (True, ["content changed outside the broker"]))
check("A3 re-attestation recorded in the audit log",
      [e["target"] for e in map(json.loads, open(A)) if e.get("event") == "reattested"], ["/workspace/reports/sa.md"])
check("A4 retiring the old secret refused while a file relies on it", B.retire_legacy_secret(cfg, A, keys), False)
assert b.handle({"tool": "delete_file", "args": [["path", "/workspace/reports/sb.md"]]})["effect"] == "succeeded"
check("A5 retired once nothing relies on it", (B.retire_legacy_secret(cfg, A, keys), keys.legacy), (True, None))
res = B.verify_world(cfg, A, keys.public_only())
check("A5 an auditor with public keys only: clean, nothing legacy", (res["ok"], res["legacy"]), (True, []))

print("B. rotation, with the broker stopped")
Z = f"{D}/stage4b.jsonl"; fresh(Z)
k1 = B._load_or_create_keys(Z)
b1 = B.Broker(cfg, KernelClient(), B.AuditLog(Z), None, None, k1)
for n in ("r1.md", "r2.md"):
    assert b1.handle({"tool": "write_file", "args": [["path", "/workspace/reports/" + n], ["content", n]]})["effect"] == "succeeded"
seed_before = open(Z + ".key", "rb").read()
old, new = B.rotate_keys(Z)
check("B1 new key id, and the private key file changed", (old != new, open(Z + ".key", "rb").read() != seed_before), (True, True))
k2 = B._load_or_create_keys(Z)
# scoped to part B's own files: part A's files share this workspace and are signed
# under part A's ring, so they are (correctly) an unknown key here; the check was
# first written unscoped and failed on exactly those two files
mine = ("r1.md", "r2.md")
check("B2 earlier attestations verify after rotation",
      [findings(k2, Z, n) for n in mine], [[], []])
check("B2 ...and from the public ring alone",
      [findings(B.Keys(B.KeyRing.load(None, Z + ".pub.json")), Z, n) for n in mine], [[], []])
b2 = B.Broker(cfg, KernelClient(), B.AuditLog(Z), None, None, k2)
assert b2.handle({"tool": "write_file", "args": [["path", "/workspace/reports/r3.md"], ["content", "r3"]]})["effect"] == "succeeded"
check("B3 new writes signed under the new key id", (att("r3.md")["kid"], att("r1.md")["kid"]), (new, old))
srv = B.serve(cfg, "/tmp/darm-stage4.sock", Z)
try:
    B.rotate_keys(Z); refused = False
except Exception:
    refused = True
srv.server_close()
check("B4 rotation refused while a broker holds the lock", refused, True)

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
