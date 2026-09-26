"""Attestation v2 inside the broker: what the regression suite cannot show.
Predictions written first."""
import hashlib, hmac, json, os, stat, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
import darm_guard.broker as B
from darm_guard.kernel import KernelClient

D = "/tmp/darmdemo"; R = f"{D}/workspace/reports"; AUDIT = f"{D}/attest_broker.jsonl"
for f in (AUDIT, AUDIT + ".key", AUDIT + ".pub.json", AUDIT + ".legacy.key", AUDIT + ".lock"):
    if os.path.exists(f):
        os.remove(f)
cfg = B.BrokerConfig.load(f"{D}/config.json", f"{D}/registry.txt")
keys = B.Keys.generate()
keys.legacy = os.urandom(32)
broker = B.Broker(cfg, KernelClient(), B.AuditLog(AUDIT), None, None, keys)
results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")
def write(name, content):
    r = broker.handle({"tool": "write_file", "args": [["path", "/workspace/reports/" + name], ["content", content]]})
    assert r.get("effect") == "succeeded", r
    return r
def raw_att(name):
    return os.getxattr(f"{R}/{name}", B.XATTR)
def findings(k, name):
    return [x["finding"] for x in B.verify_world(cfg, AUDIT, k)["findings"]
            if x["target"] == "/workspace/reports/" + name]

ra = write("va.md", "alpha"); write("vb.md", "beta"); write("vc.md", "gamma")

print("1. the broker writes v2")
a = json.loads(raw_att("va.md"))
check("scheme and key id", (a.get("v"), a.get("kid") == keys.ring.active), (2, True))
check("a signature, and no HMAC field", ("sig" in a, "mac" in a), (True, False))

print("2. an auditor with public keys only")
auditor = keys.public_only()
res = B.verify_world(cfg, AUDIT, auditor)
check("verifies the world clean", (res["ok"], res["legacy"]), (True, []))

print("3. a legacy (v1) attestation")
b = json.loads(raw_att("vb.md"))
mac = hmac.new(keys.legacy, f"{b['rid']}|{b['target']}|{b['digest']}".encode(), hashlib.sha256).hexdigest()
os.setxattr(f"{R}/vb.md", B.XATTR, json.dumps({"rid": b["rid"], "target": b["target"],
                                               "digest": b["digest"], "mac": mac}, sort_keys=True).encode())
res = B.verify_world(cfg, AUDIT, keys)
check("with the legacy secret: not a violation, but listed as legacy",
      (findings(keys, "vb.md"), res["legacy"]), ([], ["/workspace/reports/vb.md"]))
check("without it (public keys only): forged or moved",
      findings(auditor, "vb.md"), ["attestation forged or moved"])

print("4. an attestation under a key outside the ring")
c = json.loads(raw_att("vc.md"))
os.setxattr(f"{R}/vc.md", B.XATTR, B.KeyRing.generate().sign(c["rid"], c["target"], c["digest"]))
check("reported as an unknown key, not a forgery",
      findings(keys, "vc.md"), ["attestation under an unknown key (not in the ring)"])

print("5. startup migration of an old key file")
M = f"{D}/migrate.jsonl"
for f in (M + ".key", M + ".pub.json", M + ".legacy.key"):
    if os.path.exists(f):
        os.remove(f)
old = os.urandom(32)
fd = os.open(M + ".key", os.O_WRONLY | os.O_CREAT, 0o600); os.write(fd, old); os.close(fd)
k = B._load_or_create_keys(M)
check("old secret moved to .legacy.key, bytes intact", open(M + ".legacy.key", "rb").read() == old, True)
check("and loaded as the legacy key", k.legacy == old, True)
check("a public ring created", os.path.exists(M + ".pub.json"), True)
check("a new private key, owner-only",
      (open(M + ".key", "rb").read() != old, oct(stat.S_IMODE(os.stat(M + ".key").st_mode))), (True, "0o600"))
check("the new ring can sign", k.ring.can_sign(), True)

print("6. the certificate")
claims = [x for c in ra.get("basis", []) for x in c["assumptions"]]
check("states the narrower assumption", any("private signing key is secret" in x for x in claims), True)

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
