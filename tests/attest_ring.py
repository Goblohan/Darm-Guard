"""Attestation v2 (Ed25519 key ring), on its own, before the broker uses it.
Predictions written first."""
import json, os, stat, sys, tempfile
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
from darm_guard.attest import KeyRing

results = []
def check(label, got, predicted):
    results.append(got == predicted)
    print(f"  {label}: {got}   (predicted {predicted})")

broker = KeyRing.generate()
auditor = broker.public_only()
att = broker.sign("r1", "/workspace/reports/a.md", "d" * 64)
other = broker.sign("r2", "/workspace/reports/b.md", "e" * 64)

print("1. an outside verifier, holding only public keys")
check("verifies a genuine attestation", auditor.verify(att)[1], None)
check("holds no private key", auditor.can_sign(), False)

print("2. forgery, given only public information")
a = json.loads(att)
def tampered(**changes):
    return json.dumps(dict(a, **changes), sort_keys=True).encode()
check("altered digest", auditor.verify(tampered(digest="f" * 64))[1], "invalid")
check("altered target", auditor.verify(tampered(target="/workspace/reports/x.md"))[1], "invalid")
check("signature moved from another file", auditor.verify(tampered(sig=json.loads(other)["sig"]))[1], "invalid")
attacker = KeyRing.generate()
forged = json.loads(attacker.sign("r1", "/workspace/reports/a.md", "d" * 64))
check("attacker's signature under the broker's key id",
      auditor.verify(json.dumps(dict(forged, kid=broker.active), sort_keys=True).encode())[1], "invalid")
try:
    auditor.sign("r9", "/workspace/reports/z.md", "0" * 64); signed = True
except PermissionError:
    signed = False
check("the verify-only ring can sign", signed, False)

print("3. rotation")
old_kid = broker.active
broker.rotate()
check("new key id", broker.active != old_kid, True)
check("old attestation still verifies (after rotation, with the new public ring)",
      broker.public_only().verify(att)[1], None)
check("new attestations are signed under the new key",
      json.loads(broker.sign("r3", "/workspace/reports/c.md", "1" * 64))["kid"] == broker.active, True)

print("4. an unknown key is not the same finding as a forgery")
check("attacker's own key id", auditor.verify(json.dumps(forged, sort_keys=True).encode())[1], "unknown key")

print("5. persistence")
d = tempfile.mkdtemp()
priv, pub = os.path.join(d, "broker.key"), os.path.join(d, "broker.pub.json")
broker.save(priv, pub)
check("private key file is owner-only", oct(stat.S_IMODE(os.stat(priv).st_mode)), "0o600")
seed = open(priv, "rb").read()
check("public ring file contains no private material", seed.hex() in open(pub).read(), False)
reloaded = KeyRing.load(priv, pub)
check("reloaded ring verifies the pre-rotation attestation", reloaded.verify(att)[1], None)
check("an auditor loading only the public file verifies it", KeyRing.load(None, pub).verify(att)[1], None)

print(f"\n{sum(results)}/{len(results)} predictions confirmed")
sys.exit(0 if all(results) else 1)
