"""Attestations v2: Ed25519 signatures over a domain-separated message,
checked against a ring of public keys by key id.

Signing needs the private key; verifying needs only public keys. Rotation
discards the old private key and keeps its public half, so old attestations
keep verifying while nobody, including the broker, can sign under the old key.
Verification distinguishes 'unknown key' (the key id is not in the ring) from
'invalid' (malformed, or a signature that does not verify)."""
import hashlib, json, os
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DOMAIN = "darm-attest-v2"

def _raw_public(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def key_id(public_raw: bytes) -> str:
    return hashlib.sha256(public_raw).hexdigest()[:16]

CHECKPOINT_DOMAIN = "darm-checkpoint-v1"

def _checkpoint_message(genesis: str, count: int, head: str) -> bytes:
    return f"{CHECKPOINT_DOMAIN}|{genesis}|{count}|{head}".encode()

def _message(rid: str, target: str, digest: str) -> bytes:
    return f"{DOMAIN}|{rid}|{target}|{digest}".encode()


class KeyRing:
    def __init__(self, private=None, publics=None):
        self._private = private
        self.publics = dict(publics or {})       # key id -> raw public key
        self.active = None
        if private is not None:
            raw = _raw_public(private.public_key())
            self.active = key_id(raw)
            self.publics[self.active] = raw

    @classmethod
    def generate(cls) -> "KeyRing":
        return cls(Ed25519PrivateKey.generate())

    def rotate(self) -> None:
        """A new signing key. The old private key is discarded; its public key stays."""
        self._private = Ed25519PrivateKey.generate()
        raw = _raw_public(self._private.public_key())
        self.active = key_id(raw)
        self.publics[self.active] = raw

    def public_only(self) -> "KeyRing":
        """What an outside verifier holds: every public key, no private key."""
        return KeyRing(None, self.publics)

    def can_sign(self) -> bool:
        return self._private is not None

    def sign(self, rid: str, target: str, digest: str) -> bytes:
        if self._private is None:
            raise PermissionError("a verify-only ring cannot sign")
        sig = self._private.sign(_message(rid, target, digest))
        return json.dumps({"v": 2, "rid": rid, "target": target, "digest": digest,
                           "kid": self.active, "sig": sig.hex()}, sort_keys=True).encode()

    def verify(self, raw: bytes):
        """(attestation, None) if valid; otherwise (None, 'unknown key' | 'invalid' | 'not v2')."""
        try:
            a = json.loads(raw)
            if a.get("v") != 2:
                return None, "not v2"
            pub = self.publics.get(a["kid"])
            if pub is None:
                return None, "unknown key"
            Ed25519PublicKey.from_public_bytes(pub).verify(
                bytes.fromhex(a["sig"]), _message(a["rid"], a["target"], a["digest"]))
            return a, None
        except InvalidSignature:
            return None, "invalid"
        except (ValueError, KeyError, TypeError, AttributeError):
            return None, "invalid"

    def sign_checkpoint(self, genesis: str, count: int, head: str) -> dict:
        """Sign an audit log's chain head. A separate domain from attestations,
        so neither kind of signature can be replayed as the other."""
        if self._private is None:
            raise PermissionError("a verify-only ring cannot sign")
        sig = self._private.sign(_checkpoint_message(genesis, count, head))
        return {"v": 1, "genesis": genesis, "count": count, "head": head,
                "kid": self.active, "sig": sig.hex()}

    def verify_checkpoint(self, cp: dict):
        """(True, None) if valid; otherwise (False, 'unknown key' | 'invalid')."""
        try:
            pub = self.publics.get(cp["kid"])
            if pub is None:
                return False, "unknown key"
            Ed25519PublicKey.from_public_bytes(pub).verify(
                bytes.fromhex(cp["sig"]), _checkpoint_message(cp["genesis"], int(cp["count"]), cp["head"]))
            return True, None
        except InvalidSignature:
            return False, "invalid"
        except (ValueError, KeyError, TypeError, AttributeError):
            return False, "invalid"

    def save(self, private_path: str, public_path: str) -> None:
        """The private seed (owner-only) and the public ring (publishable)."""
        if self._private is not None:
            seed = self._private.private_bytes(serialization.Encoding.Raw,
                                               serialization.PrivateFormat.Raw,
                                               serialization.NoEncryption())
            tmp = private_path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.write(fd, seed); os.fsync(fd); os.close(fd)
            os.replace(tmp, private_path)
        with open(public_path + ".tmp", "w") as f:
            json.dump({"active": self.active, "keys": {k: v.hex() for k, v in self.publics.items()}},
                      f, sort_keys=True)
        os.replace(public_path + ".tmp", public_path)

    @classmethod
    def load(cls, private_path: str, public_path: str) -> "KeyRing":
        publics = {}
        if os.path.exists(public_path):
            publics = {k: bytes.fromhex(v) for k, v in json.load(open(public_path))["keys"].items()}
        private = None
        if private_path and os.path.exists(private_path):
            private = Ed25519PrivateKey.from_private_bytes(open(private_path, "rb").read())
        return cls(private, publics)
