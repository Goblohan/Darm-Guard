"""DARM Broker (DARM Guard v0.5, stage 1). Implements darm-monitor's B1 model.

The agent sends proposals: {"tool": str, "args": [[key, value], ...]}.
Nothing else is accepted. There is no provenance field, and a proposal
carrying extra fields is refused, not ignored (P-integrity). The broker
assigns provenance from a registry the principal controls, builds ONE
canonical invocation, asks the kernel, and executes that same frozen
invocation only if admitted (A1). Every decision goes to a hash-chained
audit log together with the invocation's hash.

Not proved: this Python file (B1 is the specification; correspondence is
tested, not proved), the filesystem, and complete mediation (A2), which
depends on how the broker is deployed.

Domain rule (outside B1, fail-closed): path arguments must already be in
normal form. Kernel prefix rules compare strings, so "/workspace/../etc"
would pass a "/workspace/" prefix. The broker rejects such values before
the kernel sees them, and re-checks the real path before touching disk.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import socketserver
import ctypes
import fcntl
import struct
import stat
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

from .kernel import KernelClient

PATH_KEYS = ("path",)
LOGICAL_ROOT = "/workspace/"


def _fsync_dir(path: str) -> None:
    """Durably persist the directory entry containing path."""
    fd = os.open(os.path.dirname(path) or ".", os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@dataclass(frozen=True)
class BrokerConfig:
    policy: dict                    # kernel JSON policy
    credential_tools: Tuple[str, ...]
    registry: frozenset             # values the principal registered
    workspace: str                  # real directory behind /workspace/
    issued_at: Optional[datetime] = None   # credential lifetime start
    ttl_seconds: Optional[float] = None    # credential lifetime length
    patterns: Tuple[str, ...] = ()         # registry prefixes: values yield 'derived'

    @staticmethod
    def load(config_path: str, registry_path: str) -> "BrokerConfig":
        cfg = json.load(open(config_path))
        lines = [line.strip() for line in open(registry_path) if line.strip()]
        reg = [l for l in lines if not l.endswith("*")]
        pats = tuple(l[:-1] for l in lines if l.endswith("*"))
        issued = cfg.get("issued_at")
        return BrokerConfig(cfg["policy"], tuple(cfg["credential_tools"]),
                            frozenset(reg), os.path.realpath(cfg["workspace"]),
                            datetime.fromisoformat(issued) if issued else None,
                            cfg.get("ttl_seconds"), pats)

    def expired(self, now: Optional[datetime] = None) -> bool:
        if self.issued_at is None or self.ttl_seconds is None:
            return False
        now = now or datetime.now(self.issued_at.tzinfo)
        return (now - self.issued_at).total_seconds() > self.ttl_seconds


def sha256_file(path: str) -> str:
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def _target_state(path: str):
    """Observe a filesystem target for B5 reconciliation.

    Returns:
      ("absent", None) when the target does not exist.
      ("present", sha256) when the target is a regular file.
      ("unavailable", error) when the target cannot be observed safely.
    """
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return ("absent", None)
    except OSError as e:
        return ("unavailable", f"{type(e).__name__}: {e}")

    if not os.path.isfile(path):
        return ("unavailable", "target is not a regular file")

    try:
        return ("present", sha256_file(path))
    except OSError as e:
        return ("unavailable", f"{type(e).__name__}: {e}")


def _intended_state(inv: dict):
    """Derive the B5 intended target state from the frozen invocation.

    Defined for write_file (target present with the content's digest) and
    delete_file (target absent). The intended content comes from
    the canonical invocation, never from the post-effect filesystem state.
    """
    if inv.get("tool") == "delete_file":
        args = {a["key"]: a["value"] for a in inv["args"]}
        return ("absent", None) if isinstance(args.get("path"), str) else None
    if inv.get("tool") != "write_file":
        return None

    args = {a["key"]: a["value"] for a in inv["args"]}
    path = args.get("path")
    content = args.get("content")

    if not isinstance(path, str) or not isinstance(content, str):
        return None

    return ("present", hashlib.sha256(content.encode()).hexdigest())


def _reconcile(before, intended, observed):
    """Classify observed target state against the B5 receipt."""
    if observed[0] == "unavailable":
        return "unresolved"
    if intended is not None and observed == intended:
        return "confirmedSuccess"
    if before is not None and before != intended and observed == before:
        return "confirmedFailure"
    return "unresolved"


def parse_proposal(obj) -> Optional[Tuple[str, List[Tuple[str, str]]]]:
    """Accept exactly {"tool": str, "args": [[str, str], ...]}; anything else is None."""
    if not isinstance(obj, dict) or set(obj) != {"tool", "args"}:
        return None
    tool, args = obj["tool"], obj["args"]
    if not isinstance(tool, str) or not isinstance(args, list):
        return None
    out = []
    for kv in args:
        if not (isinstance(kv, list) and len(kv) == 2 and all(isinstance(x, str) for x in kv)):
            return None
        out.append((kv[0], kv[1]))
    if len({k for k, _ in out}) != len(out):
        return None   # duplicate keys: decided and executed could diverge
    return tool, out


def path_in_normal_form(value: str) -> bool:
    return (value.startswith("/") and os.path.normpath(value) == value
            and ".." not in value.split("/"))


def assign_prov(registry: frozenset, value: str, patterns=()) -> str:
    """B2a assignProv: the broker, not the agent, decides provenance.
    Exact registered values are authoritative; values matching a
    registered pattern are derived; anything else is untrusted."""
    if value in registry:
        return "authoritative"
    if any(value.startswith(p) for p in patterns):
        return "derived"
    return "untrusted"


def canonicalize(cfg: BrokerConfig, tool: str, args) -> dict:
    """B1 canonicalize: one invocation, provenance assigned by the broker."""
    return {"tool": tool,
            "args": [{"key": k, "value": v, "prov": assign_prov(cfg.registry, v, cfg.patterns)}
                     for k, v in args]}


def invocation_hash(inv: dict) -> str:
    return hashlib.sha256(json.dumps(inv, sort_keys=True).encode()).hexdigest()


class AuditLog:
    """Append-only JSON lines; each entry carries the hash of the previous one,
    so an edited or deleted entry breaks the chain."""

    def __init__(self, path: str):
        self.path = path
        self.prev = "0" * 64
        self.last_ts = None
        self._lock = threading.Lock()
        if os.path.exists(path):
            for n, line in enumerate(open(path)):
                if not line.strip():
                    continue
                e = json.loads(line)
                h = e.pop("entry_hash")
                body = hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest()
                if e.get("prev_hash") != self.prev or body != h:
                    raise RuntimeError(f"audit chain broken at entry {n}: refusing to start")
                self.prev = h
                if e.get("ts"):
                    ts = datetime.fromisoformat(e["ts"])
                    self.last_ts = max(self.last_ts, ts) if self.last_ts else ts

    def append(self, entry: dict) -> None:
        with self._lock:
            now = datetime.now()
            entry = dict(entry, prev_hash=self.prev, ts=now.isoformat())
            self.last_ts = max(self.last_ts, now) if self.last_ts else now
            h = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
            entry["entry_hash"] = h
            with open(self.path, "a") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self.prev = h


def _real_in_workspace(cfg: BrokerConfig, path: str) -> Optional[str]:
    """Second layer: map /workspace/... onto the real directory, resolve
    symlinks, and refuse anything that lands outside it."""
    if not path.startswith(LOGICAL_ROOT):
        return None
    real = os.path.realpath(os.path.join(cfg.workspace, path[len(LOGICAL_ROOT):]))
    return real if real == cfg.workspace or real.startswith(cfg.workspace + os.sep) else None


_ESCAPE = {"error": "path escapes workspace or crosses a symlink"}

_libc = ctypes.CDLL(None, use_errno=True)
_RENAME_NOREPLACE, _RENAME_EXCHANGE = 1, 2
_HAS_RENAMEAT2 = hasattr(_libc, "renameat2")


def _renameat2(pfd: int, src: str, dst: str, flags: int, dst_fd=None) -> None:
    if not hasattr(_libc, "renameat2"):
        raise NotImplementedError("renameat2 unavailable")
    dfd = pfd if dst_fd is None else dst_fd
    if _libc.renameat2(pfd, src.encode(), dfd, dst.encode(), flags) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def _digest_at(pfd: int, name: str) -> str:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=pfd)
    with os.fdopen(fd, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _cas_replace(pfd: int, tmp: str, leaf: str, expected):
    """Compare-and-swap against the recorded before-state (fixes probe P2).
    Present target: atomically EXCHANGE, inspect what was displaced, and
    exchange back if it was not the recorded state (the foreign change is
    restored). Absent target: rename with NOREPLACE. Returns None on success,
    or a conflict message. Falls back to compare-then-rename, which has a
    small window, only when renameat2 is unavailable."""
    if expected is None or expected[0] == "unavailable":
        os.replace(tmp, leaf, src_dir_fd=pfd, dst_dir_fd=pfd)
        return None
    try:
        if expected[0] == "absent":
            try:
                _renameat2(pfd, tmp, leaf, _RENAME_NOREPLACE)
            except FileExistsError:
                os.unlink(tmp, dir_fd=pfd)
                return "conflict: target appeared since it was recorded; write not applied"
            return None
        _renameat2(pfd, tmp, leaf, _RENAME_EXCHANGE)
        if _digest_at(pfd, tmp) != expected[1]:
            _renameat2(pfd, tmp, leaf, _RENAME_EXCHANGE)
            os.unlink(tmp, dir_fd=pfd)
            return ("conflict: target changed since it was recorded; "
                    "the change was restored and the write not applied")
        os.unlink(tmp, dir_fd=pfd)
        return None
    except NotImplementedError:
        current = _leaf_state(pfd, leaf)
        if current != tuple(expected):
            os.unlink(tmp, dir_fd=pfd)
            return "conflict (fallback check): target changed since it was recorded"
        os.replace(tmp, leaf, src_dir_fd=pfd, dst_dir_fd=pfd)
        return None


def _cas_delete(pfd: int, leaf: str, expected):
    """Compare-and-delete against the recorded before-state, by the same
    exchange-inspect-undo pattern as writes. The target is renamed (NOREPLACE)
    to a private name in the same directory; what was actually moved is then
    inspected, and unlinked only if it is the recorded state. Otherwise it is
    renamed back (the foreign change is restored) and nothing is deleted.
    Returns None on success, or an error or conflict message. Without
    renameat2, falls back to check-then-unlink, which has a small window."""
    if expected is None or expected[0] != "present":
        return "target absent or not a regular file; nothing deleted"
    tmp = f".{leaf}.darm-tmp-del-{uuid.uuid4().hex}"
    try:
        _renameat2(pfd, leaf, tmp, _RENAME_NOREPLACE)
    except FileNotFoundError:
        return "conflict: target disappeared since it was recorded; nothing deleted"
    except NotImplementedError:
        if _leaf_state(pfd, leaf) != tuple(expected):
            return "conflict (fallback check): target changed since it was recorded; nothing deleted"
        os.unlink(leaf, dir_fd=pfd)
        return None
    if _leaf_kind(pfd, tmp) != stat.S_IFREG or _digest_at(pfd, tmp) != expected[1]:
        try:
            _renameat2(pfd, tmp, leaf, _RENAME_NOREPLACE)
        except FileExistsError:
            return (f"conflict: target changed and its name was re-created; "
                    f"the displaced file is kept as {tmp}; nothing deleted")
        return ("conflict: target changed since it was recorded; "
                "the change was restored and nothing deleted")
    os.unlink(tmp, dir_fd=pfd)
    return None


def _set_att(pfd: int, name: str, value) -> None:
    """Set (or, for None, remove) a file's attestation, by handle."""
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=pfd)
    try:
        if value is None:
            try:
                os.removexattr(fd, XATTR)
            except OSError:
                pass
        else:
            os.setxattr(fd, XATTR, value.encode() if isinstance(value, str) else value)
    finally:
        os.close(fd)


def _rename_protocol(sfd, sleaf, dfd, dleaf, expected, attest, private, old_att):
    """B9: claim, inspect, re-attest, place. The private name and the original
    attestation are named in the prepared record before the claim, so a crash
    at any step leaves the file where the evidence points. Returns None on
    success, or an error or conflict message. No fallback without renameat2."""
    if expected is None or expected[0] != "present":
        return "source absent or not a regular file; nothing renamed"
    if not private:
        return "no private name recorded; nothing renamed"
    try:
        _renameat2(sfd, sleaf, private, _RENAME_NOREPLACE)                    # 1. claim
    except FileNotFoundError:
        return "conflict: source disappeared since it was recorded; nothing renamed"
    except NotImplementedError:
        return "renameat2 unavailable: rename is not supported without it; nothing renamed"
    if _leaf_kind(sfd, private) != stat.S_IFREG or _digest_at(sfd, private) != expected[1]:
        _renameat2(sfd, private, sleaf, _RENAME_NOREPLACE)                    # 2. inspect: restore
        return "conflict: source changed since it was recorded; the change was restored and nothing renamed"
    if attest is not None:                                                     # 3. re-attest
        key, rid, target = attest
        _set_att(sfd, private, _attestation(key, rid, target, expected[1]))
    try:
        _renameat2(sfd, private, dleaf, _RENAME_NOREPLACE, dst_fd=dfd)        # 4. place
    except FileExistsError:
        _renameat2(sfd, private, sleaf, _RENAME_NOREPLACE)   # move first (B9: all or nothing)
        _set_att(sfd, sleaf, old_att)                        # then restore our evidence
        return ("conflict: destination exists; the source was restored with its "
                "original attestation and nothing renamed")
    os.fsync(sfd)
    os.fsync(dfd)
    return None


def _read_attestation(cfg, path: str):
    """The file's current attestation as text, or None."""
    opened = _open_parent(cfg, path)
    if opened is None:
        return None
    pfd, leaf = opened
    try:
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=pfd)
        try:
            return os.getxattr(fd, XATTR).decode()
        finally:
            os.close(fd)
    except OSError:
        return None
    finally:
        os.close(pfd)


def _leaf_state(pfd: int, leaf: str):
    kind = _leaf_kind(pfd, leaf)
    if kind is None:
        return ("absent", None)
    if kind != stat.S_IFREG:
        return ("unavailable", "target is not a regular file")
    return ("present", _digest_at(pfd, leaf))


XATTR = "user.darm"


def _attestation(key: bytes, rid: str, target: str, digest: str) -> bytes:
    """What a governed file carries (Phase 3: the world points at the log):
    the request that wrote it, and a MAC only the broker's key can produce."""
    mac = hmac.new(key, f"{rid}|{target}|{digest}".encode(), hashlib.sha256).hexdigest()
    return json.dumps({"rid": rid, "target": target, "digest": digest, "mac": mac},
                      sort_keys=True).encode()


def _check_attestation(key: bytes, raw: bytes):
    try:
        a = json.loads(raw)
        mac = hmac.new(key, f"{a['rid']}|{a['target']}|{a['digest']}".encode(),
                       hashlib.sha256).hexdigest()
        return a if hmac.compare_digest(mac, a.get("mac", "")) else None
    except (ValueError, KeyError, TypeError):
        return None


def _open_parent(cfg: BrokerConfig, path: str):
    """Race-free resolution (fixes probe P1): open the workspace, then each
    directory on the path relative to the previous handle, never following
    symlinks. Returns (dir_fd, leaf); the caller closes dir_fd. None if the
    path leaves the workspace, crosses a symlink, or a directory is missing.
    Checking IS opening, so a later swap cannot redirect the operation."""
    if not path.startswith(LOGICAL_ROOT):
        return None
    parts = path[len(LOGICAL_ROOT):].split("/")
    if not parts or any(p in ("", ".", "..") for p in parts):
        return None
    fd = os.open(cfg.workspace, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for comp in parts[:-1]:
            nxt = os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
    except OSError:
        os.close(fd)
        return None
    return fd, parts[-1]


def _leaf_kind(pfd: int, leaf: str):
    try:
        return stat.S_IFMT(os.stat(leaf, dir_fd=pfd, follow_symlinks=False).st_mode)
    except FileNotFoundError:
        return None


def _observe(cfg: BrokerConfig, path: str):
    """B5 target observation through the same race-free resolution."""
    opened = _open_parent(cfg, path)
    if opened is None:
        return ("unavailable", "path escapes workspace or crosses a symlink")
    pfd, leaf = opened
    try:
        kind = _leaf_kind(pfd, leaf)
        if kind is None:
            return ("absent", None)
        if kind != stat.S_IFREG:
            return ("unavailable", "target is not a regular file")
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=pfd)
        with os.fdopen(fd, "rb") as f:
            return ("present", hashlib.sha256(f.read()).hexdigest())
    except OSError as e:
        return ("unavailable", f"{type(e).__name__}: {e}")
    finally:
        os.close(pfd)


def _execute(cfg: BrokerConfig, inv: dict, expected=None, attest=None,
             private=None, old_att=None) -> dict:
    """Run an admitted invocation through handles pinned at resolution time."""
    args = {a["key"]: a["value"] for a in inv["args"]}
    opened = _open_parent(cfg, args.get("path", ""))
    if opened is None:
        return dict(_ESCAPE)
    pfd, leaf = opened
    try:
        if _leaf_kind(pfd, leaf) == stat.S_IFLNK:
            return dict(_ESCAPE)
        if inv["tool"] == "read_file":
            fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=pfd)
            with os.fdopen(fd) as f:
                return {"content": f.read()}
        if inv["tool"] == "write_file":
            content = args.get("content", "")
            tmp = f".{leaf}.darm-tmp-{uuid.uuid4().hex}"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644,
                         dir_fd=pfd)
            with os.fdopen(fd, "w") as f:
                f.write(content)
                f.flush()
                attested = False
                if attest is not None:
                    try:
                        os.setxattr(f.fileno(), XATTR, _attestation(
                            *attest, hashlib.sha256(content.encode()).hexdigest()))
                        attested = True
                    except OSError:
                        attested = False   # filesystem without user xattrs
                os.fsync(f.fileno())
            conflict = _cas_replace(pfd, tmp, leaf, expected)
            if conflict:
                return {"error": conflict, "conflict": True}
            os.fsync(pfd)
            return {"written": len(content), "attested": attested}
        if inv["tool"] == "rename_file":
            if args.get("destination") == args.get("path"):
                # outside B9's model (its slots are distinct), and recovery could
                # not tell a finished self-rename from an interrupted roll-back
                return {"error": "source and destination are the same; nothing renamed"}
            dopened = _open_parent(cfg, args.get("destination", ""))
            if dopened is None:
                return dict(_ESCAPE)
            dfd, dleaf = dopened
            try:
                if _leaf_kind(dfd, dleaf) == stat.S_IFLNK:
                    return dict(_ESCAPE)
                err = _rename_protocol(pfd, leaf, dfd, dleaf, expected, attest, private, old_att)
            finally:
                os.close(dfd)
            if err:
                return {"error": err, "conflict": err.startswith("conflict")}
            return {"renamed": True, "attested": attest is not None}
        if inv["tool"] == "delete_file":
            conflict = _cas_delete(pfd, leaf, expected)
            if conflict:
                return {"error": conflict, "conflict": conflict.startswith("conflict")}
            os.fsync(pfd)
            return {"deleted": True}
        if inv["tool"] == "list_dir":
            fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=pfd)
            try:
                return {"entries": sorted(os.listdir(fd))}
            finally:
                os.close(fd)
    except OSError as e:
        return {"error": f"{type(e).__name__}: {e.strerror}"}
    finally:
        os.close(pfd)
    return {"error": "no implementation for tool"}

def _basis(resp: dict) -> list:
    """Phase 4: each response carries the evidence basis of its own claims:
    the darm-monitor theorems and THREAT_MODEL.md assumptions each rests on.
    A claim with no theorem behind it says so, so no claim travels without
    its support."""
    out = []

    def claim(text, theorems, assumptions):
        out.append({"claim": text, "theorems": theorems, "assumptions": assumptions})

    d, eff, fail = resp.get("decision"), resp.get("effect"), resp.get("failure")
    certified = ["kernel binary certified against K4 on 1,000 answers, not proved"]
    if fail in ("temporal", "observation", "authority", "semantic", "provenance"):
        claim(f"rejected by the kernel ({fail})",
              ["DARM.Kernel.admit_sound", "DARM.Kernel4.k4_conservative_extension"], ["A2"] + certified)
    elif fail == "intent":
        claim("no principal-held intent for this action", ["DARM.E24.execution_requires_intent"], ["A2"])
    elif fail == "clock":
        claim("the clock reads earlier than the audit log's last record", [],
              ["A6: witnessed by the audit log, not proved"])
    if d == "admit" and eff != "already_applied":
        claim("admitted by the kernel; the executed invocation is the decided one",
              ["DARM.Kernel.admit_sound", "DARM.Broker3.executed_is_canonical"],
              ["A2"] + certified + ["broker certified against B3 on sampled inputs, not proved"])
    if resp.get("intent_consumed"):
        claim("one principal-held intent was consumed", ["DARM.E24.execution_requires_intent"], ["A2", "A5"])
    if d == "admit" and eff in ("succeeded", "failed", "unknown"):
        claim("a durable prepared record preceded any effect", ["DARM.Lifecycle.no_silent_effect_ever"], ["A3"])
    if eff == "succeeded" and "written" in resp:
        claim("the write applied from the recorded before-state",
              ["DARM.EffectIntegrity.cas_applies_iff"],
              ["A4", "renameat2 available: no window" if _HAS_RENAMEAT2 else
               "renameat2 unavailable: compare-then-rename fallback, small window, not covered by B6"])
    if eff == "succeeded" and resp.get("deleted"):
        claim("the target is absent, and verification will not flag this deletion",
              ["DARM.EffectIntegrity2.legitimate_ops_never_flagged"], ["A4"])
        claim("deleted only from the recorded before-state",
              ["DARM.EffectIntegrity.casOpt_applies_iff", "DARM.EffectIntegrity.delete_only_from_recorded"],
              ["A4", "the compare-and-delete implementation is tested against the model, not certified",
               "renameat2 available: no window" if _HAS_RENAMEAT2 else
               "renameat2 unavailable: check-then-unlink fallback, small window"])
    if eff == "succeeded" and resp.get("renamed"):
        claim("the file moved to the destination, re-attested under this request; "
              "verification will not flag the source or the destination",
              ["DARM.EffectIntegrity2.rename_preserves",
               "DARM.EffectIntegrity2.legitimate_ops_never_flagged"], ["A4"])
        claim("claimed, inspected, re-attested and placed: at no step was the file lost or duplicated",
              ["DARM.RenameProtocol.our_file_never_lost_or_duplicated",
               "DARM.RenameProtocol.recovery_normal"],
              ["A4", "no foreign process guesses the private name",
               "the implementation is tested against B9, not certified"])
    if resp.get("conflict"):
        claim("conflict: the foreign state was left intact", ["DARM.EffectIntegrity.cas_conflict_preserves"], ["A4"])
    if resp.get("reconciliation") == "confirmedSuccess":
        claim("the target is in the intended state (state correspondence, not causation)",
              ["DARM.EffectReconciliation.success_is_state_confirmation"], ["A5"])
    if resp.get("attested"):
        claim("the written file attests this request, verifiable later against the log",
              ["DARM.EffectIntegrity.writes_honest", "DARM.EffectIntegrity.tamper_detected",
               "DARM.EffectIntegrity.truncation_detected"], ["A2: the attestation key is secret"])
    if eff == "already_applied":
        claim("already applied: the original attempt's effect occurred, and this retry performed none",
              ["DARM.Idempotency2.already_applied_sound", "DARM.Idempotency2.at_most_once_with_failures"],
              ["A5", "reconciliation verdicts map to key states: tested, not modelled; "
               "confirmedSuccess is state correspondence, not attribution"])
    if "earlier attempt with this idempotency key failed" in (resp.get("error") or ""):
        claim("an earlier attempt with this key failed; nothing was applied then or now",
              ["DARM.Idempotency2.at_most_once_with_failures"], ["A5"])
    if eff == "unknown":
        claim("effect unknown: the log shows it started; reconcile before retrying",
              ["DARM.Lifecycle.no_silent_effect_ever"], ["A3"])
    if d == "admit":
        claim("no other route to this effect exists", [],
              ["A1: evidenced in the reference deployment and monitored by verify_world, not proved"])
    return out


class Broker:
    """B1 brokerStep: parse -> normal-form check -> canonicalize -> kernel
    -> execute the same invocation if admitted -> audit."""

    def __init__(self, cfg: BrokerConfig, kernel: KernelClient, audit: AuditLog,
                 intents=None, intents_path: Optional[str] = None,
                 key: Optional[bytes] = None):
        self.cfg, self.kernel, self.audit = cfg, kernel, audit
        # E24: principal-held, single-use intents; None means intents are off
        self.intents = list(intents) if intents is not None else None
        self.intents_path = intents_path
        self._lock = threading.Lock()
        self._keys = {}   # idempotency key -> {rid, hash, state, effect}
        self.key = key

    def decide(self, obj, now=None):
        """Pure B1 brokerStep: no execution, no audit.
        Returns (canonical invocation or None, tool or None, response)."""
        parsed = parse_proposal(obj)
        if parsed is None:
            return None, None, {"decision": "reject", "error": "malformed proposal"}
        tool, args = parsed
        for k, v in args:
            if k in PATH_KEYS and not path_in_normal_form(v):
                return None, tool, {"decision": "reject", "error": "path not in normal form"}
        inv = canonicalize(self.cfg, tool, args)
        if self.intents is not None and tool not in self.intents:
            return inv, tool, {"decision": "reject", "failure": "intent", "error": None}
        request = {"policy": self.cfg.policy,
                   "credential": {"tools": list(self.cfg.credential_tools),
                                  "expired": self.cfg.expired(now)},
                   "invocation": inv}
        d = self.kernel.decide(request)
        if not d.admitted:
            return inv, tool, {"decision": "reject", "failure": d.failure, "error": d.error}
        return inv, tool, {"decision": "admit"}

    def handle(self, obj, peer=None) -> dict:
        """Evidence before effect. Never raises: any unexpected failure is
        reported with effect 'unknown' rather than dropping the connection."""
        try:
            resp = self._handle(obj, peer)
            resp["basis"] = _basis(resp)
            return resp
        except Exception as e:
            return {"decision": "error", "effect": "unknown",
                    "error": f"{type(e).__name__}: {e}"}

    def _handle(self, obj, peer=None) -> dict:
        rid = uuid.uuid4().hex
        key = None
        if isinstance(obj, dict) and "idempotency_key" in obj:
            key = obj["idempotency_key"]
            obj = {k: v for k, v in obj.items() if k != "idempotency_key"}
            if not isinstance(key, str) or not key or len(key) > 128:
                return {"decision": "reject", "request_id": rid, "effect": "none",
                        "error": "malformed idempotency key"}
        with self._lock:
            last = self.audit.last_ts
            if last and datetime.now() < last - timedelta(seconds=5):
                resp = {"decision": "reject", "failure": "clock", "request_id": rid,
                        "effect": "none", "peer": peer,
                        "error": "clock rollback detected: earlier than the audit log's last record"}
                try:
                    self._record(rid, "decision", None, None, resp)
                except Exception:
                    pass
                return resp
            inv, tool, resp = self.decide(obj)
            if peer:
                resp = dict(resp, peer=peer)
            if key is not None:
                resp = dict(resp, idempotency_key=key)
                prior = self._keys.get(key)
                if prior is not None:
                    if inv is None or prior["hash"] != invocation_hash(inv):
                        dup = {"decision": "reject", "request_id": rid, "effect": "none",
                               "error": "idempotency key already used for a different invocation"}
                    elif prior["state"] == "done":
                        dup = {"decision": "admit", "request_id": rid, "effect": "already_applied",
                               "original_request_id": prior["rid"],
                               "original_effect": prior.get("effect")}
                    elif prior["state"] == "failed":
                        dup = {"decision": "reject", "request_id": rid, "effect": "none",
                               "error": "an earlier attempt with this idempotency key failed; "
                                        "nothing was applied"}
                    else:
                        dup = {"decision": "reject", "request_id": rid, "effect": "none",
                               "error": "a request with this idempotency key is unresolved"}
                    dup["peer"] = peer
                    try:
                        self._record(rid, "duplicate", inv, tool, dup)
                    except Exception:
                        pass
                    return dup
            if resp["decision"] != "admit":
                resp = dict(resp, request_id=rid, effect="none")
                try:
                    self._record(rid, "decision", inv, tool, resp)
                    resp["evidence"] = "recorded"
                except Exception:
                    resp["evidence"] = "unrecorded"
                return resp
            intended = _intended_state(inv)
            before = None
            real = None
            if intended is not None:
                args = {a["key"]: a["value"] for a in inv["args"]}
                real = args.get("path", "")
                before = _observe(self.cfg, real)
                resp = dict(
                    resp,
                    before_state=before,
                    intended_state=intended,
                    target=real,
                )

            private = None
            if tool == "rename_file":
                args = {a["key"]: a["value"] for a in inv["args"]}
                src, real = args.get("path", ""), args.get("destination", "")
                before = _observe(self.cfg, src)
                intended = (("present", before[1]) if before and before[0] == "present"
                            else ("unavailable", "source is not a present regular file"))
                private = f".{src.rsplit('/', 1)[-1]}.darm-tmp-mv-{uuid.uuid4().hex}"
                resp = dict(resp, before_state=before, intended_state=intended, target=real,
                            source=src, destination_before=_observe(self.cfg, real),
                            private=private, source_attestation=_read_attestation(self.cfg, src))
            try:
                self._record(rid, "prepared", inv, tool, resp)
            except Exception as e:
                return {"decision": "reject", "request_id": rid, "effect": "none",
                        "error": f"evidence unavailable, nothing performed: {type(e).__name__}"}
            if key is not None:
                self._keys[key] = {"rid": rid, "hash": invocation_hash(inv), "state": "pending"}
            if self.intents is not None:
                self.intents.remove(tool)
                self._persist_intents()
                resp = dict(resp, intent_consumed=tool)

        result = _execute(self.cfg, inv, before,
                          (self.key, rid, real) if self.key and intended is not None else None,
                          resp.get("private"), resp.get("source_attestation"))
        ok = "error" not in result

        response_fields = dict(
            request_id=rid,
            executed=ok,
            effect="succeeded" if ok else "failed",
            **result,
        )

        if intended is not None:
            observed = _observe(self.cfg, real)
            response_fields["reconciliation"] = _reconcile(
                before, intended, observed
            )
            response_fields["before_state"] = before
            response_fields["intended_state"] = intended
            response_fields["observed_state"] = observed
            if tool == "rename_file":
                src_now = _observe(self.cfg, resp["source"])
                if observed == tuple(intended) and src_now[0] == "absent":
                    verdict = "confirmedSuccess"
                elif src_now == tuple(before) and observed == tuple(resp["destination_before"]):
                    verdict = "confirmedFailure"
                else:
                    verdict = "unresolved"
                response_fields["reconciliation"] = verdict
                response_fields["source_observed"] = src_now

        resp = dict(resp, **response_fields)
        try:
            self._record(rid, "outcome", inv, tool, resp)
            resp["evidence"] = "recorded"
        except Exception:
            resp["evidence"] = "outcome_unrecorded"   # log shows prepared, no outcome
        if key is not None:
            # B7b: done only if the effect occurred; a failed attempt is failed
            state = "done" if resp.get("effect") == "succeeded" else "failed"
            self._keys[key] = dict(self._keys[key], state=state, effect=resp.get("effect"))
        return resp

    def _record(self, rid, event, inv, tool, response: dict) -> None:
        self.audit.append({
            "event": event,
            "request_id": rid,
            "tool": tool,
            "invocation_hash": invocation_hash(inv) if inv else None,
            "decision": response.get("decision"),
            "effect": response.get("effect"),
            "executed": response.get("executed", False),
            "intent_consumed": response.get("intent_consumed"),
            "reconciliation": response.get("reconciliation"),
            "peer": response.get("peer"),
            "target": response.get("target"),
            "source": response.get("source"),
            "private": response.get("private"),
            "destination_before": response.get("destination_before"),
            "source_attestation": response.get("source_attestation"),
            "idempotency_key": response.get("idempotency_key"),
            "before_state": response.get("before_state"),
            "intended_state": response.get("intended_state"),
            "observed_state": response.get("observed_state"),
            "failure": response.get("failure"),
            "error": response.get("error"),
        })

    def reconcile_pending(self) -> int:
        """Startup reconciliation (fixes probe P3). Every request left
        prepared-without-outcome is observed through the race-free walk and
        classified by B5's rule; the verdict is appended as a 'reconciled'
        record. Also rebuilds the idempotency-key table from the log."""
        if not os.path.exists(self.audit.path):
            return 0
        prepared, closed = {}, {}
        for line in open(self.audit.path):
            if not line.strip():
                continue
            e = json.loads(line)
            rid = e.get("request_id")
            if e.get("event") == "prepared":
                prepared[rid] = e
            elif e.get("event") in ("outcome", "reconciled"):
                closed[rid] = e.get("effect") or e.get("reconciliation")
        n = 0
        for rid, e in prepared.items():
            if rid not in closed:
                target, before, intended = e.get("target"), e.get("before_state"), e.get("intended_state")
                if e.get("tool") == "rename_file":
                    observed, verdict = None, self._recover_rename(e)
                elif target and intended:
                    observed = _observe(self.cfg, target)
                    verdict = _reconcile(tuple(before) if before else None, tuple(intended), observed)
                else:
                    observed, verdict = None, "unresolved"
                self.audit.append({"event": "reconciled", "request_id": rid,
                                   "tool": e.get("tool"), "target": target,
                                   "source": e.get("source"),
                                   "invocation_hash": e.get("invocation_hash"),
                                   "reconciliation": verdict, "observed_state": observed})
                closed[rid] = verdict
                n += 1
            k = e.get("idempotency_key")
            if k:
                v = closed.get(rid)
                state = ("done" if v in ("succeeded", "confirmedSuccess")
                         else "failed" if v in ("failed", "confirmedFailure")
                         else "pending")   # unresolved: never guess
                self._keys[k] = {"rid": rid, "hash": e.get("invocation_hash"),
                                 "state": state, "effect": v}
        return n

    def _recover_rename(self, e) -> str:
        """B9's recover, at startup. Act on the private name the prepared record
        named: the new attestation (this request, naming the destination) and a
        free destination roll forward; anything else rolls back with the original
        attestation. If that cannot complete, the file stays at the private name,
        which the evidence names, and the verdict is unresolved. Then classify
        the pair of paths."""
        src, dst, private = e.get("source"), e.get("target"), e.get("private")
        before, intended = e.get("before_state"), e.get("intended_state")
        sopen, dopen = _open_parent(self.cfg, src or ""), _open_parent(self.cfg, dst or "")
        if sopen is None or dopen is None or not private:
            for o in (sopen, dopen):
                if o:
                    os.close(o[0])
            return "unresolved"
        (sfd, sleaf), (dfd, dleaf) = sopen, dopen
        try:
            if _leaf_kind(sfd, private) is not None:
                raw = None
                try:
                    fd = os.open(private, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=sfd)
                    try:
                        raw = os.getxattr(fd, XATTR)
                    finally:
                        os.close(fd)
                except OSError:
                    pass
                a = _check_attestation(self.key, raw) if (raw and self.key) else None
                reattested = bool(a and a.get("target") == dst and a.get("rid") == e.get("request_id"))
                if reattested and _leaf_kind(dfd, dleaf) is None:
                    _renameat2(sfd, private, dleaf, _RENAME_NOREPLACE, dst_fd=dfd)   # roll forward
                else:
                    # roll back, all or nothing (B9): move first; restore the original
                    # attestation only after the move, and only onto our own content
                    ours = (before and before[0] == "present"
                            and _leaf_kind(sfd, private) == stat.S_IFREG
                            and _digest_at(sfd, private) == before[1])
                    _renameat2(sfd, private, sleaf, _RENAME_NOREPLACE)
                    if ours:
                        _set_att(sfd, sleaf, e.get("source_attestation"))
            elif (before and before[0] == "present"
                  and _leaf_kind(sfd, sleaf) == stat.S_IFREG
                  and _digest_at(sfd, sleaf) == before[1]):
                # re-runnable: a crash after the move back but before the restore
                # leaves our content at the source with the wrong attestation
                if _read_attestation(self.cfg, src) != e.get("source_attestation"):
                    _set_att(sfd, sleaf, e.get("source_attestation"))
                os.fsync(sfd)
                os.fsync(dfd)
        except OSError:
            return "unresolved"
        finally:
            os.close(sfd)
            os.close(dfd)
        src_now, dst_now = _observe(self.cfg, src), _observe(self.cfg, dst)
        if intended and dst_now == tuple(intended) and src_now[0] == "absent":
            return "confirmedSuccess"
        if before and src_now == tuple(before) and dst_now == tuple(e.get("destination_before") or ()):
            return "confirmedFailure"
        return "unresolved"

    def _persist_intents(self) -> None:
        if self.intents_path:
            tmp = self.intents_path + ".tmp"
            with open(tmp, "w") as f:
                f.write("".join(i + "\n" for i in self.intents))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.intents_path)
            _fsync_dir(self.intents_path)


# ---- Server -------------------------------------------------------------

MAX_REQUEST = 1 << 20   # 1 MB per proposal


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            raw_cred = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                               struct.calcsize("3i"))
            pid, uid, gid = struct.unpack("3i", raw_cred)
            peer = {"pid": pid, "uid": uid, "gid": gid}
        except OSError:
            peer = None
        while True:
            raw = self.rfile.readline(MAX_REQUEST + 1)
            if not raw:
                break
            if len(raw) > MAX_REQUEST:
                self._send({"decision": "reject", "effect": "none", "error": "request too large"})
                break
            try:
                obj = json.loads(raw)
            except Exception:
                obj = None
            self._send(self.server.broker.handle(obj, peer))

    def _send(self, resp: dict) -> None:
        self.wfile.write((json.dumps(resp) + "\n").encode())
        self.wfile.flush()


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 64

    def server_close(self):
        super().server_close()
        for fd in getattr(self, "_darm_locks", []):
            os.close(fd)
        self._darm_locks = []


def load_intents(path: str) -> list:
    return [line.strip() for line in open(path) if line.strip()]


def verify_world(cfg: BrokerConfig, audit_path: str, key: bytes) -> dict:
    """Check the world against the log in both directions (Phase 3; probes P8, P9).
    world -> log: each attested file needs a valid MAC for its path, content
    matching its attested digest, and its request present in the log.
    log -> world: each target's latest successful logged write must be the
    one its file attests, and must still exist. Files the broker never wrote
    are not governed and not reported. Limits: filesystems without user
    xattrs carry no attestations; truncation is detectable only for requests
    whose files survive (an effect-free tail needs an external checkpoint)."""
    findings, latest, logged = [], {}, set()
    for line in open(audit_path):
        if not line.strip():
            continue
        e = json.loads(line)
        logged.add(e.get("request_id"))
        if e.get("event") in ("outcome", "reconciled") and e.get("target") and (
                e.get("effect") == "succeeded" or e.get("reconciliation") == "confirmedSuccess"):
            # B8: the latest entry per target is typed (write or delete)
            latest[e["target"]] = (e["request_id"],
                                   "delete" if e.get("tool") == "delete_file" else "write")
            if e.get("tool") == "rename_file" and e.get("source"):
                latest[e["source"]] = (e["request_id"], "delete")
    root = cfg.workspace
    for dirpath, _dirs, files in os.walk(root, followlinks=False):
        for name in files:
            real = os.path.join(dirpath, name)
            if os.path.islink(real) or ".darm-tmp-" in name:
                continue
            logical = LOGICAL_ROOT + os.path.relpath(real, root)
            try:
                raw = os.getxattr(real, XATTR, follow_symlinks=False)
            except OSError:
                if logical in latest:
                    findings.append({"target": logical, "finding":
                        "the log records a broker write here but the file carries no attestation"
                        if latest[logical][1] == "write" else
                        "the log records a deletion but the file exists"})
                continue
            a = _check_attestation(key, raw)
            if a is None or a.get("target") != logical:
                findings.append({"target": logical, "finding": "attestation forged or moved"})
                continue
            if hashlib.sha256(open(real, "rb").read()).hexdigest() != a["digest"]:
                findings.append({"target": logical, "finding": "content changed outside the broker"})
            if a["rid"] not in logged:
                findings.append({"target": logical, "finding":
                    "attested request missing from the log (entries truncated or deleted)"})
            elif logical in latest and latest[logical][1] == "delete":
                findings.append({"target": logical, "finding":
                    "the log records a deletion but the file exists"})
            elif logical in latest and latest[logical][0] != a["rid"]:
                findings.append({"target": logical, "finding":
                    "file does not carry the log's latest write for this target"})
    for target, (_rid, op) in latest.items():
        if op == "write" and not os.path.exists(os.path.join(root, target[len(LOGICAL_ROOT):])):
            findings.append({"target": target, "finding": "the log records a write but the file is gone"})
    return {"ok": not findings, "findings": findings}


def _claim(path: str) -> int:
    """Exclusive ownership of a broker state file (fixes probe P4)."""
    fd = os.open(path + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise RuntimeError(f"{path} is owned by another running broker; refusing to start")
    return fd


def serve(cfg: BrokerConfig, socket_path: str, audit_path: str,
          kernel_path: Optional[str] = None, intents_path: Optional[str] = None) -> _Server:
    locks = [_claim(audit_path)]
    if intents_path:
        try:
            locks.append(_claim(intents_path))
        except RuntimeError:
            os.close(locks[0])
            raise
    if os.path.exists(socket_path):
        os.remove(socket_path)
    srv = _Server(socket_path, _Handler)
    srv._darm_locks = locks
    key_path = audit_path + ".key"
    if not os.path.exists(key_path):
        kfd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(kfd, os.urandom(32))
        os.fsync(kfd)
        os.close(kfd)
    key = open(key_path, "rb").read()
    os.chmod(socket_path, 0o600)
    srv.broker = Broker(cfg, KernelClient(kernel_path), AuditLog(audit_path),
                        load_intents(intents_path) if intents_path else None, intents_path, key)
    srv.broker.reconcile_pending()
    return srv


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(prog="darm-broker",
                                 description="Run the DARM broker (B1 model).")
    ap.add_argument("--config", required=True, help="JSON: policy, credential_tools, workspace")
    ap.add_argument("--registry", required=True, help="principal-registered values, one per line")
    ap.add_argument("--socket", default="/tmp/darm-broker.sock")
    ap.add_argument("--audit", default="darm-broker-audit.jsonl")
    ap.add_argument("--intents", help="principal-held single-use intents, one tool per line (E24)")
    a = ap.parse_args()
    cfg = BrokerConfig.load(a.config, a.registry)
    srv = serve(cfg, a.socket, a.audit, intents_path=a.intents)
    cfg_hash, reg_hash = sha256_file(a.config), sha256_file(a.registry)
    srv.broker.audit.append({"event": "start", "config_sha256": cfg_hash,
                             "registry_sha256": reg_hash})
    print(f"darm-broker listening on {a.socket}")
    print(f"  config sha256   {cfg_hash}")
    print(f"  registry sha256 {reg_hash}")
    srv.serve_forever()


# ---- Agent-side client ----------------------------------------------------

class BrokerClient:
    """What the agent holds: a socket path. No tools, no credentials."""

    def __init__(self, socket_path: str = "/tmp/darm-broker.sock"):
        self.socket_path = socket_path

    def propose(self, tool: str, args: dict) -> dict:
        """Nothing sent: reject (nothing can have happened). Sent, but no
        valid reply: unknown (the effect may have happened)."""
        import socket
        msg = {"tool": tool, "args": [[k, str(v)] for k, v in args.items()]}
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect(self.socket_path)
        except Exception as e:
            return {"decision": "reject", "effect": "none", "error": f"broker unavailable: {e}"}
        try:
            with s:
                s.sendall((json.dumps(msg) + "\n").encode())
                data = b""
                while not data.endswith(b"\n"):
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            return json.loads(data)
        except Exception as e:
            return {"decision": "unknown", "effect": "unknown",
                    "error": f"no valid reply after sending: {e}"}

if __name__ == "__main__":
    main()
