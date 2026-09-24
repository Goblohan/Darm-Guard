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
import json
import os
import socketserver
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Tuple

from .kernel import KernelClient

PATH_KEYS = ("path",)
LOGICAL_ROOT = "/workspace/"


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

    def append(self, entry: dict) -> None:
        with self._lock:
            entry = dict(entry, prev_hash=self.prev)
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


def _execute(cfg: BrokerConfig, inv: dict) -> dict:
    """Run an admitted invocation, reading arguments only from the frozen invocation."""
    args = {a["key"]: a["value"] for a in inv["args"]}
    real = _real_in_workspace(cfg, args.get("path", ""))
    if real is None:
        return {"error": "path escapes workspace (real-path check)"}
    try:
        if inv["tool"] == "read_file":
            with open(real) as f:
                return {"content": f.read()}
        if inv["tool"] == "write_file":
            content = args.get("content", "")
            tmp = f"{real}.darm-tmp-{uuid.uuid4().hex}"
            with open(tmp, "w") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, real)   # atomic: old content or new, never partial
            return {"written": len(content)}
        if inv["tool"] == "list_dir":
            return {"entries": sorted(os.listdir(real))}
    except OSError as e:
        return {"error": f"{type(e).__name__}: {e.strerror}"}
    return {"error": "no implementation for tool"}


class Broker:
    """B1 brokerStep: parse -> normal-form check -> canonicalize -> kernel
    -> execute the same invocation if admitted -> audit."""

    def __init__(self, cfg: BrokerConfig, kernel: KernelClient, audit: AuditLog,
                 intents=None, intents_path: Optional[str] = None):
        self.cfg, self.kernel, self.audit = cfg, kernel, audit
        # E24: principal-held, single-use intents; None means intents are off
        self.intents = list(intents) if intents is not None else None
        self.intents_path = intents_path
        self._lock = threading.Lock()

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

    def handle(self, obj) -> dict:
        """Evidence before effect. Never raises: any unexpected failure is
        reported with effect 'unknown' rather than dropping the connection."""
        try:
            return self._handle(obj)
        except Exception as e:
            return {"decision": "error", "effect": "unknown",
                    "error": f"{type(e).__name__}: {e}"}

    def _handle(self, obj) -> dict:
        rid = uuid.uuid4().hex
        with self._lock:
            inv, tool, resp = self.decide(obj)
            if resp["decision"] != "admit":
                resp = dict(resp, request_id=rid, effect="none")
                try:
                    self._record(rid, "decision", inv, tool, resp)
                    resp["evidence"] = "recorded"
                except Exception:
                    resp["evidence"] = "unrecorded"
                return resp
            try:
                self._record(rid, "prepared", inv, tool, resp)
            except Exception as e:
                return {"decision": "reject", "request_id": rid, "effect": "none",
                        "error": f"evidence unavailable, nothing performed: {type(e).__name__}"}
            if self.intents is not None:
                self.intents.remove(tool)
                self._persist_intents()
                resp = dict(resp, intent_consumed=tool)
        result = _execute(self.cfg, inv)
        ok = "error" not in result
        resp = dict(resp, request_id=rid, executed=ok,
                    effect="succeeded" if ok else "failed", **result)
        try:
            self._record(rid, "outcome", inv, tool, resp)
            resp["evidence"] = "recorded"
        except Exception:
            resp["evidence"] = "outcome_unrecorded"   # log shows prepared, no outcome
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
            "failure": response.get("failure"),
            "error": response.get("error"),
        })

    def _persist_intents(self) -> None:
        if self.intents_path:
            tmp = self.intents_path + ".tmp"
            with open(tmp, "w") as f:
                f.write("".join(i + "\n" for i in self.intents))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.intents_path)


# ---- Server -------------------------------------------------------------

MAX_REQUEST = 1 << 20   # 1 MB per proposal


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
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
            self._send(self.server.broker.handle(obj))

    def _send(self, resp: dict) -> None:
        self.wfile.write((json.dumps(resp) + "\n").encode())
        self.wfile.flush()


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 64


def load_intents(path: str) -> list:
    return [line.strip() for line in open(path) if line.strip()]


def serve(cfg: BrokerConfig, socket_path: str, audit_path: str,
          kernel_path: Optional[str] = None, intents_path: Optional[str] = None) -> _Server:
    if os.path.exists(socket_path):
        os.remove(socket_path)
    srv = _Server(socket_path, _Handler)
    os.chmod(socket_path, 0o600)
    srv.broker = Broker(cfg, KernelClient(kernel_path), AuditLog(audit_path),
                        load_intents(intents_path) if intents_path else None, intents_path)
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
