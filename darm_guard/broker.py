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
from dataclasses import dataclass
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

    @staticmethod
    def load(config_path: str, registry_path: str) -> "BrokerConfig":
        cfg = json.load(open(config_path))
        reg = [line.strip() for line in open(registry_path) if line.strip()]
        return BrokerConfig(cfg["policy"], tuple(cfg["credential_tools"]),
                            frozenset(reg), os.path.realpath(cfg["workspace"]))


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
    return tool, out


def path_in_normal_form(value: str) -> bool:
    return (value.startswith("/") and os.path.normpath(value) == value
            and ".." not in value.split("/"))


def assign_prov(registry: frozenset, value: str) -> str:
    """B1 assignProv: the broker, not the agent, decides provenance."""
    return "authoritative" if value in registry else "untrusted"


def canonicalize(cfg: BrokerConfig, tool: str, args) -> dict:
    """B1 canonicalize: one invocation, provenance assigned by the broker."""
    return {"tool": tool,
            "args": [{"key": k, "value": v, "prov": assign_prov(cfg.registry, v)}
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
            for line in open(path):
                if line.strip():
                    self.prev = json.loads(line)["entry_hash"]

    def append(self, entry: dict) -> None:
        with self._lock:
            entry = dict(entry, prev_hash=self.prev)
            h = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
            entry["entry_hash"] = h
            with open(self.path, "a") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
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
        if inv["tool"] == "list_dir":
            return {"entries": sorted(os.listdir(real))}
    except OSError as e:
        return {"error": f"{type(e).__name__}: {e.strerror}"}
    return {"error": "no implementation for tool"}


class Broker:
    """B1 brokerStep: parse -> normal-form check -> canonicalize -> kernel
    -> execute the same invocation if admitted -> audit."""

    def __init__(self, cfg: BrokerConfig, kernel: KernelClient, audit: AuditLog):
        self.cfg, self.kernel, self.audit = cfg, kernel, audit

    def decide(self, obj):
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
        request = {"policy": self.cfg.policy,
                   "credential": {"tools": list(self.cfg.credential_tools), "expired": False},
                   "invocation": inv}
        d = self.kernel.decide(request)
        if not d.admitted:
            return inv, tool, {"decision": "reject", "failure": d.failure, "error": d.error}
        return inv, tool, {"decision": "admit"}

    def handle(self, obj) -> dict:
        inv, tool, resp = self.decide(obj)
        if resp["decision"] == "admit":
            result = _execute(self.cfg, inv)
            resp = dict(resp, executed="error" not in result, **result)
        return self._record(inv, tool, resp)

    def _record(self, inv, tool, response: dict) -> dict:
        self.audit.append({
            "event": "decision",
            "tool": tool,
            "invocation_hash": invocation_hash(inv) if inv else None,
            "decision": response["decision"],
            "executed": response.get("executed", False),
            "failure": response.get("failure"),
            "error": response.get("error"),
        })
        return response


# ---- Server -------------------------------------------------------------

class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        for raw in self.rfile:
            try:
                obj = json.loads(raw)
            except Exception:
                obj = None
            resp = self.server.broker.handle(obj)
            self.wfile.write((json.dumps(resp) + "\n").encode())
            self.wfile.flush()


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def serve(cfg: BrokerConfig, socket_path: str, audit_path: str,
          kernel_path: Optional[str] = None) -> _Server:
    if os.path.exists(socket_path):
        os.remove(socket_path)
    srv = _Server(socket_path, _Handler)
    os.chmod(socket_path, 0o600)
    srv.broker = Broker(cfg, KernelClient(kernel_path), AuditLog(audit_path))
    return srv


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(prog="darm-broker",
                                 description="Run the DARM broker (B1 model).")
    ap.add_argument("--config", required=True, help="JSON: policy, credential_tools, workspace")
    ap.add_argument("--registry", required=True, help="principal-registered values, one per line")
    ap.add_argument("--socket", default="/tmp/darm-broker.sock")
    ap.add_argument("--audit", default="darm-broker-audit.jsonl")
    a = ap.parse_args()
    cfg = BrokerConfig.load(a.config, a.registry)
    srv = serve(cfg, a.socket, a.audit)
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
        import socket
        msg = {"tool": tool, "args": [[k, str(v)] for k, v in args.items()]}
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect(self.socket_path)
                s.sendall((json.dumps(msg) + "\n").encode())
                data = b""
                while not data.endswith(b"\n"):
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            return json.loads(data)
        except Exception as e:
            return {"decision": "reject", "error": f"broker unavailable: {e}"}


if __name__ == "__main__":
    main()
