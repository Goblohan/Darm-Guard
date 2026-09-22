"""DARM Guard kernel-backed runtime.

Every allow/deny decision comes from the DARM decision kernel binary
(darm-monitor K2 `darmkernel`), whose decision function (K1 kernelDecide)
has machine-checked properties. This module only marshals data.

Not proved (trusted computing base): this module, JSON encoding,
argument-to-string conversion, credential expiry computation, the
kernel's JSON parser and I/O loop, and the Lean compiler/runtime.

Fail closed: any failure to obtain a kernel decision is a rejection.
"""
from __future__ import annotations

import json
import os
import select
import subprocess
import sys
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, FrozenSet, List, Optional

from .guard import Mode

PROVENANCES = ("authoritative", "derived", "untrusted")


@dataclass(frozen=True)
class ArgRule:
    """Allow a value if listed exactly or if it starts with an allowed prefix.
    An argument key with no rule is rejected (deny by default)."""
    key: str
    allowed_values: tuple = ()
    allowed_prefixes: tuple = ()

    def to_json(self) -> dict:
        return {"key": self.key,
                "allowedValues": list(self.allowed_values),
                "allowedPrefixes": list(self.allowed_prefixes)}


@dataclass(frozen=True)
class ToolRule:
    tool: str
    rules: tuple = ()

    def to_json(self) -> dict:
        return {"tool": self.tool, "rules": [r.to_json() for r in self.rules]}


@dataclass(frozen=True)
class KernelPolicy:
    tools: tuple = ()

    def to_json(self) -> dict:
        return {"tools": [t.to_json() for t in self.tools]}


@dataclass(frozen=True)
class KernelDecision:
    admitted: bool
    failure: Optional[str] = None
    error: Optional[str] = None
    raw: str = ""

    def __bool__(self) -> bool:
        return self.admitted

    def explain(self) -> str:
        if self.admitted:
            return "admitted by kernel"
        if self.error:
            return f"rejected: {self.error}"
        return f"rejected: {self.failure}-failure"


class KernelClient:
    """Talks to a long-running darmkernel process. Contains no decision logic."""

    def __init__(self, path: Optional[str] = None, timeout: float = 5.0):
        self.path = path or os.environ.get("DARM_KERNEL_PATH", "")
        self.timeout = timeout
        self._proc = None
        self._lock = threading.Lock()

    def _start(self) -> None:
        self._proc = subprocess.Popen(
            [self.path], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1)

    def close(self) -> None:
        if self._proc is not None:
            try:
                self._proc.kill()
            except Exception:
                pass
            self._proc = None

    def decide(self, request: dict) -> KernelDecision:
        with self._lock:
            try:
                if not self.path:
                    return KernelDecision(False, error="no kernel path (set DARM_KERNEL_PATH)")
                if self._proc is None or self._proc.poll() is not None:
                    self._start()
                self._proc.stdin.write(json.dumps(request) + "\n")
                self._proc.stdin.flush()
                ready, _, _ = select.select([self._proc.stdout], [], [], self.timeout)
                if not ready:
                    self.close()
                    return KernelDecision(False, error="kernel timeout")
                line = self._proc.stdout.readline()
                if not line:
                    self.close()
                    return KernelDecision(False, error="kernel exited")
                data = json.loads(line)
            except Exception as e:
                self.close()
                return KernelDecision(False, error=f"kernel unavailable: {e}")
        if data.get("decision") == "admit":
            return KernelDecision(True, raw=line.strip())
        return KernelDecision(False, failure=data.get("failure"),
                              error=data.get("error"), raw=line.strip())


class KernelGuard:
    """Invocation-level guard. Decisions come from the DARM kernel."""

    def __init__(self, policy: KernelPolicy, tools, default_provenance: str,
                 mode: Mode = Mode.GOVERN, issued_at: Optional[datetime] = None,
                 ttl: Optional[timedelta] = None,
                 kernel: Optional[KernelClient] = None,
                 kernel_path: Optional[str] = None):
        if default_provenance not in PROVENANCES:
            raise ValueError(f"default_provenance must be one of {PROVENANCES}")
        self.policy = policy
        self.tools: FrozenSet[str] = frozenset(tools)
        self.default_provenance = default_provenance
        self.mode = mode
        self.issued_at = issued_at
        self.ttl = ttl
        self.kernel = kernel or KernelClient(kernel_path)
        self.log: List[dict] = []
        if mode == Mode.OBSERVE:
            print("[DARM] OBSERVE mode: kernel decisions are logged but NEVER enforced.",
                  file=sys.stderr)

    def _expired(self, now: datetime) -> bool:
        if self.issued_at is None or self.ttl is None:
            return False
        return now > self.issued_at + self.ttl

    def check(self, tool: str, args: Dict[str, object],
              provenance: Optional[Dict[str, str]] = None,
              now: Optional[datetime] = None) -> KernelDecision:
        now = now or datetime.utcnow()
        prov = provenance or {}
        invocation = {"tool": tool, "args": [
            {"key": k, "value": str(v), "prov": prov.get(k, self.default_provenance)}
            for k, v in args.items()]}
        request = {"policy": self.policy.to_json(),
                   "credential": {"tools": sorted(self.tools),
                                  "expired": self._expired(now)},
                   "invocation": invocation}
        decision = self.kernel.decide(request)
        self.log.append({"timestamp": now.isoformat(), "tool": tool,
                         "args": invocation["args"], "admitted": decision.admitted,
                         "failure": decision.failure, "error": decision.error})
        if self.mode == Mode.OBSERVE and not decision.admitted:
            print(f"[DARM OBSERVE] would reject {tool}: {decision.explain()}",
                  file=sys.stderr)
            return KernelDecision(True, decision.failure, decision.error, decision.raw)
        return decision

    def close(self) -> None:
        self.kernel.close()
