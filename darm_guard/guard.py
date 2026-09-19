from __future__ import annotations
from enum import Enum, auto
from typing import FrozenSet, Optional, Set
from datetime import datetime
import json
import sys
from .types import Credential, Policy, TransferResult, DriftLevel
from .session import Session


class Mode(Enum):
    OBSERVE = auto()
    GOVERN = auto()
    ENFORCE = auto()


class DARMGuard:
    def __init__(self, policy: Policy, credential: Credential,
                 mode: Mode = Mode.OBSERVE, session_id: str = "",
                 log_file: Optional[str] = None):
        self.policy = policy
        self.credential = credential
        self.mode = mode
        self.session = Session(credential, policy, session_id)
        self._log_file = log_file
        self._stderr_alerts = True

    def check(self, requested_tools: Set[str], now: Optional[datetime] = None) -> TransferResult:
        tools = frozenset(requested_tools)
        result = self.session.check(tools, now)

        if self.mode == Mode.OBSERVE:
            observed_result = TransferResult(
                admitted=True, drift=result.drift,
                delta=result.delta, failures=result.failures, timestamp=result.timestamp,
            )
            self._log_event(result)
            self._alert(result)
            return observed_result

        self._log_event(result)
        self._alert(result)
        return result

    def update_credential(self, new_tools: Set[str]) -> None:
        expanded = self.credential.tools | frozenset(new_tools)
        self.credential = Credential(
            tools=expanded, actor=self.credential.actor,
            boundary=self.credential.boundary,
            issued_at=self.credential.issued_at, ttl=self.credential.ttl,
        )
        self.session.credential = self.credential

    def scope(self) -> dict:
        return self.session.scope_summary()

    def audit(self) -> list:
        return self.session.audit_trail()

    def _log_event(self, result: TransferResult) -> None:
        if self._log_file is None:
            return
        event = self.session.log[-1] if self.session.log else None
        if event is None:
            return
        entry = {
            "timestamp": event.timestamp.isoformat(),
            "mode": self.mode.name,
            "requested": sorted(event.requested_tools),
            "admitted": result.admitted,
            "drift": result.drift.name,
            "failures": [
                {"kind": f.kind.name, "tool": f.tool, "detail": f.detail}
                for f in result.failures
            ],
        }
        try:
            with open(self._log_file, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass

    def _alert(self, result: TransferResult) -> None:
        if not self._stderr_alerts:
            return
        if result.drift == DriftLevel.WITHIN:
            return
        if result.drift == DriftLevel.DRIFT:
            print(f"[DARM DRIFT] {', '.join(sorted(result.delta))} outside credential scope", file=sys.stderr)
        elif result.drift == DriftLevel.VIOLATION:
            for f in result.failures:
                print(f"[DARM REJECT] {f.explain()}", file=sys.stderr)
