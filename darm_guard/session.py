from __future__ import annotations
from dataclasses import dataclass, field
from typing import FrozenSet, List, Optional, Callable
from datetime import datetime
from .types import Credential, Policy, TransferResult, DriftLevel
from .checker import check_transfer


@dataclass
class SessionEvent:
    timestamp: datetime
    requested_tools: FrozenSet[str]
    cumulative_scope: FrozenSet[str]
    result: TransferResult


class Session:
    def __init__(self, credential: Credential, policy: Policy, session_id: str = ""):
        self.credential = credential
        self.policy = policy
        self.session_id = session_id
        self.cumulative_scope: FrozenSet[str] = frozenset()
        self.log: List[SessionEvent] = []
        self._on_drift: Optional[Callable[[SessionEvent], None]] = None
        self._on_violation: Optional[Callable[[SessionEvent], None]] = None

    def on_drift(self, callback: Callable[[SessionEvent], None]) -> None:
        self._on_drift = callback

    def on_violation(self, callback: Callable[[SessionEvent], None]) -> None:
        self._on_violation = callback

    def check(self, requested_tools: FrozenSet[str], now: Optional[datetime] = None) -> TransferResult:
        now = now or datetime.utcnow()
        result = check_transfer(self.credential, requested_tools, self.policy, now)
        new_scope = self.cumulative_scope | requested_tools
        self.cumulative_scope = new_scope

        cumulative_delta = self.cumulative_scope - self.credential.tools
        if cumulative_delta and result.drift == DriftLevel.WITHIN:
            result = TransferResult(
                admitted=result.admitted, drift=DriftLevel.DRIFT,
                delta=result.delta, failures=result.failures, timestamp=result.timestamp,
            )

        event = SessionEvent(
            timestamp=now, requested_tools=requested_tools,
            cumulative_scope=self.cumulative_scope, result=result,
        )
        self.log.append(event)

        if result.drift == DriftLevel.DRIFT and self._on_drift:
            self._on_drift(event)
        if result.drift == DriftLevel.VIOLATION and self._on_violation:
            self._on_violation(event)

        return result

    def scope_summary(self) -> dict:
        delta = self.cumulative_scope - self.credential.tools
        return {
            "session_id": self.session_id,
            "credential_scope": sorted(self.credential.tools),
            "cumulative_scope": sorted(self.cumulative_scope),
            "delta": sorted(delta),
            "drift": bool(delta),
            "call_count": len(self.log),
            "violations": sum(1 for e in self.log if e.result.drift == DriftLevel.VIOLATION),
        }

    def audit_trail(self) -> List[dict]:
        return [
            {
                "timestamp": e.timestamp.isoformat(),
                "requested": sorted(e.requested_tools),
                "cumulative": sorted(e.cumulative_scope),
                "admitted": e.result.admitted,
                "drift": e.result.drift.name,
                "delta": sorted(e.result.delta),
                "failures": [
                    {"kind": f.kind.name, "tool": f.tool, "detail": f.detail}
                    for f in e.result.failures
                ],
            }
            for e in self.log
        ]
