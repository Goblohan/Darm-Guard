from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import FrozenSet, List, Optional
from datetime import datetime, timedelta


class FailureKind(Enum):
    OBSERVATION = auto()
    DOMAIN_COMPLETENESS = auto()
    AUTHORITY = auto()
    TEMPORAL_FRESHNESS = auto()
    SEMANTIC_BOUNDARY = auto()


class DriftLevel(Enum):
    WITHIN = auto()
    DRIFT = auto()
    VIOLATION = auto()


@dataclass(frozen=True)
class FailureWitness:
    kind: FailureKind
    tool: str
    detail: str

    def explain(self) -> str:
        labels = {
            FailureKind.OBSERVATION: "O-failure",
            FailureKind.DOMAIN_COMPLETENESS: "D-failure",
            FailureKind.AUTHORITY: "A-failure",
            FailureKind.TEMPORAL_FRESHNESS: "T-failure",
            FailureKind.SEMANTIC_BOUNDARY: "S-failure",
        }
        return f"{labels[self.kind]}: {self.tool} -- {self.detail}"


@dataclass(frozen=True)
class Credential:
    tools: FrozenSet[str]
    actor: str = ""
    boundary: str = "default"
    issued_at: Optional[datetime] = None
    ttl: Optional[timedelta] = None

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        if self.issued_at is None or self.ttl is None:
            return False
        now = now or datetime.utcnow()
        return now > self.issued_at + self.ttl


@dataclass(frozen=True)
class Policy:
    authorized_tools: FrozenSet[str]
    boundary: str = "default"


@dataclass
class TransferResult:
    admitted: bool
    drift: DriftLevel
    delta: FrozenSet[str] = field(default_factory=frozenset)
    failures: List[FailureWitness] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def __bool__(self) -> bool:
        return self.admitted

    def explain(self) -> str:
        if self.admitted:
            if self.drift == DriftLevel.DRIFT:
                return f"Admitted with drift: {', '.join(sorted(self.delta))} outside credential but authorized."
            return "Admitted: all obligations discharged."
        lines = ["Rejected:"]
        for f in self.failures:
            lines.append(f"  {f.explain()}")
        return "\n".join(lines)
