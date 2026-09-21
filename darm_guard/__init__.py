"""DARM Guard - agent tool-authorization guard grounded in a machine-checked Lean theory."""

from .types import FailureKind, FailureWitness, DriftLevel, Credential, Policy, TransferResult
from .guard import DARMGuard, Mode
from .session import Session, SessionEvent
from .checker import check_transfer

__version__ = "0.1.1"
__all__ = [
    "DARMGuard", "Mode", "Policy", "Credential", "TransferResult",
    "FailureKind", "FailureWitness", "DriftLevel",
    "Session", "SessionEvent", "check_transfer",
]
