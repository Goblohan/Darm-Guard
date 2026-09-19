from __future__ import annotations
from typing import FrozenSet, Optional, List
from datetime import datetime
from .types import Credential, Policy, FailureKind, FailureWitness, TransferResult, DriftLevel


def check_transfer(
    credential: Credential,
    requested_tools: FrozenSet[str],
    policy: Policy,
    now: Optional[datetime] = None,
) -> TransferResult:
    now = now or datetime.utcnow()
    delta = requested_tools - credential.tools
    failures: List[FailureWitness] = []

    if credential.is_expired(now):
        failures.append(FailureWitness(
            kind=FailureKind.TEMPORAL_FRESHNESS,
            tool="*",
            detail=f"credential expired (issued {credential.issued_at}, ttl {credential.ttl})",
        ))

    unknown_tools = requested_tools - policy.authorized_tools - credential.tools
    for tool in sorted(unknown_tools):
        failures.append(FailureWitness(
            kind=FailureKind.OBSERVATION,
            tool=tool,
            detail=f"not in observation model (unknown to policy at boundary '{policy.boundary}')",
        ))

    for tool in sorted(delta):
        if tool in unknown_tools:
            continue
        if tool not in policy.authorized_tools:
            failures.append(FailureWitness(
                kind=FailureKind.AUTHORITY,
                tool=tool,
                detail=f"not authorized at boundary '{policy.boundary}'",
            ))

    if not delta:
        drift = DriftLevel.WITHIN
    elif not failures:
        drift = DriftLevel.DRIFT
    else:
        drift = DriftLevel.VIOLATION

    return TransferResult(
        admitted=len(failures) == 0,
        drift=drift,
        delta=delta,
        failures=failures,
        timestamp=now,
    )
