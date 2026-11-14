"""Pure DARM SDK response validation.

This module does not authorize or execute effects.

A structurally valid response is not independently authenticated
and does not establish complete mediation.
"""

import re
from types import MappingProxyType
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple


class InvalidResponse(ValueError):
    """Broker response violates the SDK response contract."""


_ALLOWED = {
    "admit": frozenset({
        "succeeded",
        "failed",
        "unknown",
        "already_applied",
    }),
    "reject": frozenset({"none"}),
    "error": frozenset({"unknown"}),
    "unknown": frozenset({"unknown"}),
}

_EVIDENCE = frozenset({
    "recorded",
    "unrecorded",
    "outcome_unrecorded",
})



# Recognized broker response fields at the pinned Track A baseline.
# Compatibility must be checked before production integration.
_KNOWN_FIELDS = frozenset({
    "decision", "effect", "evidence", "basis",
    "request_id", "error", "failure", "peer",
    "executed", "idempotency_key",
    "original_request_id", "original_effect",
    "reconciliation", "intent_reserved",
    "intent_consumed", "intent_state",
    "proposal", "tool", "invocation_hash",
    "before_state", "intended_state",
    "observed_state", "source_observed",
    "destination_before", "target", "source",
    "private", "source_attestation",
    "read_attestation", "attested",
    "written", "deleted", "renamed",
    "conflict", "content", "read", "entries",
    "hash", "status", "body_sha256",
    "content_type", "body", "redirect",
    "truncated", "server", "location",
    "remote", "url", "response",
    "result", "state", "digest",
})


def _freeze_payload(value, depth=0):
    """Copy broker-reported JSON data into immutable containers."""
    if depth > 64:
        raise InvalidResponse("payload nesting limit exceeded")

    if value is None or type(value) in (str, int, float, bool):
        if type(value) is float and (
            value != value
            or value in (float('inf'), float('-inf'))
        ):
            raise InvalidResponse('non-finite payload number')
        return value

    if isinstance(value, list):
        return tuple(
            _freeze_payload(item, depth + 1)
            for item in value
        )

    if isinstance(value, dict):
        if not all(type(k) is str for k in value):
            raise InvalidResponse("invalid payload object keys")

        return MappingProxyType({
            key: _freeze_payload(item, depth + 1)
            for key, item in value.items()
        })

    raise InvalidResponse("unsupported payload value type")


@dataclass(frozen=True)
class DARMResult:
    decision: str
    effect: str
    evidence: Optional[str]
    request_id: Optional[str]
    reconciliation: Optional[str]
    basis: Tuple[Mapping[str, Any], ...]
    payload: Mapping[str, Any]

    @property
    def broker_reported_success(self) -> bool:
        """Unverified broker-reported success, not independent assurance."""
        return (
            self.decision == "admit"
            and self.effect == "succeeded"
        )


def validate_response(value: Any) -> DARMResult:
    """Validate and normalize one broker response.

    Does not authenticate the sender, execute an effect,
    or verify the assurance claims.
    """

    if not isinstance(value, dict):
        raise InvalidResponse("response must be an object")

    if not all(isinstance(k, str) for k in value):
        raise InvalidResponse("response keys must be strings")

    unexpected = set(value) - _KNOWN_FIELDS
    if unexpected:
        raise InvalidResponse("unrecognized response fields")

    decision = value.get("decision")
    effect = value.get("effect")

    if (
        not isinstance(decision, str)
        or decision not in _ALLOWED
    ):
        raise InvalidResponse("invalid decision")

    if (
        not isinstance(effect, str)
        or effect not in _ALLOWED[decision]
    ):
        raise InvalidResponse(
            "invalid decision/effect combination"
        )

    evidence = value.get("evidence")

    if evidence is not None:
        if (
            not isinstance(evidence, str)
            or evidence not in _EVIDENCE
        ):
            raise InvalidResponse("invalid evidence status")

    request_id = value.get("request_id")

    if request_id is not None:
        if not isinstance(request_id, str) or not request_id:
            raise InvalidResponse("invalid request_id")

    reconciliation = value.get("reconciliation")

    if reconciliation is not None:
        if reconciliation not in (
            "confirmedSuccess",
            "confirmedFailure",
            "unresolved",
        ):
            raise InvalidResponse("invalid reconciliation")

    # Operation-specific field validation.
    # These checks validate representation, not causal assurance.

    if "entries" in value:
        entries = value["entries"]
        if (
            not isinstance(entries, list)
            or not all(isinstance(x, str) for x in entries)
        ):
            raise InvalidResponse("invalid entries")

    if "status" in value:
        if type(value["status"]) is not int:
            raise InvalidResponse("invalid HTTP status")

    if "truncated" in value:
        if type(value["truncated"]) is not bool:
            raise InvalidResponse("invalid truncated flag")

    if "body" in value:
        if not isinstance(value["body"], str):
            raise InvalidResponse("invalid HTTP body")

    if "written" in value:
        written = value["written"]
        if type(written) is not int or written < 0:
            raise InvalidResponse("invalid written count")

    if "executed" in value:
        executed = value["executed"]

        if type(executed) is not bool:
            raise InvalidResponse("invalid executed flag")

        # This checks the pinned broker's reported outcome
        # convention, not independently witnessed execution.
        expected_executed = (
            decision == "admit" and effect == "succeeded"
        )

        if executed is not expected_executed:
            raise InvalidResponse(
                "executed flag contradicts decision/effect"
            )

    if "body_sha256" in value:
        digest = value["body_sha256"]
        if (
            not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-fA-F]{64}", digest) is None
        ):
            raise InvalidResponse("invalid body_sha256")

    if "basis" not in value:
        basis = ()
    else:
        raw_basis = value["basis"]
        if not isinstance(raw_basis, list):
            raise InvalidResponse("basis must be a list")

        checked = []

        for item in raw_basis:
            if not isinstance(item, dict):
                raise InvalidResponse("invalid basis entry")

            if not all(
                key in item
                for key in (
                    "claim",
                    "theorems",
                    "assumptions",
                )
            ):
                raise InvalidResponse(
                    "incomplete assurance basis"
                )

            if not isinstance(item["claim"], str):
                raise InvalidResponse("invalid claim")

            for field in ("theorems", "assumptions"):
                entries = item[field]

                if (
                    not isinstance(entries, list)
                    or not all(
                        isinstance(x, str)
                        for x in entries
                    )
                ):
                    raise InvalidResponse(
                        "invalid assurance " + field
                    )

            checked.append(MappingProxyType({
                "claim": item["claim"],
                "theorems": tuple(item["theorems"]),
                "assumptions": tuple(item["assumptions"]),
            }))

        basis = tuple(checked)

    core_fields = {
        "decision",
        "effect",
        "evidence",
        "request_id",
        "reconciliation",
        "basis",
    }

    payload = _freeze_payload({
        key: item
        for key, item in value.items()
        if key not in core_fields
    })

    return DARMResult(
        decision=decision,
        effect=effect,
        evidence=evidence,
        request_id=request_id,
        reconciliation=reconciliation,
        basis=basis,
        payload=payload,
    )
