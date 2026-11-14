"""SDK-A1 response validation contract tests.

These tests specify proposed behavior, not existing broker guarantees.
"""

import unittest

from darm_guard.sdk_response import (
    validate_response,
    InvalidResponse,
)


class ResponseContractTests(unittest.TestCase):

    def test_non_dictionary_responses(self):
        for value in (None, [], "admit", 42):
            with self.subTest(value=value):
                with self.assertRaises(InvalidResponse):
                    validate_response(value)

    def test_missing_decision(self):
        with self.assertRaises(InvalidResponse):
            validate_response({"effect": "none"})

    def test_unknown_decision(self):
        with self.assertRaises(InvalidResponse):
            validate_response({
                "decision": "approved",
                "effect": "succeeded",
            })

    def test_admission_without_effect(self):
        with self.assertRaises(InvalidResponse):
            validate_response({"decision": "admit"})

    def test_admission_with_no_effect(self):
        with self.assertRaises(InvalidResponse):
            validate_response({
                "decision": "admit",
                "effect": "none",
            })

    def test_rejection_cannot_report_success(self):
        with self.assertRaises(InvalidResponse):
            validate_response({
                "decision": "reject",
                "effect": "succeeded",
            })

    def test_broker_error_preserves_uncertainty(self):
        result = validate_response({
            "decision": "error",
            "effect": "unknown",
            "error": "broker exception",
        })
        self.assertEqual(result.decision, "error")
        self.assertEqual(result.effect, "unknown")

    def test_missing_evidence_is_not_recorded(self):
        result = validate_response({
            "decision": "admit",
            "effect": "succeeded",
        })
        self.assertIsNone(result.evidence)

    def test_assurance_assumptions_preserved(self):
        basis = [{
            "claim": "bounded admission",
            "theorems": ["K5"],
            "assumptions": ["A1", "A2"],
        }]
        result = validate_response({
            "decision": "admit",
            "effect": "succeeded",
            "basis": basis,
        })
        self.assertEqual(
            result.basis[0]["assumptions"],
            ("A1", "A2"),
        )


class ResponseHardeningTests(unittest.TestCase):

    def test_empty_request_id_rejected(self):
        with self.assertRaises(InvalidResponse):
            validate_response({
                "decision": "admit",
                "effect": "succeeded",
                "request_id": "",
            })

    def test_explicit_null_basis_rejected(self):
        with self.assertRaises(InvalidResponse):
            validate_response({
                "decision": "admit",
                "effect": "succeeded",
                "basis": None,
            })

    def test_unknown_field_not_silently_trusted(self):
        with self.assertRaises(InvalidResponse):
            validate_response({
                "decision": "admit",
                "effect": "succeeded",
                "fabricated_authority": True,
            })

    def test_assurance_basis_deeply_immutable(self):
        result = validate_response({
            "decision": "admit",
            "effect": "succeeded",
            "basis": [{
                "claim": "example",
                "theorems": ["K5"],
                "assumptions": ["A1"],
            }],
        })

        before = list(result.basis[0]["assumptions"])

        try:
            result.basis[0]["assumptions"].append("MUTATED")
        except (AttributeError, TypeError):
            pass

        self.assertEqual(
            list(result.basis[0]["assumptions"]),
            before,
        )

    def test_reported_success_not_independent_assurance(self):
        result = validate_response({
            "decision": "admit",
            "effect": "succeeded",
        })

        self.assertTrue(result.broker_reported_success)
        self.assertFalse(
            hasattr(result, "confirmed_success"),
            "Broker-reported success must not be named confirmed_success",
        )


class BrokerCompatibilityTests(unittest.TestCase):

    def test_list_dir_response_accepted(self):
        result = validate_response({
            "decision": "admit",
            "effect": "succeeded",
            "request_id": "list-dir-fixture-001",
            "executed": True,
            "entries": ["a.txt", "b.txt"],
            "evidence": "recorded",
            "basis": [],
        })

        self.assertEqual(result.decision, "admit")
        self.assertEqual(result.effect, "succeeded")
        self.assertTrue(result.broker_reported_success)


class HTTPCompatibilityTests(unittest.TestCase):

    def test_success_response_fields_accepted(self):
        result = validate_response({
            "decision": "admit",
            "effect": "succeeded",
            "request_id": "http-fixture-001",
            "status": 200,
            "content_type": "text/plain",
            "body": "fixture",
            "body_sha256": "0" * 64,
            "truncated": False,
            "server": "fixture.example",
            "evidence": "recorded",
            "basis": [],
        })
        self.assertTrue(result.broker_reported_success)

    def test_redirect_response_accepted(self):
        result = validate_response({
            "decision": "admit",
            "effect": "succeeded",
            "request_id": "http-fixture-002",
            "status": 302,
            "content_type": "text/plain",
            "body": "",
            "body_sha256": "0" * 64,
            "truncated": False,
            "server": "fixture.example",
            "location": "/next",
            "redirect": "not followed",
            "basis": [],
        })
        self.assertEqual(result.effect, "succeeded")

    def test_sent_without_answer_stays_unknown(self):
        result = validate_response({
            "decision": "admit",
            "effect": "unknown",
            "request_id": "http-fixture-003",
            "error": "sent, but no complete answer",
            "server": "fixture.example",
            "evidence": "recorded",
            "basis": [],
        })
        self.assertEqual(result.effect, "unknown")
        self.assertFalse(result.broker_reported_success)


class OperationFieldValidationTests(unittest.TestCase):

    def base(self):
        return {
            "decision": "admit",
            "effect": "succeeded",
            "request_id": "field-fixture-001",
        }

    def test_entries_must_be_list(self):
        with self.assertRaises(InvalidResponse):
            validate_response(dict(self.base(), entries="not a list"))

    def test_entries_must_contain_strings(self):
        with self.assertRaises(InvalidResponse):
            validate_response(dict(self.base(), entries=["a.txt", 42]))

    def test_http_status_must_be_integer(self):
        with self.assertRaises(InvalidResponse):
            validate_response(dict(self.base(), status="200"))

    def test_http_status_rejects_boolean(self):
        with self.assertRaises(InvalidResponse):
            validate_response(dict(self.base(), status=True))

    def test_truncated_must_be_boolean(self):
        with self.assertRaises(InvalidResponse):
            validate_response(dict(self.base(), truncated="false"))

    def test_http_body_must_be_string(self):
        with self.assertRaises(InvalidResponse):
            validate_response(dict(self.base(), body=["not", "text"]))

    def test_written_must_be_nonnegative_integer(self):
        with self.assertRaises(InvalidResponse):
            validate_response(dict(self.base(), written=-1))

    def test_executed_must_be_boolean(self):
        with self.assertRaises(InvalidResponse):
            validate_response(dict(self.base(), executed="true"))

    def test_http_digest_format(self):
        with self.assertRaises(InvalidResponse):
            validate_response(dict(self.base(), body_sha256="not-sha256"))

    def test_valid_directory_entries(self):
        result = validate_response(dict(
            self.base(), entries=["a.txt", "b.txt"]
        ))
        self.assertTrue(result.broker_reported_success)

    def test_valid_http_field_types(self):
        result = validate_response(dict(
            self.base(),
            status=200,
            truncated=False,
            body="fixture",
            body_sha256="0" * 64,
        ))
        self.assertTrue(result.broker_reported_success)


class CrossFieldConsistencyTests(unittest.TestCase):

    def test_success_executed_false_rejected(self):
        with self.assertRaises(InvalidResponse):
            validate_response({
                "decision": "admit",
                "effect": "succeeded",
                "executed": False,
            })

    def test_unknown_executed_true_rejected(self):
        with self.assertRaises(InvalidResponse):
            validate_response({
                "decision": "admit",
                "effect": "unknown",
                "executed": True,
            })

    def test_failed_executed_true_rejected(self):
        with self.assertRaises(InvalidResponse):
            validate_response({
                "decision": "admit",
                "effect": "failed",
                "executed": True,
            })

    def test_reject_executed_true_rejected(self):
        with self.assertRaises(InvalidResponse):
            validate_response({
                "decision": "reject",
                "effect": "none",
                "executed": True,
            })

    def test_error_unknown_executed_false(self):
        result = validate_response({
            "decision": "error",
            "effect": "unknown",
            "executed": False,
        })
        self.assertEqual(result.effect, "unknown")

    def test_already_applied_distinct(self):
        result = validate_response({
            "decision": "admit",
            "effect": "already_applied",
            "original_request_id": "original-001",
            "original_effect": "succeeded",
        })
        self.assertFalse(result.broker_reported_success)

    def test_unknown_with_successful_reconciliation(self):
        result = validate_response({
            "decision": "admit",
            "effect": "unknown",
            "reconciliation": "confirmedSuccess",
        })
        self.assertEqual(result.effect, "unknown")
        self.assertFalse(result.broker_reported_success)

    def test_success_with_unrecorded_outcome(self):
        result = validate_response({
            "decision": "admit",
            "effect": "succeeded",
            "executed": True,
            "evidence": "outcome_unrecorded",
        })
        self.assertEqual(result.evidence, "outcome_unrecorded")

    def test_recorded_rejection(self):
        result = validate_response({
            "decision": "reject",
            "effect": "none",
            "evidence": "recorded",
        })
        self.assertEqual(result.effect, "none")

    def test_consistent_success(self):
        result = validate_response({
            "decision": "admit",
            "effect": "succeeded",
            "executed": True,
        })
        self.assertTrue(result.broker_reported_success)


class PayloadPreservationTests(unittest.TestCase):

    def test_directory_entries_preserved(self):
        result = validate_response({
            "decision": "admit",
            "effect": "succeeded",
            "executed": True,
            "entries": ["a.txt", "b.txt"],
        })

        self.assertEqual(
            result.payload["entries"],
            ("a.txt", "b.txt"),
        )
        self.assertIs(result.payload["executed"], True)

    def test_http_body_and_status_preserved(self):
        result = validate_response({
            "decision": "admit",
            "effect": "succeeded",
            "executed": True,
            "status": 200,
            "body": "fixture",
            "content_type": "text/plain",
        })

        self.assertEqual(result.payload["status"], 200)
        self.assertEqual(result.payload["body"], "fixture")
        self.assertEqual(
            result.payload["content_type"],
            "text/plain",
        )

    def test_payload_deeply_immutable(self):
        response = {
            "decision": "admit",
            "effect": "succeeded",
            "executed": True,
            "entries": ["original.txt"],
        }

        result = validate_response(response)

        response["entries"].append("injected.txt")

        self.assertEqual(
            result.payload["entries"],
            ("original.txt",),
        )

        with self.assertRaises(TypeError):
            result.payload["entries"] = ("modified.txt",)

    def test_unknown_effect_payload_not_promoted(self):
        result = validate_response({
            "decision": "admit",
            "effect": "unknown",
            "executed": False,
            "error": "response unavailable",
        })

        self.assertEqual(result.effect, "unknown")
        self.assertFalse(result.broker_reported_success)
        self.assertEqual(
            result.payload["error"],
            "response unavailable",
        )


class PayloadDepthBoundaryTests(unittest.TestCase):

    @staticmethod
    def nested(levels):
        value = "leaf"
        for _ in range(levels):
            value = [value]
        return value

    def test_payload_depth_64_accepted(self):
        result = validate_response({
            "decision": "reject",
            "effect": "none",
            "response": self.nested(63),
        })

        value = result.payload["response"]

        for _ in range(63):
            self.assertIsInstance(value, tuple)
            value = value[0]

        self.assertEqual(value, "leaf")

    def test_payload_depth_65_rejected(self):
        from darm_guard.sdk_response import InvalidResponse

        with self.assertRaisesRegex(
            InvalidResponse,
            "payload nesting limit exceeded",
        ):
            validate_response({
                "decision": "reject",
                "effect": "none",
                "response": self.nested(64),
            })


class NonFinitePayloadTests(unittest.TestCase):
    def test_non_finite_numbers_are_rejected_recursively(self):
        from darm_guard.sdk_response import InvalidResponse, _freeze_payload

        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=repr(value)):
                with self.assertRaises(InvalidResponse):
                    _freeze_payload({"nested": [value]})


if __name__ == "__main__":
    unittest.main()
