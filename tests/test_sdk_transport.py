"""Isolated bounded-transport contract tests.

No DARM broker is started. No governed effects are requested.
"""

import json
import socket
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path

from darm_guard.sdk_transport import BoundedBrokerClient


@contextmanager
def mock_broker(reply):
    """Single-connection synthetic AF_UNIX broker."""
    with tempfile.TemporaryDirectory() as directory:
        path = str(Path(directory) / "mock.sock")

        server = socket.socket(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        )
        server.settimeout(3.0)
        server.bind(path)
        server.listen(1)

        errors = []

        def serve():
            try:
                conn, _ = server.accept()
                with conn:
                    conn.settimeout(3.0)
                    request = b""

                    while not request.endswith(b"\n"):
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        request += chunk

                    if request:
                        json.loads(request)

                    if isinstance(reply, (tuple, list)):
                        for index, chunk in enumerate(reply):
                            conn.sendall(chunk)
                            if index + 1 < len(reply):
                                threading.Event().wait(0.2)
                    elif reply is not None:
                        conn.sendall(reply)
            except Exception as exc:
                errors.append(exc)
            finally:
                server.close()

        thread = threading.Thread(
            target=serve,
            daemon=True,
        )
        thread.start()

        try:
            yield path
        finally:
            thread.join(timeout=4.0)
            if thread.is_alive():
                raise AssertionError("mock server did not terminate")
            if errors:
                raise AssertionError(
                    f"mock server error: {errors!r}"
                )


class BoundedTransportBaselineTests(unittest.TestCase):

    def client(self, path):
        return BoundedBrokerClient(
            socket_path=path,
            max_response_bytes=4 * 1024 * 1024,
            timeout_seconds=2.0,
        )

    def test_A01_connection_unavailable_before_send(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "absent.sock")
            result = self.client(path).propose(
                "read_file", {"path": "fixture"}
            )

        self.assertEqual(result.decision, "reject")
        self.assertEqual(result.effect, "none")

    def test_A03_complete_valid_response(self):
        reply = (
            json.dumps({
                "decision": "admit",
                "effect": "succeeded",
                "executed": True,
            }).encode() + b"\n"
        )

        with mock_broker(reply) as path:
            result = self.client(path).propose(
                "read_file", {"path": "fixture"}
            )

        self.assertEqual(result.decision, "admit")
        self.assertEqual(result.effect, "succeeded")
        self.assertTrue(result.broker_reported_success)

    def test_A04_partial_response_then_eof(self):
        reply = b'{"decision":"admit","effect":"succeeded"}'

        with mock_broker(reply) as path:
            result = self.client(path).propose(
                "read_file", {"path": "fixture"}
            )

        self.assertEqual(result.decision, "unknown")
        self.assertEqual(result.effect, "unknown")
        self.assertFalse(result.broker_reported_success)

    def test_A07_invalid_json_after_submission(self):
        with mock_broker(b"{invalid-json}\n") as path:
            result = self.client(path).propose(
                "read_file", {"path": "fixture"}
            )

        self.assertEqual(result.decision, "unknown")
        self.assertEqual(result.effect, "unknown")
        self.assertFalse(result.broker_reported_success)


class TransportBoundaryTests(unittest.TestCase):

    def test_A05_oversized_response_is_unknown(self):
        reply = (
            b'{"decision":"admit","effect":"succeeded",'
            b'"body":"' + b"x" * 512 + b'"}'
            + bytes([10])
        )

        with mock_broker(reply) as path:
            client = BoundedBrokerClient(
                socket_path=path,
                max_response_bytes=128,
                timeout_seconds=2.0,
            )
            result = client.propose("read_file", {"path": "fixture"})

        self.assertEqual(result.decision, "unknown")
        self.assertEqual(result.effect, "unknown")
        self.assertFalse(result.broker_reported_success)

    def test_A08_invalid_schema_is_unknown(self):
        reply = json.dumps({
            "decision": "reject",
            "effect": "succeeded",
        }).encode() + bytes([10])

        with mock_broker(reply) as path:
            client = BoundedBrokerClient(
                socket_path=path,
                timeout_seconds=2.0,
            )
            result = client.propose("read_file", {"path": "fixture"})

        self.assertEqual(result.decision, "unknown")
        self.assertEqual(result.effect, "unknown")

    def test_A10_exact_response_limit_accepted(self):
        reply = json.dumps({
            "decision": "admit",
            "effect": "succeeded",
            "executed": True,
        }).encode() + bytes([10])

        with mock_broker(reply) as path:
            client = BoundedBrokerClient(
                socket_path=path,
                max_response_bytes=len(reply),
                timeout_seconds=2.0,
            )
            result = client.propose("read_file", {"path": "fixture"})

        self.assertEqual(result.decision, "admit")
        self.assertEqual(result.effect, "succeeded")
        self.assertTrue(result.broker_reported_success)


class TransportDeadlineTests(unittest.TestCase):

    def test_A06_slow_drip_total_deadline(self):
        import time

        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "slow.sock")

            server = socket.socket(
                socket.AF_UNIX, socket.SOCK_STREAM
            )
            server.settimeout(2.0)
            server.bind(path)
            server.listen(1)

            ready = threading.Event()
            errors = []

            def serve():
                ready.set()
                try:
                    conn, _ = server.accept()
                    with conn:
                        conn.settimeout(2.0)
                        request = b""
                        while not request.endswith(bytes([10])):
                            chunk = conn.recv(4096)
                            if not chunk:
                                return
                            request += chunk

                        # Keep sending without terminating the frame.
                        end = time.monotonic() + 1.0
                        while time.monotonic() < end:
                            try:
                                conn.sendall(b"x")
                            except (BrokenPipeError, ConnectionResetError):
                                break
                            time.sleep(0.02)
                except Exception as exc:
                    errors.append(exc)
                finally:
                    server.close()

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            self.assertTrue(ready.wait(1.0))

            client = BoundedBrokerClient(
                socket_path=path,
                max_response_bytes=4096,
                timeout_seconds=0.15,
            )

            start = time.monotonic()
            result = client.propose(
                "read_file", {"path": "fixture"}
            )
            elapsed = time.monotonic() - start

            thread.join(timeout=2.0)

            self.assertFalse(thread.is_alive())
            self.assertFalse(errors, repr(errors))
            self.assertEqual(result.decision, "unknown")
            self.assertEqual(result.effect, "unknown")
            self.assertFalse(result.broker_reported_success)
            self.assertLess(elapsed, 0.75)


class TransportFramingTests(unittest.TestCase):

    def test_A09_trailing_response_data(self):
        valid = json.dumps({
            "decision": "admit",
            "effect": "succeeded",
            "executed": True,
        }).encode()

        # Both frames are supplied together.
        reply = (
            valid + bytes([10])
            + b'{"decision":"reject","effect":"none"}'
            + bytes([10])
        )

        with mock_broker(reply) as path:
            client = BoundedBrokerClient(
                socket_path=path,
                timeout_seconds=2.0,
            )
            result = client.propose(
                "read_file", {"path": "fixture"}
            )

        self.assertEqual(result.decision, "unknown")
        self.assertEqual(result.effect, "unknown")
        self.assertFalse(result.broker_reported_success)


    def test_A09_delayed_trailing_response_data(self):
        valid = json.dumps({
            "decision": "admit",
            "effect": "succeeded",
            "executed": True,
        }).encode()
        trailing = (
            b'{"decision":"reject","effect":"none"}'
            + bytes([10])
        )

        with mock_broker((valid + bytes([10]), trailing)) as path:
            client = BoundedBrokerClient(
                socket_path=path,
                timeout_seconds=2.0,
            )
            result = client.propose(
                "read_file", {"path": "fixture"}
            )

        self.assertEqual(result.decision, "unknown")
        self.assertEqual(result.effect, "unknown")
        self.assertFalse(result.broker_reported_success)


class TransportSubmissionTests(unittest.TestCase):

    def test_A02_partial_send_preserves_unknown(self):
        from unittest.mock import patch

        calls = {
            "connections": 0,
            "send_attempts": 0,
        }

        class FakeSocket:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def settimeout(self, timeout):
                assert timeout > 0

            def connect(self, path):
                assert path == "/tmp/sdk-a2-fake.sock"

            def sendall(self, payload):
                calls["send_attempts"] += 1
                assert payload.endswith(bytes([10]))

                # Delivery of a prefix cannot be ruled out.
                raise BrokenPipeError(
                    "simulated interrupted transmission"
                )

            def recv(self, size):
                raise AssertionError(
                    "recv must not follow failed sendall"
                )

        def socket_factory(*args, **kwargs):
            calls["connections"] += 1
            return FakeSocket()

        with patch(
            "darm_guard.sdk_transport.socket.socket",
            side_effect=socket_factory,
        ):
            client = BoundedBrokerClient(
                socket_path="/tmp/sdk-a2-fake.sock",
                timeout_seconds=2.0,
            )

            result = client.propose(
                "read_file", {"path": "fixture"}
            )

        self.assertEqual(result.decision, "unknown")
        self.assertEqual(result.effect, "unknown")
        self.assertFalse(result.broker_reported_success)

        self.assertEqual(calls["connections"], 1)
        self.assertEqual(calls["send_attempts"], 1)


class TransportTransactionTests(unittest.TestCase):

    def test_A11_broker_unknown_remains_unknown(self):
        reply = json.dumps({
            "decision": "admit",
            "effect": "unknown",
            "executed": False,
        }).encode() + bytes([10])

        with mock_broker(reply) as path:
            result = BoundedBrokerClient(
                socket_path=path,
                timeout_seconds=2.0,
            ).propose("read_file", {"path": "fixture"})

        self.assertEqual(result.decision, "admit")
        self.assertEqual(result.effect, "unknown")
        self.assertFalse(result.broker_reported_success)

    def test_A12_repeated_proposals_separate_connections(self):
        reply = json.dumps({
            "decision": "reject",
            "effect": "none",
        }).encode() + bytes([10])

        for index in range(2):
            with self.subTest(index=index):
                with mock_broker(reply) as path:
                    client = BoundedBrokerClient(
                        socket_path=path,
                        timeout_seconds=2.0,
                    )
                    result = client.propose(
                        "read_file",
                        {"path": f"fixture-{index}"},
                    )

                self.assertEqual(result.decision, "reject")
                self.assertEqual(result.effect, "none")


class StrictJsonTransportTests(unittest.TestCase):
    def test_nonstandard_nan_response_stays_unknown(self):
        reply = (
            b'{"decision":"admit","effect":"succeeded",'
            b'"executed":true,"content":NaN}\n'
        )

        with mock_broker(reply) as path:
            result = BoundedBrokerClient(
                socket_path=path,
                timeout_seconds=2.0,
            ).propose("read_file", {"path": "fixture"})

        self.assertEqual(result.decision, "unknown")
        self.assertEqual(result.effect, "unknown")
        self.assertFalse(result.broker_reported_success)

    def test_duplicate_response_key_stays_unknown(self):
        reply = (
            b'{"decision":"reject","decision":"admit",'
            b'"effect":"succeeded","executed":true}\n'
        )

        with mock_broker(reply) as path:
            result = BoundedBrokerClient(
                socket_path=path,
                timeout_seconds=2.0,
            ).propose("read_file", {"path": "fixture"})

        self.assertEqual(result.decision, "unknown")
        self.assertEqual(result.effect, "unknown")
        self.assertFalse(result.broker_reported_success)

    def test_decoder_recursion_exhaustion_stays_unknown(self):
        reply = (
            b'{"decision":"admit","effect":"succeeded",'
            b'"executed":true,"result":'
            + b"[" * 10000
            + b"0"
            + b"]" * 10000
            + b"}\n"
        )

        with mock_broker(reply) as path:
            result = BoundedBrokerClient(
                socket_path=path,
                timeout_seconds=2.0,
            ).propose("read_file", {"path": "fixture"})

        self.assertEqual(result.decision, "unknown")
        self.assertEqual(result.effect, "unknown")
        self.assertFalse(result.broker_reported_success)


class OutboundRequestBoundsTests(unittest.TestCase):
    def test_request_encoder_preserves_wire_format(self):
        from darm_guard.sdk_transport import _encode_request_payload

        args = {
            "path": "fixture",
            "count": 3,
            "enabled": True,
        }
        payload = _encode_request_payload(
            "read_file",
            args,
            4096,
            lambda: 1.0,
        )
        expected = (
            json.dumps({
                "tool": "read_file",
                "args": [[key, str(value)] for key, value in args.items()],
            }) + "\n"
        ).encode("utf-8")

        self.assertEqual(payload, expected)

    def test_request_limit_includes_newline_exactly(self):
        from darm_guard.sdk_transport import _encode_request_payload

        args = {"path": "fixture"}
        payload = _encode_request_payload(
            "read_file", args, 1024, lambda: 1.0
        )

        exact = _encode_request_payload(
            "read_file", args, len(payload), lambda: 1.0
        )
        self.assertEqual(exact, payload)

        with self.assertRaisesRegex(ValueError, "request size limit exceeded"):
            _encode_request_payload(
                "read_file", args, len(payload) - 1, lambda: 1.0
            )

    def test_oversized_request_is_rejected_before_connect(self):
        from unittest.mock import patch

        client = BoundedBrokerClient(
            max_request_bytes=128,
            timeout_seconds=2.0,
        )
        with patch("darm_guard.sdk_transport.socket.socket") as socket_mock:
            result = client.propose(
                "write_file",
                {"content": "x" * 200},
            )

        socket_mock.assert_not_called()
        self.assertEqual(result.decision, "reject")
        self.assertEqual(result.effect, "none")
        self.assertFalse(result.broker_reported_success)

    def test_deadline_includes_request_encoding(self):
        from unittest.mock import patch

        client = BoundedBrokerClient(timeout_seconds=1.0)
        with patch(
            "darm_guard.sdk_transport.time.monotonic",
            side_effect=[10.0, 12.0],
        ):
            with patch(
                "darm_guard.sdk_transport.socket.socket"
            ) as socket_mock:
                result = client.propose(
                    "read_file",
                    {"path": "fixture"},
                )

        socket_mock.assert_not_called()
        self.assertEqual(result.decision, "reject")
        self.assertEqual(result.effect, "none")
        self.assertFalse(result.broker_reported_success)

    def test_request_limit_cannot_exceed_broker_limit(self):
        with self.assertRaisesRegex(ValueError, "invalid request size limit"):
            BoundedBrokerClient(max_request_bytes=(1 << 20) + 1)


if __name__ == "__main__":
    unittest.main()
