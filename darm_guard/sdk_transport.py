"""Bounded agent-side transport for the DARM broker.

Transport integrity only. No independent causal assurance.
"""

import json
import socket
import time

from .sdk_response import InvalidResponse, validate_response


def _reject_json_constant(token):
    raise ValueError(f"non-standard JSON constant: {token}")


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


class BoundedBrokerClient:
    """One request per AF_UNIX connection, with no automatic retry."""

    def __init__(
        self,
        socket_path="/tmp/darm-broker.sock",
        max_response_bytes=4 * 1024 * 1024,
        timeout_seconds=10.0,
    ):
        if type(max_response_bytes) is not int or max_response_bytes < 2:
            raise ValueError("invalid response size limit")
        if (
            type(timeout_seconds) not in (int, float)
            or not 0 < timeout_seconds < float("inf")
        ):
            raise ValueError("invalid transaction deadline")

        self.socket_path = socket_path
        self.max_response_bytes = max_response_bytes
        self.timeout_seconds = float(timeout_seconds)

    def _result(self, decision, effect, error):
        return validate_response({
            "decision": decision,
            "effect": effect,
            "error": str(error),
        })

    def propose(self, tool, args):
        # Encode before contacting the broker.
        try:
            message = {
                "tool": tool,
                "args": [[k, str(v)] for k, v in args.items()],
            }
            payload = (json.dumps(message) + "\n").encode("utf-8")
        except (TypeError, ValueError, AttributeError) as exc:
            return self._result("reject", "none", exc)

        deadline = time.monotonic() + self.timeout_seconds

        def remaining():
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("transaction deadline exceeded")
            return left

        try:
            with socket.socket(
                socket.AF_UNIX, socket.SOCK_STREAM
            ) as connection:
                # No request bytes have been transmitted yet.
                try:
                    connection.settimeout(remaining())
                    connection.connect(self.socket_path)
                except (OSError, TimeoutError) as exc:
                    return self._result("reject", "none", exc)

                # From this point onward, delivery may have occurred.
                try:
                    connection.settimeout(remaining())
                    connection.sendall(payload)
                    connection.shutdown(socket.SHUT_WR)

                    data = bytearray()

                    while True:
                        connection.settimeout(remaining())
                        available = self.max_response_bytes - len(data)
                        chunk = connection.recv(
                            min(65536, available + 1)
                        )

                        if not chunk:
                            break

                        data.extend(chunk)

                        if len(data) > self.max_response_bytes:
                            raise ValueError(
                                "response size limit exceeded"
                            )

                    if b"\n" not in data:
                        raise ValueError(
                            "response terminated before newline"
                        )

                    frame, trailing = bytes(data).split(b"\n", 1)

                    if trailing.strip():
                        raise ValueError("trailing response data")

                    remaining()

                    response = json.loads(
                        frame,
                        parse_constant=_reject_json_constant,
                        object_pairs_hook=_unique_json_object,
                    )
                    return validate_response(response)

                except (
                    OSError,
                    TimeoutError,
                    ValueError,
                    UnicodeError,
                    InvalidResponse,
                ) as exc:
                    return self._result("unknown", "unknown", exc)

        except (OSError, TimeoutError) as exc:
            # Defensive fallback. No claim of a completed action.
            return self._result("unknown", "unknown", exc)
