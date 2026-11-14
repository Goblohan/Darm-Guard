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


BROKER_MAX_REQUEST_BYTES = 1 << 20


def _append_bounded(output, chunk, max_bytes, reserve_newline=True):
    reserve = 1 if reserve_newline else 0
    if len(output) + len(chunk) + reserve > max_bytes:
        raise ValueError("request size limit exceeded")
    output.extend(chunk)


def _append_json_string(output, value, max_bytes, remaining):
    _append_bounded(output, b'"', max_bytes)
    for offset in range(0, len(value), 1024):
        remaining()
        chunk = json.dumps(
            value[offset:offset + 1024],
            ensure_ascii=True,
        )[1:-1].encode("ascii")
        _append_bounded(output, chunk, max_bytes)
    _append_bounded(output, b'"', max_bytes)


def _stringify_argument(value, max_bytes, remaining):
    if type(value) is str:
        return value

    if value is None or type(value) in (int, float, bool):
        if type(value) is int and value.bit_length() > max_bytes * 3:
            raise ValueError("request size limit exceeded")
        remaining()
        result = str(value)
        remaining()
        return result

    raise TypeError("argument values must be strings or JSON scalars")


def _encode_request_payload(tool, args, max_bytes, remaining):
    remaining()
    if type(tool) is not str:
        raise TypeError("tool must be a string")
    if type(args) is not dict:
        raise TypeError("args must be a plain dictionary")

    output = bytearray()

    def append(chunk, final=False):
        _append_bounded(
            output,
            chunk,
            max_bytes,
            reserve_newline=not final,
        )

    append(b'{"tool": ')
    _append_json_string(output, tool, max_bytes, remaining)
    append(b', "args": [')

    for index, (key, value) in enumerate(args.items()):
        remaining()
        if type(key) is not str:
            raise TypeError("argument names must be strings")

        value_text = _stringify_argument(value, max_bytes, remaining)

        if index:
            append(b", ")
        append(b"[")
        _append_json_string(output, key, max_bytes, remaining)
        append(b", ")
        _append_json_string(output, value_text, max_bytes, remaining)
        append(b"]")

    append(b"]}")
    append(b"\n", final=True)
    remaining()
    return bytes(output)


class BoundedBrokerClient:
    """One request per AF_UNIX connection, with no automatic retry."""

    def __init__(
        self,
        socket_path="/tmp/darm-broker.sock",
        max_response_bytes=4 * 1024 * 1024,
        max_request_bytes=1 * 1024 * 1024,
        timeout_seconds=10.0,
    ):
        if type(max_response_bytes) is not int or max_response_bytes < 2:
            raise ValueError("invalid response size limit")
        if (
            type(max_request_bytes) is not int
            or not 2 <= max_request_bytes <= BROKER_MAX_REQUEST_BYTES
        ):
            raise ValueError("invalid request size limit")
        if (
            type(timeout_seconds) not in (int, float)
            or not 0 < timeout_seconds < float("inf")
        ):
            raise ValueError("invalid transaction deadline")

        self.socket_path = socket_path
        self.max_response_bytes = max_response_bytes
        self.max_request_bytes = max_request_bytes
        self.timeout_seconds = float(timeout_seconds)

    def _result(self, decision, effect, error):
        return validate_response({
            "decision": decision,
            "effect": effect,
            "error": str(error),
        })

    def propose(self, tool, args):
        deadline = time.monotonic() + self.timeout_seconds

        def remaining():
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("transaction deadline exceeded")
            return left

        try:
            payload = _encode_request_payload(
                tool,
                args,
                self.max_request_bytes,
                remaining,
            )
        except (TypeError, ValueError, AttributeError, TimeoutError) as exc:
            return self._result("reject", "none", exc)

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

                    if trailing.strip(b" \t\r\n"):
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
                    RecursionError,
                ) as exc:
                    return self._result("unknown", "unknown", exc)

        except (OSError, TimeoutError) as exc:
            # Defensive fallback. No claim of a completed action.
            return self._result("unknown", "unknown", exc)
