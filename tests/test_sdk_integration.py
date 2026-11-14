"""Bounded DARM SDK integration tests.

Four disposable scenarios. No admitted effect is requested.
The real kernel test is a local integration observation,
not independent causal witnessing or complete mediation.
"""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

from darm_guard import broker as B
from darm_guard import install
from darm_guard.sdk_transport import BoundedBrokerClient


EXPECTED_KERNEL_SHA256 = (
    "6f6c3a21688047a2dd5111483ba9f25d7f4db83d3562d4da2cc616e00c484d31"
)


class SDKIntegrationTests(unittest.TestCase):

    def run_scenario(self, kind):
        with tempfile.TemporaryDirectory(
            prefix="darm-sdk-integration-"
        ) as temporary:

            directory = Path(temporary)
            workspace = directory / "workspace"
            workspace.mkdir(mode=0o700)

            socket_path = str(directory / "broker.sock")
            audit_path = str(directory / "audit.jsonl")
            marker = directory / "fixture-received.json"

            cfg = B.BrokerConfig(
                policy={"tools": []},
                credential_tools=(),
                registry=frozenset(),
                workspace=str(workspace),
                issued_at=None,
                ttl_seconds=None,
                patterns=(),
                read_requires_attestation=False,
                vouched_manifest=None,
                http=None,
                tool_registry=(),
            )

            if kind == "real":
                self.assertEqual(
                    install.KERNEL_SHA256,
                    EXPECTED_KERNEL_SHA256,
                )
                kernel_path = install.verified_kernel_path()
                self.assertTrue(kernel_path)
                self.assertEqual(
                    hashlib.sha256(
                        Path(kernel_path).read_bytes()
                    ).hexdigest(),
                    EXPECTED_KERNEL_SHA256,
                )

            elif kind == "missing":
                kernel_path = str(directory / "missing-kernel")
                self.assertFalse(Path(kernel_path).exists())

            else:
                fixture = directory / "synthetic-kernel"
                python = str(Path(sys.executable).resolve())

                response_nonce = (
                    "'wrong-nonce'"
                    if kind == "nonce"
                    else "nonce"
                )

                program = (
                    f"#!{python}\n"
                    "import json\n"
                    "import sys\n"
                    "from pathlib import Path\n"
                    "for line in sys.stdin:\n"
                    "    req = json.loads(line)\n"
                    "    nonce = req.get('nonce')\n"
                    f"    Path({str(marker)!r}).write_text(\n"
                    "        json.dumps({\n"
                    "            'received': True,\n"
                    "            'nonce_present': bool(nonce),\n"
                    "            'tool': req.get('proposal', {}).get('tool')\n"
                    "        }), encoding='utf-8')\n"
                    "    print(json.dumps({\n"
                    "        'decision': 'admit',\n"
                    f"        'nonce': {response_nonce},\n"
                    "        'invocation': {}\n"
                    "    }), flush=True)\n"
                )

                fixture.write_text(program, encoding="utf-8")
                fixture.chmod(0o700)
                self.assertTrue(os.access(fixture, os.X_OK))
                kernel_path = str(fixture)

            server = None
            worker = None
            child = None

            try:
                server = B.serve(
                    cfg,
                    socket_path,
                    audit_path,
                    kernel_path=kernel_path,
                    intents_path=None,
                    checkpoint_sink=None,
                    revocations_path=None,
                )

                kernel = server.broker.kernel
                self.assertIsNone(kernel._proc)
                self.assertEqual(server.broker.audit.count, 0)

                server.timeout = 8
                worker = threading.Thread(
                    target=server.handle_request,
                    daemon=True,
                )
                worker.start()

                client = BoundedBrokerClient(
                    socket_path=socket_path,
                    timeout_seconds=8,
                    max_response_bytes=65536,
                )

                result = client.propose(
                    "read_file",
                    {"path": "/workspace/denied.txt"},
                )

                failure = result.payload.get("failure")
                error = result.payload.get("error")

                self.assertEqual(result.decision, "reject")
                self.assertEqual(result.effect, "none")
                self.assertEqual(result.evidence, "recorded")
                self.assertFalse(result.broker_reported_success)

                if kind == "real":
                    self.assertEqual(failure, "observation")
                    self.assertIsNone(error)
                    self.assertIsNotNone(kernel._proc)

                elif kind == "missing":
                    self.assertIsNone(failure)
                    self.assertIsInstance(error, str)
                    self.assertTrue(
                        error.startswith("kernel unavailable:")
                    )
                    self.assertIsNone(kernel._proc)

                else:
                    self.assertTrue(marker.is_file())
                    receipt = json.loads(marker.read_text())
                    self.assertEqual(receipt, {
                        "received": True,
                        "nonce_present": True,
                        "tool": "read_file",
                    })

                    if kind == "nonce":
                        self.assertIsNone(failure)
                        self.assertIn("nonce mismatch", error)
                        self.assertIsNone(kernel._proc)
                    else:
                        self.assertEqual(failure, "semantic")
                        self.assertEqual(
                            error,
                            "the kernel's canonical invocation "
                            "differs from the broker's",
                        )
                        self.assertEqual(
                            result.payload.get("failure"),
                            "semantic",
                        )
                        self.assertIsNotNone(kernel._proc)

                records = [
                    json.loads(line)
                    for line in Path(audit_path).read_text(
                        encoding="utf-8"
                    ).splitlines()
                    if line.strip()
                ]

                self.assertEqual(len(records), 1)
                entry = records[0]

                self.assertEqual(entry["event"], "decision")
                self.assertEqual(entry["decision"], "reject")
                self.assertEqual(entry["effect"], "none")
                self.assertEqual(
                    entry["request_id"],
                    result.request_id,
                )
                self.assertEqual(
                    entry.get("error"),
                    error,
                )
                self.assertEqual(
                    entry.get("failure"),
                    failure,
                )

                body = dict(entry)
                stored_hash = body.pop("entry_hash")

                calculated = hashlib.sha256(
                    json.dumps(
                        body, sort_keys=True
                    ).encode()
                ).hexdigest()

                self.assertEqual(calculated, stored_hash)

                reopened = B.AuditLog(audit_path)
                self.assertEqual(reopened.count, 1)
                self.assertEqual(reopened.prev, stored_hash)

                self.assertEqual(list(workspace.iterdir()), [])

            finally:
                if server is not None:
                    try:
                        server.server_close()
                    finally:
                        child = server.broker.kernel._proc
                        server.broker.kernel.close()

                if child is not None:
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=5)

                if worker is not None:
                    worker.join(timeout=9)

            self.assertIsNotNone(worker)
            self.assertFalse(worker.is_alive())

            if child is not None:
                self.assertIsNotNone(child.poll())

    def test_real_kernel_rejection(self):
        self.run_scenario("real")

    def test_kernel_unavailable(self):
        self.run_scenario("missing")

    def test_wrong_nonce_admission(self):
        self.run_scenario("nonce")

    def test_wrong_invocation_admission(self):
        self.run_scenario("semantic")
