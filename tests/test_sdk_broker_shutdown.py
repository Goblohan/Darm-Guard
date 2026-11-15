import json
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from darm_guard import broker as candidate
from darm_guard.checkpoint import Checkpointer, check_log, load_published


class _Kernel:
    _proc = None
    _cleanup_unresolved = False
    _cleanup_error = ""

    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True
        return True


class _HeldBroker:
    def __init__(self, audit, key):
        self.audit = audit
        self.key = key
        self.kernel = _Kernel()
        self._shutdown_barrier = candidate.ShutdownBarrier()
        self.entered = threading.Event()
        self.release = threading.Event()
        self.errors = []

    def handle(self):
        try:
            with self._shutdown_barrier.transaction():
                self.audit.append({"event": "prepared"})
                self.entered.set()
                if not self.release.wait(5):
                    raise RuntimeError("held transaction timed out")
                self.audit.append({"event": "outcome"})
        except BaseException as exc:
            self.errors.append(exc)


class BrokerShutdownProductionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            prefix="a175-candidate-test-", dir="/tmp"
        )
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)

        self.audit_path = str(root / "audit.jsonl")
        self.key = candidate._load_or_create_keys(self.audit_path)
        self.audit = candidate.AuditLog(self.audit_path)
        self.checkpointer = Checkpointer(
            self.key.ring, str(root / "checkpoints"), every=1000
        )
        self.audit.checkpointer = self.checkpointer
        self.audit.append({"event": "start"})
        self.assertIsNone(self.audit.checkpoint_now())

        self.server = candidate._Server(
            str(root / "broker.sock"), candidate._Handler
        )
        self.server._darm_locks = [candidate._claim(self.audit_path)]
        self.broker = _HeldBroker(self.audit, self.key)
        self.server.broker = self.broker

        self.serving = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.01},
            daemon=True,
        )
        self.transaction = None
        self.coordinator = None
        self.addCleanup(self._cleanup)

        self.serving.start()
        deadline = time.monotonic() + 2
        while self.server._BaseServer__is_shut_down.is_set():
            if time.monotonic() >= deadline:
                self.fail("serve loop did not start")
            time.sleep(0.005)

    def _cleanup(self):
        self.broker.release.set()

        for thread in (self.transaction, self.coordinator):
            if thread is not None and thread.is_alive():
                thread.join(timeout=7)

        if self.serving.is_alive():
            self.server.shutdown()
            self.serving.join(timeout=2)

        for fd in getattr(self.server, "_darm_locks", []):
            try:
                os.close(fd)
            except OSError:
                pass
        self.server._darm_locks = []

        try:
            self.server.server_close()
        except OSError:
            pass

    def _events(self):
        with open(self.audit_path) as stream:
            return [
                json.loads(line)["event"]
                for line in stream
                if line.strip()
            ]

    def _start_transaction(self):
        self.transaction = threading.Thread(
            target=self.broker.handle, daemon=True
        )
        self.transaction.start()
        self.assertTrue(
            self.broker.entered.wait(2),
            "direct broker transaction did not start",
        )

    def test_shutdown_waits_for_direct_broker_transaction(self):
        self._start_transaction()
        result = []

        self.coordinator = threading.Thread(
            target=lambda: result.append(
                candidate.coordinate_shutdown(
                    self.server, self.serving, drain_timeout=5
                )
            ),
            daemon=True,
        )
        self.coordinator.start()

        deadline = time.monotonic() + 2
        while not self.broker._shutdown_barrier.closing:
            if result or time.monotonic() >= deadline:
                self.fail("shutdown did not close broker admission")
            time.sleep(0.005)

        time.sleep(0.05)
        self.assertEqual(self.broker._shutdown_barrier.active, 1)
        self.assertEqual(self._events(), ["start", "prepared"])
        self.assertFalse(result, "coordinator returned before transaction drained")

        with self.assertRaises(candidate.ShutdownAdmissionClosed):
            with self.broker._shutdown_barrier.transaction():
                self.fail("transaction crossed closed broker barrier")

        self.broker.release.set()
        self.transaction.join(timeout=3)
        self.coordinator.join(timeout=7)

        self.assertFalse(self.transaction.is_alive())
        self.assertFalse(self.coordinator.is_alive())
        self.assertEqual(self.broker.errors, [])
        self.assertEqual(
            self._events(), ["start", "prepared", "outcome", "stop"]
        )
        self.assertEqual(
            result[0]["state"], "GRACEFUL_SHUTDOWN_COMPLETE"
        )
        self.assertEqual(self.server._darm_locks, [])

        checkpoints = load_published(
            self.checkpointer.path_for(self.audit.genesis)
        )
        verification = check_log(
            self.audit_path,
            checkpoints,
            self.key.ring.public_only(),
        )
        self.assertTrue(verification["ok"], verification)
        self.assertEqual(verification["covered"], self.audit.count)
        self.assertTrue(any(
            item.get("count") == self.audit.count
            and item.get("head") == self.audit.prev
            for item in checkpoints
        ))

        reclaimed_fd = candidate._claim(self.audit_path)
        os.close(reclaimed_fd)

    def test_timeout_does_not_finalize_and_repeat_refuses(self):
        self._start_transaction()

        first = candidate.coordinate_shutdown(
            self.server, self.serving, drain_timeout=0.15
        )
        self.assertEqual(first["state"], "INCOMPLETE_DRAIN")
        self.assertFalse(first["broker_transactions_drained"])
        self.assertEqual(self._events(), ["start", "prepared"])
        self.assertFalse(self.broker.kernel.closed)
        self.assertEqual(len(self.server._darm_locks), 1)

        self.broker.release.set()
        self.transaction.join(timeout=3)
        self.assertFalse(self.transaction.is_alive())
        self.assertEqual(self.broker.errors, [])

        second = candidate.coordinate_shutdown(
            self.server, self.serving, drain_timeout=1
        )
        self.assertEqual(second["state"], "INCOMPLETE_SHUTDOWN_PHASE")
        self.assertEqual(
            self._events(), ["start", "prepared", "outcome"]
        )
        self.assertFalse(self.broker.kernel.closed)
        self.assertEqual(len(self.server._darm_locks), 1)

    def test_checkpoint_unavailable_still_closes_kernel(self):
        self.audit.checkpointer = None

        result = candidate.coordinate_shutdown(
            self.server, self.serving, drain_timeout=2
        )

        self.assertEqual(
            result["state"], "STOP_RECORDED_CHECKPOINT_UNAVAILABLE"
        )
        self.assertTrue(result["kernel_closed"])
        self.assertTrue(self.broker.kernel.closed)
        self.assertEqual(self._events(), ["start", "stop"])
        self.assertEqual(len(self.server._darm_locks), 1)

    def test_checkpoint_failure_still_closes_kernel(self):
        self.audit.checkpoint_now = lambda: "synthetic checkpoint failure"

        result = candidate.coordinate_shutdown(
            self.server, self.serving, drain_timeout=2
        )

        self.assertEqual(result["state"], "STOP_RECORDED_CHECKPOINT_FAILED")
        self.assertTrue(result["kernel_closed"])
        self.assertTrue(self.broker.kernel.closed)
        self.assertEqual(self._events(), ["start", "stop"])
        self.assertEqual(len(self.server._darm_locks), 1)

    def test_shutdown_waits_for_worker_thread_exit(self):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        unregistered = threading.Event()
        release_worker = threading.Event()
        original_unregister = self.server._connection_gate.unregister

        def pause_after_unregister(connection):
            original_unregister(connection)
            unregistered.set()
            release_worker.wait(3)

        self.server._connection_gate.unregister = pause_after_unregister
        result = []
        try:
            client.connect(self.server.server_address)
            deadline = time.monotonic() + 2
            while self.server._connection_gate.pending != 1:
                if time.monotonic() >= deadline:
                    self.fail("idle client was not registered")
                time.sleep(0.005)

            self.coordinator = threading.Thread(
                target=lambda: result.append(
                    candidate.coordinate_shutdown(
                        self.server, self.serving, drain_timeout=0.2
                    )
                ),
                daemon=True,
            )
            self.coordinator.start()

            self.assertTrue(
                unregistered.wait(2),
                "worker did not reach post-unregister hold",
            )
            self.coordinator.join(timeout=2)
            self.assertFalse(
                self.coordinator.is_alive(),
                "coordinator did not report the worker timeout",
            )
            self.assertEqual(result[0]["state"], "INCOMPLETE_DRAIN")
            self.assertTrue(result[0]["connections_drained"])
            self.assertFalse(result[0]["workers_drained"])
            self.assertIn("WORKERS_ALIVE", result[0]["blockers"])
            self.assertEqual(self._events(), ["start"])
            self.assertFalse(self.broker.kernel.closed)
            self.assertEqual(len(self.server._darm_locks), 1)
        finally:
            release_worker.set()
            client.close()
            if self.coordinator is not None:
                self.coordinator.join(timeout=2)

    def test_completed_socket_worker_is_reaped(self):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.connect(self.server.server_address)
            deadline = time.monotonic() + 2
            while self.server._connection_gate.pending != 1:
                if time.monotonic() >= deadline:
                    self.fail("idle client was not registered")
                time.sleep(0.005)

            self.assertEqual(len(self.server.worker_snapshot()), 1)
        finally:
            client.close()

        deadline = time.monotonic() + 2
        while (
            self.server._connection_gate.pending
            or self.server.worker_snapshot()
        ):
            if time.monotonic() >= deadline:
                self.fail("completed worker or connection was retained")
            time.sleep(0.005)

        self.assertEqual(self.server.worker_snapshot(), ())

    def test_broker_admission_races_with_shutdown_closure(self):
        for iteration in range(200):
            gate = candidate.ShutdownBarrier()
            start = threading.Barrier(3)
            release = threading.Event()
            close_done = threading.Event()
            admission_decided = threading.Event()
            result = {}
            errors = []

            def admit():
                try:
                    start.wait(timeout=2)
                    with gate.transaction():
                        result["admitted"] = True
                        admission_decided.set()
                        if not release.wait(2):
                            raise RuntimeError("transaction release timed out")
                except candidate.ShutdownAdmissionClosed:
                    result["admitted"] = False
                    admission_decided.set()
                except BaseException as exc:
                    errors.append(exc)
                    admission_decided.set()

            def close():
                try:
                    start.wait(timeout=2)
                    result["first_close"] = gate.begin_shutdown()
                    close_done.set()
                except BaseException as exc:
                    errors.append(exc)
                    close_done.set()

            threads = [
                threading.Thread(target=admit),
                threading.Thread(target=close),
            ]

            try:
                for thread in threads:
                    thread.start()
                start.wait(timeout=2)

                self.assertTrue(close_done.wait(2))
                self.assertTrue(admission_decided.wait(2))
                self.assertEqual(
                    gate.active, int(result["admitted"]),
                    f"iteration {iteration}: admission was not counted",
                )

                release.set()
                for thread in threads:
                    thread.join(timeout=2)

                self.assertEqual(errors, [])
                self.assertFalse(any(thread.is_alive() for thread in threads))
                self.assertTrue(result["first_close"])
                self.assertTrue(gate.closing)
                self.assertEqual(gate.active, 0)
                self.assertTrue(gate.wait_drained(timeout=0))
                self.assertFalse(gate.begin_shutdown())

                with self.assertRaises(candidate.ShutdownAdmissionClosed):
                    with gate.transaction():
                        self.fail(
                            f"iteration {iteration}: post-cutoff admission"
                        )
            finally:
                release.set()
                for thread in threads:
                    if thread.ident is not None:
                        thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
