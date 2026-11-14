import threading
import unittest
from unittest.mock import patch

import darm_guard.broker as broker_module


class MemoryAudit:
    def __init__(self):
        self.last_ts = None
        self._lock = threading.Lock()
        self.events = []
        self.checkpoints = []

    def append(self, record):
        with self._lock:
            self.events.append(record["event"])

    def checkpoint_now(self):
        with self._lock:
            snapshot = tuple(self.events)
            self.checkpoints.append(snapshot)
            return snapshot


class BrokerShutdownRaceTests(unittest.TestCase):

    def test_terminal_checkpoint_can_precede_outcome(self):
        audit = MemoryAudit()

        # Construct only the state needed to exercise the
        # actual Broker._handle transaction implementation.
        broker = broker_module.Broker.__new__(
            broker_module.Broker
        )
        broker.cfg = object()
        broker.audit = audit
        broker._lock = threading.Lock()
        broker._keys = {}
        broker._reserved = {}
        broker._proposal = None
        broker.intents = None
        broker.key = None

        invocation = {
            "tool": "write_file",
            "args": [],
        }

        effect_entered = threading.Event()
        release_effect = threading.Event()
        worker_errors = []
        responses = []

        def blocked_execute(*args, **kwargs):
            effect_entered.set()
            if not release_effect.wait(timeout=3):
                raise RuntimeError(
                    "Negative-control effect release timed out"
                )
            return {"written": 1}

        def worker():
            try:
                responses.append(
                    broker._handle({"tool": "write_file"})
                )
            except BaseException as exc:
                worker_errors.append(exc)

        thread = threading.Thread(
            target=worker,
            daemon=True,
        )

        try:
            with (
                patch.object(
                    broker_module.Broker,
                    "decide",
                    return_value=(
                        invocation,
                        "write_file",
                        {"decision": "admit"},
                    ),
                ),
                patch.object(
                    broker_module,
                    "_intended_state",
                    return_value=None,
                ),
                patch.object(
                    broker_module,
                    "invocation_hash",
                    return_value="synthetic-invocation-hash",
                ),
                patch.object(
                    broker_module,
                    "_execute",
                    side_effect=blocked_execute,
                ),
            ):
                thread.start()

                self.assertTrue(
                    effect_entered.wait(timeout=2),
                    "Transaction did not enter blocked effect",
                )

                self.assertEqual(
                    audit.events,
                    ["prepared"],
                )

                # Reproduce the existing shutdown finalization
                # statements while the effect is unfinished.
                audit.append({"event": "stop"})
                checkpoint = audit.checkpoint_now()

                self.assertEqual(
                    checkpoint,
                    ("prepared", "stop"),
                )
                self.assertNotIn("outcome", checkpoint)

                release_effect.set()
                thread.join(timeout=3)

            self.assertFalse(thread.is_alive())
            self.assertEqual(worker_errors, [])
            self.assertEqual(len(responses), 1)
            self.assertEqual(
                audit.events,
                ["prepared", "stop", "outcome"],
            )
            self.assertEqual(
                audit.checkpoints,
                [("prepared", "stop")],
            )

        finally:
            release_effect.set()
            if thread.ident is not None:
                thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
