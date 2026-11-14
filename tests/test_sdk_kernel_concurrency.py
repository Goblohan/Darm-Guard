import io
import threading
import unittest
from unittest.mock import patch

from darm_guard.kernel import KernelClient, KernelDecision


class FakeProcess:
    def __init__(self):
        self.stdin = io.StringIO()
        self.stdout = io.StringIO()
        self.running = True
        self.waited = False

    def poll(self):
        return None if self.running else 0

    def kill(self):
        self.running = False

    def wait(self, timeout=None):
        self.waited = True
        return 0


class KernelConcurrencyTests(unittest.TestCase):
    def test_external_close_waits_for_active_decision(self):
        client = KernelClient(path="/unused/fake-kernel")
        proc = FakeProcess()
        client._proc = proc

        decision_entered = threading.Event()
        release_decision = threading.Event()
        close_attempted = threading.Event()
        close_completed = threading.Event()

        outcomes = {}
        errors = []

        def blocked_decision(request):
            decision_entered.set()
            if not release_decision.wait(timeout=3):
                raise RuntimeError("decision release timed out")
            return KernelDecision(
                False, error="synthetic decision rejection"
            )

        def decision_worker():
            try:
                outcomes["decision"] = client.decide({
                    "tool": "read_file",
                    "args": {
                        "path": "/workspace/example.txt"
                    },
                })
            except BaseException as exc:
                errors.append(exc)

        def close_worker():
            close_attempted.set()
            try:
                outcomes["close"] = client.close()
            except BaseException as exc:
                errors.append(exc)
            finally:
                close_completed.set()

        decision_thread = threading.Thread(
            target=decision_worker, daemon=True
        )
        close_thread = threading.Thread(
            target=close_worker, daemon=True
        )

        try:
            with patch.object(
                client, "_decide_locked",
                side_effect=blocked_decision
            ):
                decision_thread.start()
                self.assertTrue(
                    decision_entered.wait(timeout=2),
                    "Decision did not enter its critical section",
                )

                close_thread.start()
                self.assertTrue(
                    close_attempted.wait(timeout=2),
                    "Close thread did not start",
                )

                self.assertFalse(
                    close_completed.wait(timeout=0.15),
                    "Close completed while decision held lock",
                )
                self.assertFalse(proc.waited)
                self.assertIs(client._proc, proc)

                release_decision.set()
                decision_thread.join(timeout=3)
                close_thread.join(timeout=3)

            self.assertFalse(decision_thread.is_alive())
            self.assertFalse(close_thread.is_alive())
            self.assertEqual(errors, [])
            self.assertFalse(outcomes["decision"].admitted)
            self.assertTrue(outcomes["close"])
            self.assertTrue(proc.waited)
            self.assertIsNone(client._proc)
            self.assertTrue(proc.stdin.closed)
            self.assertTrue(proc.stdout.closed)

        finally:
            release_decision.set()
            decision_thread.join(timeout=3)
            if close_thread.ident is not None:
                close_thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
