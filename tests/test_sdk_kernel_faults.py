import io
import subprocess
import unittest
from unittest.mock import patch

from darm_guard.kernel import KernelClient


class RecordingStream(io.StringIO):
    def __init__(self):
        super().__init__()
        self.writes = []

    def write(self, value):
        self.writes.append(value)
        return super().write(value)


class FaultyStream(io.StringIO):
    def __init__(self):
        super().__init__()
        self.fail_next_close = True

    def close(self):
        if self.fail_next_close:
            self.fail_next_close = False
            raise OSError("injected stream close failure")
        return super().close()


class FaultProcess:
    def __init__(self, wait_failures=0, faulty_stream=False):
        self.running = True
        self.wait_failures = wait_failures
        self.killed = False
        self.wait_calls = 0
        self.stdin = RecordingStream()
        self.stdout = (
            FaultyStream() if faulty_stream
            else io.StringIO()
        )

    def poll(self):
        return None if self.running else 0

    def kill(self):
        self.killed = True
        self.running = False

    def wait(self, timeout=None):
        self.wait_calls += 1
        if self.wait_failures:
            self.wait_failures -= 1
            raise subprocess.TimeoutExpired(
                cmd="fake-kernel", timeout=timeout
            )
        return 0


class KernelFaultTests(unittest.TestCase):
    def setUp(self):
        self.client = KernelClient(
            path="/unused/fake-kernel"
        )
        self.processes = []

    def attach(self, **kwargs):
        proc = FaultProcess(**kwargs)
        self.processes.append(proc)
        self.client._proc = proc
        return proc

    def tearDown(self):
        for proc in self.processes:
            # Test-owned in-memory resources only.
            io.StringIO.close(proc.stdin)
            io.StringIO.close(proc.stdout)
        self.client._proc = None

    def assert_blocked_without_submission(self, proc):
        with patch.object(
            self.client, "_start"
        ) as start_mock:
            decision = self.client.decide({
                "tool": "read_file",
                "args": {
                    "path": "/workspace/example.txt"
                },
            })
        self.assertFalse(decision.admitted)
        start_mock.assert_not_called()
        self.assertEqual(proc.stdin.writes, [])

    def test_stream_close_failure_retains_ownership(self):
        proc = self.attach(faulty_stream=True)

        result = self.client.close()
        self.assertFalse(result)
        self.assertTrue(proc.wait_calls >= 1)
        self.assertIs(self.client._proc, proc)
        self.assertTrue(self.client._cleanup_unresolved)
        self.assertIn(
            "stream_close_failed",
            self.client._cleanup_error,
        )
        self.assert_blocked_without_submission(proc)

        self.assertTrue(self.client.close())
        self.assertIsNone(self.client._proc)
        self.assertFalse(self.client._cleanup_unresolved)
        self.assertTrue(proc.stdout.closed)

    def test_reap_timeout_requires_explicit_recovery(self):
        proc = self.attach(wait_failures=1)

        self.assertFalse(self.client.close())
        self.assertIs(self.client._proc, proc)
        self.assertTrue(self.client._cleanup_unresolved)
        self.assertIn(
            "process_reap_failed",
            self.client._cleanup_error,
        )
        self.assert_blocked_without_submission(proc)

        self.assertTrue(self.client.close())
        self.assertEqual(proc.wait_calls, 2)
        self.assertIsNone(self.client._proc)
        self.assertTrue(proc.stdin.closed)
        self.assertTrue(proc.stdout.closed)


if __name__ == "__main__":
    unittest.main()
