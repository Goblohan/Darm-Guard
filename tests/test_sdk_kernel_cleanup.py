import subprocess
import unittest

from darm_guard.kernel import KernelClient


class FakeStream:
    def __init__(self, close_error=None):
        self.close_error = close_error
        self.close_calls = 0
        self.closed = False

    def close(self):
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error
        self.closed = True


class FakeProcess:
    def __init__(
        self,
        returncode=None,
        kill_error=None,
        wait_error=None,
        stdout_close_error=None,
    ):
        self.returncode = returncode
        self.kill_error = kill_error
        self.wait_error = wait_error
        self.kill_calls = 0
        self.wait_timeouts = []
        self.stdin = FakeStream()
        self.stdout = FakeStream(stdout_close_error)
        self.stderr = FakeStream()

    def poll(self):
        return self.returncode

    def kill(self):
        self.kill_calls += 1
        if self.kill_error is not None:
            raise self.kill_error

    def wait(self, timeout=None):
        self.wait_timeouts.append(timeout)
        if self.wait_error is not None:
            raise self.wait_error
        if self.returncode is None:
            self.returncode = -9
        return self.returncode


class KernelClientCleanupTests(unittest.TestCase):
    def setUp(self):
        self.client = KernelClient(path="/synthetic/darmkernel")

    def test_close_kills_reaps_and_closes_streams(self):
        process = FakeProcess()
        self.client._proc = process

        self.assertTrue(self.client.close())
        self.assertEqual(process.kill_calls, 1)
        self.assertEqual(process.wait_timeouts, [self.client.timeout])
        self.assertTrue(process.stdin.closed)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)
        self.assertIsNone(self.client._proc)
        self.assertFalse(self.client._cleanup_unresolved)
        self.assertEqual(self.client._cleanup_error, "")

    def test_process_exit_race_still_reaps_and_closes(self):
        process = FakeProcess(kill_error=ProcessLookupError("already exited"))
        self.client._proc = process

        self.assertTrue(self.client.close())
        self.assertEqual(process.kill_calls, 1)
        self.assertEqual(process.wait_timeouts, [self.client.timeout])
        self.assertIsNone(self.client._proc)

    def test_kill_failure_stays_visible_and_blocks_decisions(self):
        process = FakeProcess(kill_error=PermissionError("denied"))
        self.client._proc = process

        self.assertFalse(self.client.close())
        self.assertIs(self.client._proc, process)
        self.assertTrue(self.client._cleanup_unresolved)
        self.assertIn("process_kill_failed", self.client._cleanup_error)
        self.assertEqual(process.wait_timeouts, [])

        decision = self.client.decide({"tool": "read_file", "args": []})
        self.assertFalse(decision.admitted)
        self.assertIn("kernel cleanup unresolved", decision.error)
        self.assertEqual(process.kill_calls, 1)

    def test_reap_failure_stays_visible(self):
        process = FakeProcess(
            wait_error=subprocess.TimeoutExpired(
                cmd="synthetic-kernel",
                timeout=5,
            )
        )
        self.client._proc = process

        self.assertFalse(self.client.close())
        self.assertIs(self.client._proc, process)
        self.assertTrue(self.client._cleanup_unresolved)
        self.assertIn("process_reap_failed", self.client._cleanup_error)
        self.assertFalse(process.stdin.closed)
        self.assertFalse(process.stdout.closed)

    def test_stream_close_failure_stays_visible_and_can_retry(self):
        process = FakeProcess(
            stdout_close_error=OSError("synthetic close failure")
        )
        self.client._proc = process

        self.assertFalse(self.client.close())
        self.assertIs(self.client._proc, process)
        self.assertTrue(self.client._cleanup_unresolved)
        self.assertIn("stream_close_failed", self.client._cleanup_error)

        process.stdout.close_error = None
        self.assertTrue(self.client.close())
        self.assertIsNone(self.client._proc)
        self.assertFalse(self.client._cleanup_unresolved)
        self.assertEqual(self.client._cleanup_error, "")

    def test_already_exited_process_is_reaped_without_kill(self):
        process = FakeProcess(returncode=0)
        self.client._proc = process

        self.assertTrue(self.client.close())
        self.assertEqual(process.kill_calls, 0)
        self.assertEqual(process.wait_timeouts, [self.client.timeout])
        self.assertIsNone(self.client._proc)


if __name__ == "__main__":
    unittest.main()
