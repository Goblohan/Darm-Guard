import io
import subprocess
import unittest
from unittest.mock import patch

from darm_guard.kernel import KernelClient


class FakeProcess:
    def __init__(self, running=True, wait_fails=False):
        self.running = running
        self.wait_fails = wait_fails
        self.killed = False
        self.waited = False
        self.stdin = io.StringIO()
        self.stdout = io.StringIO()

    def poll(self):
        return None if self.running else 0

    def kill(self):
        self.killed = True
        self.running = False

    def wait(self, timeout=None):
        self.waited = True
        if self.wait_fails:
            raise subprocess.TimeoutExpired(
                cmd="fake-kernel",
                timeout=timeout,
            )
        return 0


class KernelLifecycleTests(unittest.TestCase):

    def setUp(self):
        self.client = KernelClient(
            path="/unused/fake-kernel"
        )
        self.processes = []

    def tearDown(self):
        # Test-owned in-memory streams only.
        for proc in self.processes:
            proc.stdin.close()
            proc.stdout.close()
        self.client._proc = None

    def attach(self, **kwargs):
        proc = FakeProcess(**kwargs)
        self.processes.append(proc)
        self.client._proc = proc
        return proc

    def test_running_child_is_reaped_and_pipes_closed(self):
        proc = self.attach(running=True)

        self.client.close()

        self.assertTrue(proc.killed)
        self.assertTrue(proc.waited)
        self.assertTrue(proc.stdin.closed)
        self.assertTrue(proc.stdout.closed)
        self.assertIsNone(self.client._proc)

    def test_exited_child_is_reaped_and_pipes_closed(self):
        proc = self.attach(running=False)

        self.client.close()

        self.assertTrue(proc.waited)
        self.assertTrue(proc.stdin.closed)
        self.assertTrue(proc.stdout.closed)
        self.assertIsNone(self.client._proc)

    def test_failed_reap_preserves_process_ownership(self):
        proc = self.attach(
            running=True,
            wait_fails=True,
        )

        try:
            self.client.close()
        except subprocess.TimeoutExpired:
            pass

        self.assertTrue(proc.waited)
        self.assertIs(
            self.client._proc,
            proc,
            "Unconfirmed cleanup must retain process ownership",
        )

    def test_unresolved_cleanup_blocks_next_decision(self):
        proc = self.attach(
            running=True,
            wait_fails=True,
        )

        try:
            self.client.close()
        except subprocess.TimeoutExpired:
            pass

        with patch.object(
            self.client,
            "_start",
            side_effect=AssertionError(
                "Unresolved child must not be replaced"
            ),
        ) as start_mock:
            result = self.client.decide({
                "tool": "read_file",
                "args": {
                    "path": "/workspace/example.txt"
                },
            })

        self.assertFalse(result.admitted)
        start_mock.assert_not_called()
        self.assertEqual(proc.stdin.getvalue(), "")
        self.assertIs(self.client._proc, proc)


if __name__ == "__main__":
    unittest.main()
