import os
import subprocess
import sys
import unittest

from darm_guard.kernel import KernelClient


class RealProcessLifecycleTests(unittest.TestCase):

    def setUp(self):
        self.client = KernelClient(
            path="/unused/not-a-kernel"
        )
        self.children = []

    def launch(self, code):
        proc = subprocess.Popen(
            [sys.executable, "-B", "-u", "-c", code],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        self.children.append(proc)
        self.client._proc = proc
        return proc

    def tearDown(self):
        # Independent safety cleanup for test-owned children.
        # Never operate on unrelated process IDs.
        for proc in self.children:
            if proc.poll() is None:
                proc.kill()
            try:
                proc.wait(timeout=3)
            finally:
                for stream in (proc.stdin, proc.stdout):
                    if stream is not None:
                        stream.close()
        self.client._proc = None

    def assert_released(self, proc):
        self.assertIsNone(self.client._proc)
        self.assertIsNotNone(proc.returncode)
        self.assertIsNotNone(proc.poll())
        self.assertTrue(proc.stdin.closed)
        self.assertTrue(proc.stdout.closed)
        self.assertFalse(self.client._cleanup_unresolved)

    def test_running_child_is_terminated_and_reaped(self):
        proc = self.launch(
            "import time; time.sleep(60)"
        )

        self.assertIsNone(proc.poll())
        self.assertTrue(self.client.close())
        self.assert_released(proc)
    def test_exited_child_is_reaped_and_pipes_closed(self):
        proc = self.launch("pass")

        # Observe exit without consuming the child's wait status.
        # WNOWAIT leaves it available for KernelClient cleanup.
        info = os.waitid(
            os.P_PID,
            proc.pid,
            os.WEXITED | os.WNOWAIT,
        )
        self.assertEqual(info.si_pid, proc.pid)
        self.assertEqual(proc.returncode, None)

        self.assertTrue(self.client.close())
        self.assert_released(proc)
        self.assertEqual(proc.returncode, 0)
        self.assert_released(proc)


if __name__ == "__main__":
    unittest.main()
