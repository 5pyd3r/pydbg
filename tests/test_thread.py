"""Tests for thread operations: context, suspend, resume."""

import unittest
import os

from tests import TEST_TARGET_PATH


class TestThreadContext(unittest.TestCase):
    """Test reading and writing thread context."""

    def setUp(self):
        from pydbg.cython import _process
        self.pid, self.tid, self.h_proc, self.h_thr = _process.create_process(
            TEST_TARGET_PATH)
        _process.wait_for_debug_event(5000)
        _process.continue_debug_event(self.pid, self.tid, 0)

    def tearDown(self):
        from pydbg.cython import _process
        _process.terminate_process(self.h_proc, 0)
        _process.close_handle(self.h_proc)
        _process.close_handle(self.h_thr)

    def test_get_thread_context(self):
        """Verify get_thread_context returns x64 registers."""
        from pydbg.cython import _thread

        ctx = _thread.get_thread_context(self.h_thr)
        self.assertIn('rip', ctx)
        self.assertIn('rsp', ctx)
        self.assertIn('rax', ctx)
        self.assertIsInstance(ctx['rip'], int)

    def test_open_thread(self):
        """Verify open_thread returns valid handle."""
        from pydbg.cython import _thread

        h = _thread.open_thread(self.tid)
        self.assertGreater(h, 0)
        _thread.close_handle(h)

    def test_suspend_resume(self):
        """Verify suspend and resume cycle."""
        from pydbg.cython import _thread

        h = _thread.open_thread(self.tid)
        count = _thread.suspend_thread(h)
        self.assertGreaterEqual(count, 0)

        count2 = _thread.resume_thread(h)
        self.assertGreaterEqual(count2, 0)

        _thread.close_handle(h)


class TestDebuggerThreadAPI(unittest.TestCase):
    """Tests for high-level thread API."""

    def test_get_registers(self):
        """Verify Debugger.get_registers returns dict."""
        from pydbg import Debugger
        from pydbg.cython import _thread

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        event = dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        h_thread = dbg.open_thread(tid)
        regs = dbg.get_registers(h_thread)
        self.assertIn('rip', regs)
        self.assertIn('rsp', regs)

        _thread.close_handle(h_thread)
        dbg.close_handle(dbg._process_handle)
        dbg.close_handle(dbg._thread_handle)


if __name__ == '__main__':
    unittest.main()
