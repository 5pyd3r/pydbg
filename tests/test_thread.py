"""Tests for thread operations: context, suspend, resume."""

import unittest

from tests import TEST_TARGET_PATH, IP_REG, SP_REG, GP_REG

try:
    from pydbg import _pydbg

    _has_cython = True
except ImportError:
    _has_cython = False


class TestThreadContext(unittest.TestCase):
    """Test reading and writing thread context."""

    def setUp(self):
        self.pid, self.tid, self.h_proc, self.h_thr = _pydbg.create_process(
            TEST_TARGET_PATH
        )
        _pydbg.wait_for_debug_event(5000)
        _pydbg.continue_debug_event(self.pid, self.tid)

    def tearDown(self):
        _pydbg.debug_active_process_stop(self.pid)
        _pydbg.terminate_process(self.h_proc, 0)
        _pydbg.close_handle(self.h_proc)
        _pydbg.close_handle(self.h_thr)

    def test_get_thread_context(self):
        """Verify get_thread_context returns registers for host architecture."""
        ctx = _pydbg.get_thread_context(self.h_thr)
        self.assertIn(IP_REG, ctx)
        self.assertIn(SP_REG, ctx)
        self.assertIn(GP_REG, ctx)
        self.assertIn("eflags", ctx)
        self.assertIn("arch", ctx)
        self.assertIsInstance(ctx[IP_REG], int)

    def test_open_thread(self):
        """Verify open_thread returns valid handle."""
        h = _pydbg.open_thread(self.tid)
        self.assertGreater(h, 0)
        _pydbg.close_handle(h)

    def test_suspend_resume(self):
        """Verify suspend and resume cycle."""
        h = _pydbg.open_thread(self.tid)
        count = _pydbg.suspend_thread(h)
        self.assertGreaterEqual(count, 0)

        count2 = _pydbg.resume_thread(h)
        self.assertGreaterEqual(count2, 0)

        _pydbg.close_handle(h)


class TestDebuggerThreadAPI(unittest.TestCase):
    """Tests for high-level thread API."""

    def test_get_registers(self):
        """Verify Debugger.get_registers returns dict."""
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        h_thread = dbg.open_thread(tid)
        regs = dbg.get_registers(h_thread)
        self.assertIn(IP_REG, regs)
        self.assertIn(SP_REG, regs)

        _pydbg.close_handle(h_thread)
        dbg.detach()
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)


if __name__ == "__main__":
    unittest.main()
