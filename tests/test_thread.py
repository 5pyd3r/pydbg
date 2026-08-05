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


# Arch-safe invalid tid/pid for ThreadManager error-path tests. Must fit the
# signed 32-bit C `int` param used by _pydbg.open_thread/enumerate_threads on
# both x64 and x86 Windows (0xFFFFFFF0 would raise OverflowError at the
# Python->Cython boundary instead of reaching the Win32 call). No real
# tid/pid is this large, so OpenThread fails with ERROR_INVALID_PARAMETER.
INVALID_TID = 0x7FFFFFF0


class TestThreadManagerCoverage(unittest.TestCase):
    """Live-process coverage for ThreadManager error paths, step, get_ids."""

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def setUp(self):
        from tests.helpers import create_debugger
        self.dbg, self.pid, self.tid = create_debugger()

    def tearDown(self):
        from tests.helpers import teardown
        teardown(self.dbg)

    def test_step_sets_trap_flag(self):
        h_thread = self.dbg.open_thread(self.tid)
        self.dbg.step(h_thread)  # sets TF (0x100)
        regs = self.dbg.get_registers(h_thread)
        self.assertTrue(regs["eflags"] & 0x100)
        # clear TF so the paused process does not single-step unexpectedly
        self.dbg.set_register(h_thread, "eflags", regs["eflags"] & ~0x100)
        self.dbg.close_handle(h_thread)

    def test_get_ids(self):
        tids = self.dbg.thread.get_ids(self.pid)
        self.assertIsInstance(tids, list)
        self.assertIn(self.tid, tids)

    def test_open_invalid_tid_raises(self):
        from pydbg.exceptions import ThreadError
        with self.assertRaises(ThreadError):
            self.dbg.thread.open(INVALID_TID)

    def test_get_context_invalid_handle_raises(self):
        from pydbg.exceptions import ThreadError
        with self.assertRaises(ThreadError):
            self.dbg.thread.get_context(0)

    def test_set_context_invalid_handle_raises(self):
        from pydbg.exceptions import ThreadError
        with self.assertRaises(ThreadError):
            self.dbg.thread.set_context(0, {})

    def test_suspend_invalid_handle_raises(self):
        from pydbg.exceptions import ThreadError
        with self.assertRaises(ThreadError):
            self.dbg.thread.suspend(0)

    def test_resume_invalid_handle_raises(self):
        from pydbg.exceptions import ThreadError
        with self.assertRaises(ThreadError):
            self.dbg.thread.resume(0)

    def test_enumerate_unknown_pid_empty(self):
        # CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid) succeeds for any
        # pid -- the pid only filters the snapshot -- so an unknown/out-of-range
        # pid yields an empty list rather than raising.
        self.assertEqual(self.dbg.thread.enumerate(INVALID_TID), [])


if __name__ == "__main__":
    unittest.main()
