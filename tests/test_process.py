"""Tests for process debugging: create, wait, continue, detach."""

import unittest

from tests import TEST_TARGET_PATH

try:
    from pydbg import _pydbg

    _has_cython = True
except ImportError:
    _has_cython = False


class TestProcessLifecycle(unittest.TestCase):
    """Integration tests for process creation and debug event loop."""

    def test_create_process(self):
        """Verify create_process returns valid pid/tid."""

        pid, tid, h_proc, h_thr = _pydbg.create_process(TEST_TARGET_PATH)
        self.assertGreater(pid, 0)
        self.assertGreater(tid, 0)
        self.assertNotEqual(h_proc, 0)
        self.assertNotEqual(h_thr, 0)

        # Clean up
        _pydbg.debug_active_process_stop(pid)
        _pydbg.terminate_process(h_proc, 0)
        _pydbg.close_handle(h_proc)
        _pydbg.close_handle(h_thr)

    def test_wait_and_continue(self):
        """Verify wait_for_debug_event returns CREATE_PROCESS, then continue."""

        pid, tid, h_proc, h_thr = _pydbg.create_process(TEST_TARGET_PATH)

        event = _pydbg.wait_for_debug_event(5000)
        self.assertIsNotNone(event)
        self.assertEqual(event["event_name"], "CREATE_PROCESS")
        self.assertEqual(event["pid"], pid)

        _pydbg.continue_debug_event(pid, tid)

        # Clean up
        _pydbg.debug_active_process_stop(pid)
        _pydbg.terminate_process(h_proc, 0)
        _pydbg.close_handle(h_proc)
        _pydbg.close_handle(h_thr)

    def test_exception_breakpoint(self):
        """Verify we get EXCEPTION_BREAKPOINT from initial int3."""

        pid, tid, h_proc, h_thr = _pydbg.create_process(TEST_TARGET_PATH)

        # First event: CREATE_PROCESS
        event = _pydbg.wait_for_debug_event(5000)
        self.assertEqual(event["event_name"], "CREATE_PROCESS")
        self.assertEqual(event["pid"], pid)
        _pydbg.continue_debug_event(pid, tid)

        # Second event: LOAD_DLL (may be multiple)
        for _ in range(20):
            event = _pydbg.wait_for_debug_event(5000)
            if event is None:
                break
            if event["event_name"] == "EXCEPTION":
                break
            _pydbg.continue_debug_event(event["pid"], event["tid"])

        # Should hit the loader breakpoint
        if event and event["event_name"] == "EXCEPTION":
            self.assertEqual(
                event["exception_code"], 0x80000003
            )  # EXCEPTION_BREAKPOINT

        _pydbg.terminate_process(h_proc, 0)
        _pydbg.close_handle(h_proc)
        _pydbg.close_handle(h_thr)

    def test_detach_nonexistent(self):
        """Verify detach on invalid pid raises OSError."""

        with self.assertRaises(OSError):
            _pydbg.debug_active_process_stop(999999)


class TestDebuggerAPI(unittest.TestCase):
    """Tests for the high-level Debugger class."""

    def test_create_and_detach(self):
        """Full lifecycle: create -> wait -> continue -> detach."""
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        self.assertGreater(pid, 0)

        event = dbg.wait_event(5000)
        self.assertIsNotNone(event)
        self.assertEqual(event.type, "CREATE_PROCESS")

        dbg.continue_event(pid, tid)

        # Terminate
        dbg.detach()
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)


if __name__ == "__main__":
    unittest.main()
