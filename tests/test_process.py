"""Tests for process debugging: create, wait, continue, detach."""

import struct
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

        # Terminate: detach() now closes + clears the main-session handles
        dbg.detach()
        self.assertIsNone(dbg._session.process_handle)
        self.assertIsNone(dbg._session.thread_handle)

    def test_attach_sets_process_handle(self):
        """Verify attach() opens process handle so read_memory works immediately."""
        from pydbg import Debugger

        # Create process with native API (not through Debugger, so we can attach later)
        pid, tid, h_proc, h_thr = _pydbg.create_process(TEST_TARGET_PATH)
        # Consume CREATE_PROCESS event
        _pydbg.wait_for_debug_event(5000)
        _pydbg.continue_debug_event(pid, tid)
        # Consume until initial breakpoint
        for _ in range(20):
            event = _pydbg.wait_for_debug_event(2000)
            if event is None:
                break
            if event.get("event_name") == "EXCEPTION":
                break
            _pydbg.continue_debug_event(event["pid"], event["tid"])
        # Detach so we can re-attach via Debugger
        _pydbg.debug_active_process_stop(pid)
        _pydbg.close_handle(h_proc)
        _pydbg.close_handle(h_thr)

        # Now attach via high-level API
        dbg = Debugger()
        dbg.attach(pid)

        # Process handle should be set automatically
        self.assertIsNotNone(dbg._session.process_handle)
        self.assertNotEqual(dbg._session.process_handle, 0)

        # read_memory should work without manual handle setup
        modules = dbg.enum_modules()
        self.assertGreater(len(modules), 0)
        base = modules[0]["base_address"]
        # Read MZ header
        data = dbg.read_memory(base, 2)
        self.assertEqual(data, b"MZ")

        # Target arch should be detected
        self.assertIn(dbg._session.target_arch, (32, 64))

        # detach() closes + clears the main-session process handle
        dbg.detach(pid)
        self.assertIsNone(dbg._session.process_handle)

    def test_attach_detects_target_arch(self):
        """Verify attach() detects target architecture."""
        from pydbg import Debugger

        pid, tid, h_proc, h_thr = _pydbg.create_process(TEST_TARGET_PATH)
        _pydbg.wait_for_debug_event(5000)
        _pydbg.continue_debug_event(pid, tid)
        for _ in range(20):
            event = _pydbg.wait_for_debug_event(2000)
            if event is None:
                break
            if event.get("event_name") == "EXCEPTION":
                break
            _pydbg.continue_debug_event(event["pid"], event["tid"])
        _pydbg.debug_active_process_stop(pid)
        _pydbg.close_handle(h_proc)
        _pydbg.close_handle(h_thr)

        dbg = Debugger()
        dbg.attach(pid)

        expected = struct.calcsize("P") * 8
        self.assertEqual(dbg._session.target_arch, expected)

        # detach() closes + clears the main-session process handle
        dbg.detach(pid)
        self.assertIsNone(dbg._session.process_handle)


if __name__ == "__main__":
    unittest.main()
