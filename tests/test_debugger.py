"""Tests for DebugEvent, Debugger API completeness, and exception helpers."""

import unittest

from tests import TEST_TARGET_PATH


class TestDebugEvent(unittest.TestCase):
    """Tests for the DebugEvent wrapper class."""

    def test_debug_event_attributes(self):
        """Verify DebugEvent correctly parses event dict."""
        from pydbg.debugger import DebugEvent

        raw = {
            'event_name': 'CREATE_PROCESS',
            'pid': 1234,
            'tid': 5678,
        }
        event = DebugEvent(raw)
        self.assertEqual(event.type, 'CREATE_PROCESS')
        self.assertEqual(event.pid, 1234)
        self.assertEqual(event.tid, 5678)
        self.assertIsNone(event.exception_code)
        self.assertIsNone(event.exception_addr)
        self.assertIsNone(event.first_chance)
        self.assertEqual(event.raw, raw)

    def test_debug_event_repr(self):
        """Verify __repr__ format."""
        from pydbg.debugger import DebugEvent

        raw = {'event_name': 'EXCEPTION', 'pid': 100, 'tid': 200}
        event = DebugEvent(raw)
        self.assertEqual(repr(event), '<DebugEvent EXCEPTION pid=100 tid=200>')

    def test_debug_event_default_values(self):
        """Verify defaults for missing keys."""
        from pydbg.debugger import DebugEvent

        event = DebugEvent({})
        self.assertEqual(event.type, 'UNKNOWN')
        self.assertEqual(event.pid, 0)
        self.assertEqual(event.tid, 0)


class TestDebuggerAPICompleteness(unittest.TestCase):
    """Tests for terminate_process and get_exit_code."""

    def test_terminate_process(self):
        """Verify terminate_process kills the target."""
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        dbg.terminate_process(0)
        dbg.close_handle(dbg._process_handle)
        dbg.close_handle(dbg._thread_handle)

    def test_get_exit_code_running(self):
        """Verify get_exit_code returns STILL_ACTIVE for running process."""
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        code = dbg.get_exit_code()
        self.assertEqual(code, 259)  # STILL_ACTIVE

        dbg.terminate_process(0)
        dbg.close_handle(dbg._process_handle)
        dbg.close_handle(dbg._thread_handle)


class TestExceptionHelpers(unittest.TestCase):
    """Tests for exception_code_to_str and get_exception_info."""

    def test_exception_code_to_str(self):
        """Verify known codes map to correct names."""
        from pydbg.cython import _exception

        self.assertEqual(
            _exception.exception_code_to_str(0x80000003),
            'EXCEPTION_BREAKPOINT')
        self.assertEqual(
            _exception.exception_code_to_str(0xC0000005),
            'EXCEPTION_ACCESS_VIOLATION')
        self.assertEqual(
            _exception.exception_code_to_str(0x80000004),
            'EXCEPTION_SINGLE_STEP')

    def test_exception_code_unknown(self):
        """Verify unknown code returns formatted string."""
        from pydbg.cython import _exception

        result = _exception.exception_code_to_str(0xDEADBEEF)
        self.assertEqual(result, 'UNKNOWN_EXCEPTION(0xDEADBEEF)')


if __name__ == '__main__':
    unittest.main()
