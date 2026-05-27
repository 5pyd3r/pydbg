"""Tests for DebugEvent, Debugger API completeness, exception helpers, and new features."""

import unittest

from tests import TEST_TARGET_PATH

try:
    from pydbg.cython import _process
    _has_cython = True
except ImportError:
    _has_cython = False


class TestDebugEvent(unittest.TestCase):
    """Tests for the DebugEvent wrapper class."""

    def test_debug_event_attributes(self):
        """Verify DebugEvent correctly parses event dict."""
        from pydbg import DebugEvent

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
        from pydbg import DebugEvent

        raw = {'event_name': 'EXCEPTION', 'pid': 100, 'tid': 200}
        event = DebugEvent(raw)
        self.assertEqual(repr(event), '<DebugEvent EXCEPTION pid=100 tid=200>')

    def test_debug_event_default_values(self):
        """Verify defaults for missing keys."""
        from pydbg import DebugEvent

        event = DebugEvent({})
        self.assertEqual(event.type, 'UNKNOWN')
        self.assertEqual(event.pid, 0)
        self.assertEqual(event.tid, 0)

    def test_debug_event_exception_fields(self):
        """Verify DebugEvent populates exception_name and exception_info."""
        from pydbg import DebugEvent

        raw = {
            'event_name': 'EXCEPTION',
            'pid': 100,
            'tid': 200,
            'exception_code': 0x80000003,
            'exception_addr': 0x1000,
            'first_chance': True,
            'exception_params': [],
        }
        event = DebugEvent(raw)
        self.assertEqual(event.exception_name, 'EXCEPTION_BREAKPOINT')
        self.assertIsNotNone(event.exception_info)
        self.assertEqual(event.exception_info['name'], 'EXCEPTION_BREAKPOINT')


@unittest.skipUnless(_has_cython, "Requires compiled Cython extensions")
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
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

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
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)


@unittest.skipUnless(_has_cython, "Requires compiled Cython extensions")
class TestExceptionHelpers(unittest.TestCase):
    """Tests for exception_code_to_str."""

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

    def test_debugger_exception_code_to_str(self):
        """Verify Debugger.exception_code_to_str delegates to Cython."""
        from pydbg import Debugger

        dbg = Debugger()
        self.assertEqual(
            dbg.exception_code_to_str(0x80000003), 'EXCEPTION_BREAKPOINT')
        self.assertEqual(
            dbg.exception_code_to_str(0xC0000005), 'EXCEPTION_ACCESS_VIOLATION')

    def test_debugger_get_exception_info(self):
        """Verify Debugger.get_exception_info parses access violation."""
        from pydbg import Debugger

        dbg = Debugger()
        info = dbg.get_exception_info(
            0xC0000005, 0xDEAD, 1, [0, 0xDEAD])
        self.assertEqual(info['name'], 'EXCEPTION_ACCESS_VIOLATION')
        self.assertEqual(info['access_type'], 'read')
        self.assertEqual(info['access_addr'], 0xDEAD)


@unittest.skipUnless(_has_cython, "Requires compiled Cython extensions")
class TestRemoveHwBreakpoint(unittest.TestCase):
    """Tests for hardware breakpoint removal."""

    def test_remove_hw_breakpoint(self):
        """Verify remove_breakpoint works for HW breakpoints without error."""
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        h_thread = dbg.open_thread(tid)
        regs = dbg.get_registers(h_thread)
        bp_id = dbg.set_hw_breakpoint(regs['rip'], condition='x', length=1, slot=0)

        dbg.remove_breakpoint(bp_id)
        self.assertIsNone(dbg.find_breakpoint(regs['rip']))

        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)


@unittest.skipUnless(_has_cython, "Requires compiled Cython extensions")
class TestRunLoop(unittest.TestCase):
    """Tests for the event-driven debug loop."""

    def test_run_with_callback(self):
        """Verify run() dispatches events to callback and returns exit code."""
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)

        events = []

        def on_event(event):
            events.append(event.type)

        exit_code = dbg.run(on_event, timeout_ms=5000)

        self.assertIn('CREATE_PROCESS', events)
        self.assertIsInstance(exit_code, int)


@unittest.skipUnless(_has_cython, "Requires compiled Cython extensions")
class TestThreadEnumeration(unittest.TestCase):
    """Tests for thread enumeration."""

    def setUp(self):
        self.pid, self.tid, self.h_proc, self.h_thr = _process.create_process(
            TEST_TARGET_PATH)
        _process.wait_for_debug_event(5000)
        _process.continue_debug_event(self.pid, self.tid)

    def tearDown(self):
        _process.terminate_process(self.h_proc, 0)
        _process.close_handle(self.h_proc)
        _process.close_handle(self.h_thr)

    def test_enumerate_threads(self):
        """Verify enumerate_threads returns at least one thread."""
        from pydbg.cython import _thread

        threads = _thread.enumerate_threads(self.pid)
        self.assertGreater(len(threads), 0)
        self.assertIn('tid', threads[0])

    def test_get_thread_ids(self):
        """Verify Debugger.get_thread_ids returns list of ints."""
        from pydbg import Debugger

        dbg = Debugger()
        dbg._session.pid = self.pid
        dbg._session.process_handle = self.h_proc

        tids = dbg.get_thread_ids()
        self.assertGreater(len(tids), 0)
        self.assertIsInstance(tids[0], int)


@unittest.skipUnless(_has_cython, "Requires compiled Cython extensions")
class TestFindBreakpoint(unittest.TestCase):
    """Tests for find_breakpoint."""

    def test_find_existing_breakpoint(self):
        """Verify find_breakpoint returns correct ID."""
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        modules = dbg.enum_modules()
        base = modules[0]['base_address']
        bp_id = dbg.set_breakpoint(base)

        self.assertEqual(dbg.find_breakpoint(base), bp_id)

        dbg.remove_breakpoint(bp_id)
        self.assertIsNone(dbg.find_breakpoint(base))

        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    def test_find_nonexistent_breakpoint(self):
        """Verify find_breakpoint returns None for unknown address."""
        from pydbg import Debugger

        dbg = Debugger()
        self.assertIsNone(dbg.find_breakpoint(0xDEADBEEF))


if __name__ == '__main__':
    unittest.main()
