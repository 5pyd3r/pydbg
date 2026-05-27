"""Tests for hardware breakpoints."""

import unittest
from tests import TEST_TARGET_PATH

try:
    from pydbg.cython import _process
    _has_cython = True
except ImportError:
    _has_cython = False


@unittest.skipUnless(_has_cython, "Requires compiled Cython extensions")
class TestHardwareBreakpoint(unittest.TestCase):
    """Test setting and clearing hardware breakpoints."""

    def setUp(self):
        self.pid, self.tid, self.h_proc, self.h_thr = _process.create_process(
            TEST_TARGET_PATH)
        _process.wait_for_debug_event(5000)
        _process.continue_debug_event(self.pid, self.tid)

        for _ in range(20):
            event = _process.wait_for_debug_event(5000)
            if event is None:
                break
            if event['event_name'] == 'EXCEPTION':
                break
            _process.continue_debug_event(event['pid'], event['tid'])

    def tearDown(self):
        _process.debug_active_process_stop(self.pid)
        _process.terminate_process(self.h_proc, 0)
        _process.close_handle(self.h_proc)
        _process.close_handle(self.h_thr)

    def test_set_hw_breakpoint(self):
        """Set an execute breakpoint at image base."""
        from pydbg.cython import _bp, _memory

        modules = _memory.enum_process_modules(self.h_proc)
        base = modules[0]['base_address']

        result = _bp.set_hw_breakpoint(
            self.h_thr, slot=0, addr=base,
            condition=0, length=0)  # execute, 1 byte
        self.assertEqual(result, 0)

        # Clean up
        _bp.clear_hw_breakpoint(self.h_thr, slot=0)

    def test_clear_hw_breakpoint(self):
        """Set then clear a breakpoint."""
        from pydbg.cython import _bp, _memory

        modules = _memory.enum_process_modules(self.h_proc)
        base = modules[0]['base_address']

        _bp.set_hw_breakpoint(self.h_thr, 0, base, 0, 0)
        result = _bp.clear_hw_breakpoint(self.h_thr, 0)
        self.assertEqual(result, 0)

    def test_invalid_slot(self):
        """Verify invalid slot raises ValueError."""
        from pydbg.cython import _bp

        with self.assertRaises(ValueError):
            _bp.set_hw_breakpoint(self.h_thr, 5, 0x1000, 0, 0)


@unittest.skipUnless(_has_cython, "Requires compiled Cython extensions")
class TestDebuggerBreakpointAPI(unittest.TestCase):
    """Tests for high-level breakpoint API."""

    def test_set_and_remove_int3(self):
        """Set int3 breakpoint, then remove."""
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        # Get a code address
        h_thread = dbg.open_thread(tid)
        regs = dbg.get_registers(h_thread)
        addr = regs['rip']

        bp_id = dbg.set_breakpoint(addr)
        self.assertGreater(bp_id, 0)

        dbg.remove_breakpoint(bp_id)

        _process.close_handle(h_thread)
        dbg.detach()
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    def test_set_hw_breakpoint_via_api(self):
        """Set hw breakpoint via high-level API."""
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        h_thread = dbg.open_thread(tid)
        regs = dbg.get_registers(h_thread)
        addr = regs['rip']

        bp_id = dbg.set_hw_breakpoint(addr, 'x', 1, 0)
        self.assertGreater(bp_id, 0)

        dbg.remove_breakpoint(bp_id)

        _process.close_handle(h_thread)
        dbg.detach()
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)


if __name__ == '__main__':
    unittest.main()
