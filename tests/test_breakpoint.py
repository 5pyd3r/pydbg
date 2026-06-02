"""Tests for hardware breakpoints."""

import unittest

from tests import TEST_TARGET_PATH, IP_REG

try:
    from pydbg import _pydbg

    _has_cython = True
except ImportError:
    _has_cython = False


class TestHardwareBreakpoint(unittest.TestCase):
    """Test setting and clearing hardware breakpoints."""

    def setUp(self):
        self.pid, self.tid, self.h_proc, self.h_thr = _pydbg.create_process(
            TEST_TARGET_PATH
        )
        _pydbg.wait_for_debug_event(5000)
        _pydbg.continue_debug_event(self.pid, self.tid)

        for _ in range(20):
            event = _pydbg.wait_for_debug_event(5000)
            if event is None:
                break
            if event["event_name"] == "EXCEPTION":
                break
            _pydbg.continue_debug_event(event["pid"], event["tid"])

    def tearDown(self):
        _pydbg.debug_active_process_stop(self.pid)
        _pydbg.terminate_process(self.h_proc, 0)
        _pydbg.close_handle(self.h_proc)
        _pydbg.close_handle(self.h_thr)

    def test_set_hw_breakpoint(self):
        """Set an execute breakpoint at image base."""
        modules = _pydbg.enum_process_modules(self.h_proc)
        base = modules[0]["base_address"]

        result = _pydbg.set_hw_breakpoint(
            self.h_thr, slot=0, addr=base, condition=0, length=0
        )  # execute, 1 byte
        self.assertEqual(result, 0)

        # Clean up
        _pydbg.clear_hw_breakpoint(self.h_thr, slot=0)

    def test_clear_hw_breakpoint(self):
        """Set then clear a breakpoint."""
        modules = _pydbg.enum_process_modules(self.h_proc)
        base = modules[0]["base_address"]

        _pydbg.set_hw_breakpoint(self.h_thr, 0, base, 0, 0)
        result = _pydbg.clear_hw_breakpoint(self.h_thr, 0)
        self.assertEqual(result, 0)

    def test_invalid_slot(self):
        """Verify invalid slot raises ValueError."""
        with self.assertRaises(ValueError):
            _pydbg.set_hw_breakpoint(self.h_thr, 5, 0x1000, 0, 0)


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
        addr = regs[IP_REG]

        bp_id = dbg.set_breakpoint(addr)
        self.assertGreater(bp_id, 0)

        dbg.remove_breakpoint(bp_id)

        _pydbg.close_handle(h_thread)
        dbg.detach()
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    def test_breakpoint_restores_page_protection(self):
        """Verify set/remove int3 restores original page protection."""
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        # Consume events until initial breakpoint
        for _ in range(50):
            event = dbg.wait_event(2000)
            if event is None or event.type == "EXIT_PROCESS":
                break
            if event.type == "EXCEPTION":
                break
            dbg.continue_event(event.pid, event.tid)

        modules = dbg.enum_modules()
        base = modules[0]["base_address"]

        # Record protection before setting breakpoint
        prot_before = dbg.query_memory(base)
        original_prot = prot_before["protect"]

        # Set breakpoint and verify protection is restored after
        bp_id = dbg.set_breakpoint(base)
        prot_after_set = dbg.query_memory(base)
        self.assertEqual(prot_after_set["protect"], original_prot,
                         "Page protection should be restored after set_breakpoint")

        # Remove breakpoint and verify protection is still correct
        dbg.remove_breakpoint(bp_id)
        prot_after_remove = dbg.query_memory(base)
        self.assertEqual(prot_after_remove["protect"], original_prot,
                         "Page protection should be restored after remove_breakpoint")

        dbg.terminate_process(0)
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
        addr = regs[IP_REG]

        bp_id = dbg.set_hw_breakpoint(addr, "x", 1, 0)
        self.assertGreater(bp_id, 0)

        dbg.remove_breakpoint(bp_id)

        _pydbg.close_handle(h_thread)
        dbg.detach()
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)


if __name__ == "__main__":
    unittest.main()
