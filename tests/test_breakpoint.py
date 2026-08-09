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
        # detach() now closes + clears the main-session handles
        dbg.detach()
        self.assertIsNone(dbg._session.process_handle)
        self.assertIsNone(dbg._session.thread_handle)

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
        # detach() now closes + clears the main-session handles
        dbg.detach()
        self.assertIsNone(dbg._session.process_handle)
        self.assertIsNone(dbg._session.thread_handle)


class TestBreakpointLifecycle(unittest.TestCase):
    """Tests for automatic breakpoint lifecycle management."""

    def setUp(self):
        self.pid, self.tid, self.h_proc, self.h_thr = _pydbg.create_process(
            TEST_TARGET_PATH
        )
        _pydbg.wait_for_debug_event(5000)
        _pydbg.continue_debug_event(self.pid, self.tid)
        # Consume until initial breakpoint
        for _ in range(20):
            event = _pydbg.wait_for_debug_event(2000)
            if event is None or event.get("event_name") == "EXIT_PROCESS":
                break
            if event.get("event_name") == "EXCEPTION":
                break
            _pydbg.continue_debug_event(event["pid"], event["tid"])

    def tearDown(self):
        _pydbg.terminate_process(self.h_proc, 0)
        for _ in range(50):
            try:
                event = _pydbg.wait_for_debug_event(2000)
                if event is None:
                    break
                _pydbg.continue_debug_event(event["pid"], event["tid"])
                if event.get("event_name") == "EXIT_PROCESS":
                    break
            except OSError:
                break
        _pydbg.close_handle(self.h_proc)
        _pydbg.close_handle(self.h_thr)

    def test_handle_breakpoint_hit_removes_int3(self):
        """Verify handle_breakpoint_hit restores original byte and sets TF."""
        from pydbg import Debugger

        dbg = Debugger()
        dbg._session.pid = self.pid
        dbg._session.process_handle = self.h_proc

        modules = dbg.enum_modules()
        base = modules[0]["base_address"]
        original_byte = dbg.read_memory(base, 1)

        # Set breakpoint (writes INT3)
        bp_id = dbg.set_breakpoint(base)
        self.assertEqual(dbg.read_memory(base, 1), b"\xcc")

        # Simulate breakpoint hit lifecycle
        handled = dbg.brk_sw.handle_breakpoint_hit(self.tid, base)
        self.assertTrue(handled, "breakpoint hit should be handled")

        # INT3 should be removed — original byte restored
        self.assertEqual(dbg.read_memory(base, 1), original_byte)

        # Pending single-step should be scheduled
        self.assertIn(self.tid, dbg._session.pending_single_step)

        dbg.remove_breakpoint(bp_id)

    def test_handle_single_step_restores_int3(self):
        """Verify handle_single_step restores INT3 after single-step."""
        from pydbg import Debugger

        dbg = Debugger()
        dbg._session.pid = self.pid
        dbg._session.process_handle = self.h_proc

        modules = dbg.enum_modules()
        base = modules[0]["base_address"]

        # Set breakpoint and simulate hit
        bp_id = dbg.set_breakpoint(base)
        dbg.brk_sw.handle_breakpoint_hit(self.tid, base)
        # INT3 is now removed, pending single-step is set

        # Simulate single-step event
        handled = dbg.brk_sw.handle_single_step(self.tid)
        self.assertTrue(handled, "single-step should be handled")

        # INT3 should be restored
        self.assertEqual(dbg.read_memory(base, 1), b"\xcc")

        # Pending single-step should be cleared
        self.assertNotIn(self.tid, dbg._session.pending_single_step)

        dbg.remove_breakpoint(bp_id)

    def test_lifecycle_full_cycle(self):
        """Full cycle: set BP -> hit -> remove INT3 -> single-step -> restore INT3."""
        from pydbg import Debugger

        dbg = Debugger()
        dbg._session.pid = self.pid
        dbg._session.process_handle = self.h_proc

        modules = dbg.enum_modules()
        base = modules[0]["base_address"]
        original_byte = dbg.read_memory(base, 1)

        bp_id = dbg.set_breakpoint(base)

        # Step 1: breakpoint hit — removes INT3, sets TF
        dbg.brk_sw.handle_breakpoint_hit(self.tid, base)
        self.assertEqual(dbg.read_memory(base, 1), original_byte)

        # Step 2: single-step — restores INT3
        dbg.brk_sw.handle_single_step(self.tid)
        self.assertEqual(dbg.read_memory(base, 1), b"\xcc")

        dbg.remove_breakpoint(bp_id)


class TestSoftwareBreakpointManagerFixes(unittest.TestCase):
    """Regression tests for SoftwareBreakpointManager bug fixes."""

    def test_remove_does_not_pop_on_type_mismatch(self):
        """remove() must not mutate breakpoints dict when type is wrong."""
        from pydbg.core.session import DebugSession
        from pydbg.breakpoint.software import SoftwareBreakpointManager
        from pydbg.exceptions import BreakpointError

        session = DebugSession()
        session.breakpoints[7] = ("hw", 0x1000, 0)  # a hardware entry
        mgr = SoftwareBreakpointManager(session)
        with self.assertRaises(BreakpointError):
            mgr.remove(7)
        self.assertIn(7, session.breakpoints)  # must NOT have been popped

    def test_remove_not_found_raises(self):
        """remove() of an unknown id raises without mutating the dict."""
        from pydbg.core.session import DebugSession
        from pydbg.breakpoint.software import SoftwareBreakpointManager
        from pydbg.exceptions import BreakpointError

        session = DebugSession()
        mgr = SoftwareBreakpointManager(session)
        with self.assertRaises(BreakpointError):
            mgr.remove(999)
        self.assertEqual(session.breakpoints, {})

    def test_hw_remove_does_not_pop_on_type_mismatch(self):
        """HardwareBreakpointManager.remove must not pop on type mismatch."""
        from pydbg.core.session import DebugSession
        from pydbg.breakpoint.hardware import HardwareBreakpointManager
        from pydbg.exceptions import BreakpointError

        session = DebugSession()
        session.breakpoints[8] = ("int3", 0x2000, b"\x90")
        mgr = HardwareBreakpointManager(session)
        with self.assertRaises(BreakpointError):
            mgr.remove(8)
        self.assertIn(8, session.breakpoints)

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_handle_bp_hit_tf_failure_rearms_int3(self):
        """If TF cannot be set, INT3 must be re-armed (no permanent removal)."""
        from unittest import mock
        from tests.helpers import create_debugger, teardown, entry_point

        dbg, pid, tid = create_debugger()
        try:
            entry = entry_point(dbg)
            bp_id = dbg.set_breakpoint(entry)
            self.assertEqual(dbg.read_memory(entry, 1), b"\xcc")
            with mock.patch("pydbg.breakpoint.software._pydbg.open_thread",
                            side_effect=OSError(5, "mock")):
                handled = dbg.brk_sw.handle_breakpoint_hit(tid, entry)
            self.assertTrue(handled)
            # INT3 must be restored even though TF could not be set
            self.assertEqual(dbg.read_memory(entry, 1), b"\xcc")
            dbg.remove_breakpoint(bp_id)
        finally:
            teardown(dbg)


class TestBPDeliveryAPI(unittest.TestCase):
    """Live coverage for the branch's new BP delivery API."""

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_manual_bp_lifecycle(self):
        """wait_event/continue_event + handle_bp_manual/handle_ss_manual."""
        from pydbg.exceptions import BreakpointError
        from tests.helpers import create_debugger, teardown, entry_point

        dbg, pid, tid = create_debugger()
        try:
            entry = entry_point(dbg)
            orig = dbg.read_memory(entry, 1)  # original byte before INT3
            bp_id = dbg.set_breakpoint(entry)
            dbg.continue_event(pid, tid)

            bp_seen = ss_seen = False
            for _ in range(100):
                ev = dbg.wait_event(2000)
                if ev is None:
                    break
                if ev.type == "EXCEPTION":
                    if ev.exception_code == 0x80000003 and ev.exception_addr == entry:
                        handled = dbg.handle_bp_manual(ev.tid, ev.exception_addr)
                        self.assertTrue(handled)
                        # INT3 removed at delivery time -> original byte back
                        self.assertEqual(dbg.read_memory(entry, 1), orig)
                        bp_seen = True
                        dbg.continue_event(ev.pid, ev.tid)
                        continue
                    if ev.exception_code == 0x80000004:  # single-step
                        handled = dbg.handle_ss_manual(ev.tid)
                        self.assertTrue(handled)
                        # INT3 re-armed after single-step
                        self.assertEqual(dbg.read_memory(entry, 1), b"\xcc")
                        ss_seen = True
                        dbg.continue_event(ev.pid, ev.tid)
                        continue
                dbg.continue_event(ev.pid, ev.tid)
                if ev.type == "EXIT_PROCESS":
                    break
            self.assertTrue(bp_seen, "breakpoint was not hit")
            self.assertTrue(ss_seen, "single-step was not handled")
            try:
                dbg.remove_breakpoint(bp_id)
            except BreakpointError:
                pass  # process may have already exited; INT3 is moot
        finally:
            teardown(dbg)

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_remove_all_breakpoints_restores_bytes(self):
        from tests.helpers import create_debugger, teardown, entry_point

        dbg, pid, tid = create_debugger()
        try:
            entry = entry_point(dbg)
            orig1 = dbg.read_memory(entry, 1)
            orig2 = dbg.read_memory(entry + 2, 1)
            dbg.set_breakpoint(entry)
            dbg.set_breakpoint(entry + 2)
            self.assertEqual(dbg.read_memory(entry, 1), b"\xcc")
            dbg.remove_all_breakpoints()
            self.assertEqual(dbg.read_memory(entry, 1), orig1)
            self.assertEqual(dbg.read_memory(entry + 2, 1), orig2)
            self.assertEqual(dbg._session.breakpoints, {})
            self.assertIsNone(dbg.find_breakpoint(entry))
        finally:
            teardown(dbg)

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_handle_bp_manual_unknown_addr_returns_false(self):
        from tests.helpers import create_debugger, teardown

        dbg, pid, tid = create_debugger()
        try:
            # no breakpoint set -> not ours
            self.assertFalse(dbg.handle_bp_manual(tid, 0x99999999))
            self.assertFalse(dbg.handle_ss_manual(tid))
        finally:
            teardown(dbg)


if __name__ == "__main__":
    unittest.main()
