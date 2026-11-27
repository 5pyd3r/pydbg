"""Tests for hardware breakpoints."""

import unittest

from tests import IP_REG, TEST_TARGET_PATH, extension_free_module

try:
    from pydbg import _pydbg

    _has_cython = True
except ImportError:
    _has_cython = False


@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
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


@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
class TestHardwareSlotBusy(unittest.TestCase):
    """A reused debug-register slot has its own error type, not a string."""

    def test_a_slot_already_in_use_raises_breakpoint_slot_busy(self):
        from pydbg.breakpoint.hardware import (
            BreakpointSlotBusy, HardwareBreakpointManager,
        )
        from pydbg.breakpoint.model import Breakpoint
        from pydbg.core.session import DebugSession
        from pydbg.exceptions import BreakpointError

        session = DebugSession()
        session.breakpoints[7] = Breakpoint(
            kind="hw", addr=0x401000, slot=0, condition="x", length=1)
        manager = HardwareBreakpointManager(session)

        with self.assertRaises(BreakpointSlotBusy) as caught:
            manager.set(0x401100, "x", 1, 0)

        self.assertIsInstance(caught.exception, BreakpointError,
                              "callers catching BreakpointError must still "
                              "catch a busy slot")
        self.assertIn("hardware breakpoint slot 0 already in use",
                      str(caught.exception),
                      "the message must keep naming the slot")


class TestHardwareDisarmScope(unittest.TestCase):
    """An un-cleared Dr slot on a live thread must not look like a corpse."""

    @staticmethod
    def _armed():
        from pydbg.breakpoint.model import Breakpoint
        from pydbg.core.session import DebugSession

        hardware = extension_free_module("pydbg.breakpoint.hardware")
        session = DebugSession()
        session.breakpoints[4] = Breakpoint(
            kind="hw", addr=0x401000, slot=1, scope=7,
            condition="x", length=1)
        return hardware.HardwareBreakpointManager(session), hardware

    def test_a_live_thread_that_cannot_be_opened_is_reported(self):
        """Only ERROR_INVALID_PARAMETER means the thread (and its DRs) is gone."""
        from unittest import mock

        mgr, hardware = self._armed()
        extension = mock.Mock()
        extension.open_thread.side_effect = OSError(5, "access denied")

        with mock.patch.object(hardware, "_pydbg", extension):
            problems = mgr.teardown()

        self.assertEqual(len(problems), 1, problems)
        what, why = problems[0]
        self.assertIn("hardware breakpoint 4", what)
        self.assertIn("slot 1", what)
        self.assertIn("access denied", why,
                      "a live thread's armed slot was swallowed")

    def test_a_vanished_thread_is_not_a_problem(self):
        """The thread and its debug registers are gone with it."""
        from unittest import mock

        mgr, hardware = self._armed()
        extension = mock.Mock()
        extension.open_thread.side_effect = OSError(
            87, "The parameter is incorrect")

        with mock.patch.object(hardware, "_pydbg", extension):
            self.assertEqual(mgr.teardown(), [])


@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
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


@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
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
        from pydbg.breakpoint.outcome import HandleOutcome

        outcome = dbg.brk_sw.handle_breakpoint_hit(self.tid, base)
        self.assertIs(outcome, HandleOutcome.HANDLED)

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
        from pydbg.breakpoint.outcome import HandleOutcome

        outcome = dbg.brk_sw.handle_single_step(self.tid)
        self.assertIs(outcome, HandleOutcome.HANDLED)

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

    @staticmethod
    def _manager():
        from pydbg.core.session import DebugSession
        from pydbg.breakpoint.software import SoftwareBreakpointManager
        return SoftwareBreakpointManager(DebugSession())

    @unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
    def test_every_write_sequence_restores_protection_after_a_failure(self):
        """A failed write must not leave the page writable.

        The three protect→write→restore sequences are set, restore-byte and
        re-arm. All three used to skip the restore when the write raised; the
        page then stayed PAGE_EXECUTE_READWRITE, which is both a behavioural
        side effect and a detection surface.
        """
        from unittest import mock
        from pydbg.exceptions import BreakpointError

        sequences = {
            "set": lambda mgr: mgr.set_handle(0x1234, 0x401000),
            "restore": lambda mgr: mgr._restore_byte_handle(
                0x1234, 0x401000, b"\x90"),
            "re-arm": lambda mgr: mgr._write_int3_handle(0x1234, 0x401000),
        }
        for name, call in sequences.items():
            with self.subTest(sequence=name):
                mgr = self._manager()
                protect = mock.Mock(side_effect=[0x20, None])
                with mock.patch(
                        "pydbg.breakpoint.software._pydbg.read_process_memory",
                        return_value=b"\x90"), \
                     mock.patch(
                        "pydbg.breakpoint.software._pydbg.virtual_protect_ex",
                        protect), \
                     mock.patch(
                        "pydbg.breakpoint.software._pydbg.write_process_memory",
                        side_effect=OSError(5, "denied")):
                    with self.assertRaises(BreakpointError):
                        call(mgr)
                self.assertEqual(
                    protect.call_count, 2,
                    f"{name}: protection was not restored after the failure")

    @unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
    def test_a_failed_restore_is_reported_with_the_write_error(self):
        """Both failures are named; dropping either hides one of them."""
        from unittest import mock
        from pydbg.exceptions import BreakpointError

        mgr = self._manager()
        protect = mock.Mock(side_effect=[0x20, OSError(5, "cannot restore")])
        with mock.patch(
                "pydbg.breakpoint.software._pydbg.read_process_memory",
                return_value=b"\x90"), \
             mock.patch(
                "pydbg.breakpoint.software._pydbg.virtual_protect_ex",
                protect), \
             mock.patch(
                "pydbg.breakpoint.software._pydbg.write_process_memory",
                side_effect=OSError(5, "denied")):
            with self.assertRaises(BreakpointError) as caught:
                mgr.set_handle(0x1234, 0x401000)

        message = str(caught.exception)
        self.assertIn("denied", message)
        self.assertIn("restoring protection also failed", message)

    @unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
    def test_a_restore_failure_after_a_successful_write_is_reported(self):
        """The byte landed; the page did not go back. That must not be silent."""
        from unittest import mock
        from pydbg.exceptions import BreakpointError

        mgr = self._manager()
        protect = mock.Mock(side_effect=[0x20, OSError(5, "cannot restore")])
        with mock.patch(
                "pydbg.breakpoint.software._pydbg.read_process_memory",
                return_value=b"\x90"), \
             mock.patch(
                "pydbg.breakpoint.software._pydbg.virtual_protect_ex",
                protect), \
             mock.patch(
                "pydbg.breakpoint.software._pydbg.write_process_memory",
                return_value=None):
            with self.assertRaises(BreakpointError) as caught:
                mgr.set_handle(0x1234, 0x401000)

        message = str(caught.exception)
        self.assertIn("restoring protection failed", message)
        self.assertNotIn("denied", message)

    @unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
    def test_remove_does_not_pop_on_type_mismatch(self):
        """remove() must not mutate breakpoints dict when type is wrong."""
        from pydbg.breakpoint.model import Breakpoint
        from pydbg.core.session import DebugSession
        from pydbg.breakpoint.software import SoftwareBreakpointManager
        from pydbg.exceptions import BreakpointError

        session = DebugSession()
        session.breakpoints[7] = Breakpoint(kind="hw", addr=0x1000, slot=0)  # a hardware entry
        mgr = SoftwareBreakpointManager(session)
        with self.assertRaises(BreakpointError):
            mgr.remove(7)
        self.assertIn(7, session.breakpoints)  # must NOT have been popped

    def test_remove_keeps_the_record_when_the_byte_cannot_be_restored(self):
        """A failed restore leaves the INT3 in the target.

        The record is the only way teardown() can find it again, so remove()
        must not delete it first and then fail the write.
        """
        from unittest import mock
        from pydbg.breakpoint.model import Breakpoint
        from pydbg.core.session import DebugSession
        from pydbg.exceptions import BreakpointError

        software = extension_free_module("pydbg.breakpoint.software")
        session = DebugSession()
        session.breakpoints[5] = Breakpoint(
            kind="int3", addr=0x401000, original=b"\x90", h_process=123)
        mgr = software.SoftwareBreakpointManager(session)
        extension = mock.Mock()
        extension.virtual_protect_ex.return_value = 0x20
        extension.write_process_memory.side_effect = OSError(5, "denied")

        with mock.patch.object(software, "_pydbg", extension):
            with self.assertRaises(BreakpointError) as caught:
                mgr.remove(5)

        message = str(caught.exception)
        self.assertIn("Breakpoint 5", message)
        self.assertIn("0x401000", message)
        self.assertIn(5, session.breakpoints,
                      "a failed restore forgot the INT3 it left behind")

    @unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
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

    @unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
    def test_hw_remove_does_not_pop_on_type_mismatch(self):
        """HardwareBreakpointManager.remove must not pop on type mismatch."""
        from pydbg.breakpoint.model import Breakpoint
        from pydbg.core.session import DebugSession
        from pydbg.breakpoint.hardware import HardwareBreakpointManager
        from pydbg.exceptions import BreakpointError

        session = DebugSession()
        session.breakpoints[8] = Breakpoint(kind="int3", addr=0x2000, original=b"\x90")
        mgr = HardwareBreakpointManager(session)
        with self.assertRaises(BreakpointError):
            mgr.remove(8)
        self.assertIn(8, session.breakpoints)

    @unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
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
                from pydbg.breakpoint.outcome import HandleOutcome

                outcome = dbg.brk_sw.handle_breakpoint_hit(tid, entry)
            self.assertIs(outcome, HandleOutcome.DEGRADED,
                          "a re-armed hit that could not rewind must say so")
            # INT3 must be restored even though TF could not be set
            self.assertEqual(dbg.read_memory(entry, 1), b"\xcc")
            dbg.remove_breakpoint(bp_id)
        finally:
            teardown(dbg)


class TestBPDeliveryAPI(unittest.TestCase):
    """Live coverage for the branch's new BP delivery API."""

    @unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
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

    @unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
    def test_set_same_address_twice_does_not_corrupt(self):
        """Re-arming an address answers with the same bp_id and removes cleanly.

        The second set used to read back the 0xCC the first one had just
        written, store it as the displaced byte, and remove_breakpoint then
        put that 0xCC back for good — a permanent int3 in the middle of a real
        instruction, with no error anywhere.
        """
        from tests.helpers import create_debugger, teardown, entry_point

        dbg, pid, tid = create_debugger()
        try:
            entry = entry_point(dbg)
            original = dbg.read_memory(entry, 1)
            self.assertNotEqual(original, b"\xcc",
                                "target entry is already INT3; pick another site")

            first = dbg.set_breakpoint(entry)
            second = dbg.set_breakpoint(entry)
            self.assertEqual(first, second,
                             "the same address must answer with one bp_id")
            self.assertEqual(len(dbg._session.breakpoints), 1)
            self.assertEqual(dbg.read_memory(entry, 1), b"\xcc")
            self.assertEqual(dbg._session.breakpoints[first].original, original,
                             "the displaced byte must still be the target's own")

            dbg.remove_breakpoint(first)
            self.assertEqual(dbg.read_memory(entry, 1), original)
            self.assertEqual(dbg._session.breakpoints, {})
        finally:
            teardown(dbg)

    @unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
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

    @unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
    def test_handle_bp_manual_unknown_addr_returns_false(self):
        from tests.helpers import create_debugger, teardown

        dbg, pid, tid = create_debugger()
        try:
            # no breakpoint set -> not ours
            self.assertFalse(dbg.handle_bp_manual(tid, 0x99999999))
            self.assertFalse(dbg.handle_ss_manual(tid))
        finally:
            teardown(dbg)


class TestSoftwareBreakpointProcessScope(unittest.TestCase):
    """A software breakpoint belongs to (process, address), not to an address."""

    ADDR = 0x401000

    @staticmethod
    def _session_with_child():
        from pydbg.core.session import ChildProcessInfo, DebugSession

        session = DebugSession()
        session.pid = 1000
        session.process_handle = 0x1000
        session.child_processes[2000] = ChildProcessInfo(
            pid=2000, tid=2001, process_handle=0x2000, thread_handle=0x2001)
        session.register_thread(1001, 1000)
        session.register_thread(2001, 2000)
        return session

    def _patched(self, software, originals, writer):
        """The Win32 calls a set/hit lifecycle makes, without a real target."""
        from unittest import mock

        return mock.patch.multiple(
            software._pydbg,
            create=True,
            read_process_memory=mock.Mock(
                side_effect=lambda h, addr, size: originals[h]),
            virtual_protect_ex=mock.Mock(return_value=0x20),
            write_process_memory=writer,
            open_thread=mock.Mock(return_value=0x3000),
            get_thread_context=mock.Mock(return_value={"rip": self.ADDR + 1}),
            set_thread_context=mock.Mock(),
            close_handle=mock.Mock())

    def test_a_child_hit_restores_through_the_child_handle(self):
        """Both processes hold 0x401000; the child's thread is the one that hit."""
        from unittest import mock

        software = extension_free_module("pydbg.breakpoint.software")
        session = self._session_with_child()
        mgr = software.SoftwareBreakpointManager(session)
        originals = {0x1000: b"\x90", 0x2000: b"\x55"}
        writer = mock.Mock()

        with self._patched(software, originals, writer):
            parent_bp = mgr.set_handle(0x1000, self.ADDR)
            child_bp = mgr.set_handle(0x2000, self.ADDR)
            writer.reset_mock()
            outcome = mgr.handle_breakpoint_hit(2001, self.ADDR)

        self.assertIs(outcome, software.HandleOutcome.HANDLED)
        self.assertEqual(
            writer.call_args_list,
            [mock.call(0x2000, self.ADDR, b"\x55")],
            "the child's hit restored a byte through another process's handle")
        self.assertEqual(session.breakpoints[child_bp].hits, 1)
        self.assertEqual(session.breakpoints[parent_bp].hits, 0,
                         "the address-only lookup picked the parent's record")
        self.assertEqual(
            session.pending_single_step[2001].h_process, 0x2000,
            "the re-arming single-step was scheduled against another process")

    def test_a_thread_whose_pid_was_never_opened_still_dispatches(self):
        """An unresolvable pid must not abort run(): fall back to the record.

        session.tid_pid is filled from debug events, so it can name a process
        this session never opened — a tid value reused by another process, or
        a child that already exited. Raising here turned one unrecognised
        thread into a failed event dispatch; the record's own handle is the
        only identity left, so the hit degrades to it.
        """
        from unittest import mock

        software = extension_free_module("pydbg.breakpoint.software")
        session = self._session_with_child()
        session.register_thread(3001, 9999)      # this pid was never opened
        mgr = software.SoftwareBreakpointManager(session)
        originals = {0x1000: b"\x90", 0x2000: b"\x55"}
        writer = mock.Mock()

        with self._patched(software, originals, writer):
            mgr.set_handle(0x1000, self.ADDR)
            writer.reset_mock()
            outcome = mgr.handle_breakpoint_hit(3001, self.ADDR)

        self.assertIs(outcome, software.HandleOutcome.HANDLED)
        self.assertEqual(
            writer.call_args_list,
            [mock.call(0x1000, self.ADDR, b"\x90")],
            "an unresolvable pid should degrade to the record's own handle")

    def test_a_parent_hit_is_not_mistaken_for_the_child(self):
        """The parent's record answers the parent's thread, not the child's."""
        from unittest import mock

        software = extension_free_module("pydbg.breakpoint.software")
        session = self._session_with_child()
        mgr = software.SoftwareBreakpointManager(session)
        originals = {0x1000: b"\x90", 0x2000: b"\x55"}
        writer = mock.Mock()

        with self._patched(software, originals, writer):
            parent_bp = mgr.set_handle(0x1000, self.ADDR)
            mgr.set_handle(0x2000, self.ADDR)
            writer.reset_mock()
            outcome = mgr.handle_breakpoint_hit(1001, self.ADDR)

        self.assertIs(outcome, software.HandleOutcome.HANDLED)
        self.assertEqual(
            writer.call_args_list,
            [mock.call(0x1000, self.ADDR, b"\x90")],
            "the parent's hit was restored through the child's handle")
        self.assertEqual(session.breakpoints[parent_bp].hits, 1)


class TestHardwareBreakpointProcessScope(unittest.TestCase):
    """Dr0-3 are four slots per process, not four per session."""

    ADDR = 0x401000

    def setUp(self):
        from pydbg.core.session import DebugSession

        self.hardware = extension_free_module("pydbg.breakpoint.hardware")
        self.session = DebugSession()
        self.session.pid = 1000
        self.session.tid = 1001
        self.session.register_pid_arch(1000, 64)
        self.session.register_pid_arch(2000, 64)
        self.session.register_pid_arch(3000, 32)
        self.threads = {1000: [{"tid": 1001}, {"tid": 1002}],
                        2000: [{"tid": 2001}],
                        3000: [{"tid": 3001}]}
        for pid, threads in self.threads.items():
            for thread in threads:
                self.session.register_thread(thread["tid"], pid)
        self.armed = []
        self.cleared = []
        self.manager = self.hardware.HardwareBreakpointManager(self.session)

    def _record_armed(self, h_thread, slot, addr, condition, length, machine):
        self.armed.append((h_thread, slot))

    def _record_cleared(self, h_thread, slot, machine):
        self.cleared.append((h_thread, slot))

    def _extension(self):
        from unittest import mock

        return mock.patch.multiple(
            self.hardware._pydbg,
            create=True,
            enumerate_threads=mock.Mock(
                side_effect=lambda pid: self.threads[pid]),
            open_thread=mock.Mock(side_effect=lambda tid: tid),
            close_handle=mock.Mock(),
            set_hw_breakpoint=mock.Mock(side_effect=self._record_armed),
            clear_hw_breakpoint=mock.Mock(side_effect=self._record_cleared))

    def test_the_same_slot_can_belong_to_two_processes(self):
        with self._extension():
            parent_bp = self.manager.set(self.ADDR, "x", 1, slot=0)
            child_bp = self.manager.set(self.ADDR, "x", 1, slot=0, pid=2000)
        self.assertNotEqual(parent_bp, child_bp)
        self.assertEqual(self.manager.find(self.ADDR), parent_bp)
        self.assertEqual(self.manager.find(self.ADDR, pid=2000), child_bp)
        self.assertEqual([h for h, _slot in self.armed], [1001, 1002, 2001],
                         "the main target's Dr0 blocked the child's Dr0")

    def test_one_process_cannot_clear_the_other_slot(self):
        with self._extension():
            main_bp = self.manager.set(self.ADDR, "x", 1, slot=0)
            child_bp = self.manager.set(self.ADDR, "x", 1, slot=0, pid=2000)
            self.manager.clear(0)
            cleared_main = [h for h, _slot in self.cleared]
            self.cleared.clear()
            self.manager.clear(0, pid=2000)
            cleared_child = [h for h, _slot in self.cleared]
        self.assertEqual(cleared_main, [1001, 1002],
                         "clearing the main target touched another process")
        self.assertEqual(cleared_child, [2001],
                         "the child's own slot could not be cleared")
        self.assertEqual(self.manager.find(self.ADDR), main_bp)
        self.assertEqual(self.manager.find(self.ADDR, pid=2000), child_bp)

    def test_freeing_a_slot_in_one_process_leaves_the_other_occupied(self):
        with self._extension():
            main_bp = self.manager.set(self.ADDR, "x", 1, slot=0)
            child_bp = self.manager.set(self.ADDR, "x", 1, slot=0, pid=2000)
            self.manager.remove(child_bp)
            self.assertIsNone(self.manager.find(self.ADDR, pid=2000))
            with self.assertRaises(self.hardware.BreakpointSlotBusy):
                self.manager.set(0x401100, "x", 1, slot=0)
            reused = self.manager.set(0x401100, "x", 1, slot=0, pid=2000)
        self.assertEqual(self.manager.find(self.ADDR), main_bp)
        self.assertEqual(self.manager.find(0x401100, pid=2000), reused)

    def test_four_slots_are_a_per_process_limit(self):
        with self._extension():
            for slot in range(4):
                self.manager.set(0x400000 + slot, "x", 1, slot=slot)
            with self.assertRaises(self.hardware.BreakpointSlotBusy):
                self.manager.set(0x400100, "x", 1, slot=0)
            child_bp = self.manager.set(0x400000, "x", 1, slot=0, pid=2000)
        self.assertEqual(self.manager.find(0x400000, pid=2000), child_bp)

    def test_eight_byte_length_is_still_refused_on_x86(self):
        with self.assertRaises(self.hardware.BreakpointError):
            self.manager.set(0x400000, "w", 8, slot=0, pid=3000)


if __name__ == "__main__":
    unittest.main()
