"""Teardown ownership — close() undoes what every manager installed (ADR-0004)."""

import unittest
from unittest import mock

from tests import TEST_TARGET_PATH

try:
    from pydbg import _pydbg  # noqa: F401
    _has_cython = True
except ImportError:
    _has_cython = False

from pydbg.breakpoint.hardware import HardwareBreakpointManager
from pydbg.breakpoint.software import SoftwareBreakpointManager
from pydbg.breakpoint.model import Breakpoint
from pydbg.core.session import DebugSession
from pydbg.exceptions import TeardownError
from pydbg.hook.iat import IATHook
from pydbg.hook.inline import InlineHook


class TestManagerTeardown(unittest.TestCase):
    """Each manager undoes its own writes and reports the ones it could not."""

    def test_software_teardown_puts_every_byte_back(self):
        session = DebugSession()
        mgr = SoftwareBreakpointManager(session)
        session.breakpoints[1] = Breakpoint(kind="int3", addr=0x1000, original=b"\x90", h_process=123)
        session.breakpoints[2] = Breakpoint(kind="int3", addr=0x2000, original=b"\x55", h_process=123)
        session.breakpoints[3] = Breakpoint(kind="hw", addr=0x3000, slot=0, condition="x", length=1)

        restored = []
        mgr._restore_byte_handle = (
            lambda h, addr, original: restored.append((addr, original)))

        self.assertEqual(mgr.teardown(), [])
        self.assertEqual(restored, [(0x1000, b"\x90"), (0x2000, b"\x55")])
        # The hardware record is not this manager's business and stays put.
        self.assertEqual(list(session.breakpoints), [3])

    def test_software_teardown_reports_and_keeps_walking(self):
        session = DebugSession()
        mgr = SoftwareBreakpointManager(session)
        session.breakpoints[1] = Breakpoint(kind="int3", addr=0x1000, original=b"\x90", h_process=123)
        session.breakpoints[2] = Breakpoint(kind="int3", addr=0x2000, original=b"\x55", h_process=123)

        def restore(h, addr, original):
            if addr == 0x1000:
                from pydbg.exceptions import BreakpointError
                raise BreakpointError("page is gone")

        mgr._restore_byte_handle = restore
        problems = mgr.teardown()
        self.assertEqual(len(problems), 1)
        self.assertIn("0x1000", problems[0][0])

    def test_hardware_teardown_disarms_every_recorded_slot(self):
        session = DebugSession()
        mgr = HardwareBreakpointManager(session)
        session.breakpoints[7] = Breakpoint(kind="hw", addr=0x1000, slot=2, condition="x", length=1)
        session.breakpoints[8] = Breakpoint(kind="int3", addr=0x2000, original=b"\x90", h_process=123)

        disarmed = []
        mgr._disarm_scope = (
            lambda scope, slot, pid=None: disarmed.append((scope, slot)))

        self.assertEqual(mgr.teardown(), [])
        self.assertEqual(disarmed, [(None, 2)])
        self.assertEqual(list(session.breakpoints), [8])

    def test_iat_teardown_restores_every_hook(self):
        session = DebugSession()
        hook = IATHook(session)
        hook._hooks[("kernel32.dll", "Sleep")] = (0x5000, 0x1234)
        hook._hooks[("kernel32.dll", "ExitProcess")] = (0x5008, 0x5678)

        restored = []

        def fake_restore(module, func, orig=None):
            restored.append((module, func))
            hook._hooks.pop((module, func), None)

        hook.restore = fake_restore

        self.assertEqual(hook.teardown(), [])
        self.assertEqual(sorted(restored),
                         [("kernel32.dll", "ExitProcess"),
                          ("kernel32.dll", "Sleep")])
        self.assertEqual(hook._hooks, {})

    def test_inline_teardown_restores_every_detour(self):
        session = DebugSession()
        hook = InlineHook(session)
        hook._hooks[0x1000] = mock.Mock(addr=0x9000)
        hook._hooks[0x2000] = mock.Mock(addr=0xA000)

        restored = []

        def fake_restore(tramp):
            restored.append(tramp.addr)
            for addr, known in list(hook._hooks.items()):
                if known is tramp:
                    del hook._hooks[addr]

        hook.restore = fake_restore

        self.assertEqual(hook.teardown(), [])
        self.assertEqual(sorted(restored), [0x9000, 0xA000])
        self.assertEqual(hook._hooks, {})


@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
class TestClose(unittest.TestCase):
    """close() is the single owner: teardown, stop debugging, release handles."""

    def _started(self):
        from pydbg import Debugger
        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        return dbg, pid, tid

    def test_close_undoes_in_the_documented_order(self):
        from pydbg import Debugger
        dbg = Debugger()
        order = []
        for name in dbg._TEARDOWN_ORDER:
            manager = getattr(dbg, name)
            manager.teardown = (lambda n: lambda: (order.append(n), [])[1])(name)
        dbg.close()
        self.assertEqual(order, list(dbg._TEARDOWN_ORDER))

    def test_close_is_idempotent(self):
        dbg, pid, tid = self._started()
        dbg.close()
        dbg.close()  # nothing left to undo, nothing to detach from
        self.assertIsNone(dbg._session.process_handle)
        self.assertIsNone(dbg._session.thread_handle)

    def test_context_manager_closes(self):
        dbg, pid, tid = self._started()
        with dbg:
            self.assertIsNotNone(dbg._session.process_handle)
        self.assertIsNone(dbg._session.process_handle)
        self.assertEqual(dbg._session.breakpoints, {})

    def test_close_releases_handles_even_when_detach_fails(self):
        dbg, pid, tid = self._started()
        with mock.patch("pydbg.core.debugger._pydbg.debug_active_process_stop",
                        side_effect=OSError(5, "denied")):
            with self.assertRaises(TeardownError) as ctx:
                dbg.close()
        self.assertIn("DebugActiveProcessStop", str(ctx.exception))
        # The leak this guarded against: raising before the handles were closed.
        self.assertIsNone(dbg._session.process_handle)
        self.assertIsNone(dbg._session.thread_handle)

    def test_close_keeps_going_after_one_manager_fails(self):
        dbg, pid, tid = self._started()
        seen = []

        def broken():
            seen.append("broken")
            raise RuntimeError("teardown exploded")

        dbg.hook_iat.teardown = broken
        dbg.brk_sw.teardown = lambda: seen.append("still ran") or []
        with self.assertRaises(TeardownError) as ctx:
            dbg.close()
        self.assertIn("still ran", seen)
        self.assertIn("hook_iat", str(ctx.exception))

    def test_terminate_discards_without_pretending_to_restore(self):
        from tests.helpers import create_debugger
        dbg, pid, tid = create_debugger()
        dbg.set_breakpoint(_entry_point(dbg))
        dbg.terminate_process(0)
        # A killed process has no bytes to put back; the records must not
        # survive it and claim to be armed.
        self.assertEqual(dbg._session.breakpoints, {})
        self.assertEqual(dbg.breakpoint_report(), [])
        dbg.close()


def _entry_point(dbg):
    import struct
    base = dbg.enum_modules()[0]["base_address"]
    dos = dbg.read_memory(base, 0x40)
    e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
    headers = dbg.read_memory(base + e_lfanew, 4 + 20 + 16 + 4)
    entry_rva = struct.unpack_from("<I", headers, 4 + 20 + 16)[0]
    return base + entry_rva


if __name__ == "__main__":
    unittest.main()
