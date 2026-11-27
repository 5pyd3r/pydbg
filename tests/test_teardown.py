"""Teardown ownership — close() undoes what every manager installed (ADR-0004)."""

import unittest
from unittest import mock

from tests import TEST_TARGET_PATH, extension_free_module

try:
    from pydbg import _pydbg  # noqa: F401
    _has_cython = True
except ImportError:
    _has_cython = False

from pydbg.breakpoint.model import Breakpoint
from pydbg.core.session import DebugSession
from pydbg.core.trace_registry import TraceRegistry
from pydbg.exceptions import TeardownError
from pydbg.hook.iat import IATHook
from pydbg.hook.inline import InlineHook
from pydbg.symbol.resolver import SymbolResolver
from pydbg.thread.manager import ThreadManager

# The managers below are imported inside the tests that use them: hardware,
# software and memory all bind `_pydbg` at module import, so a top-level import
# would make this file (and every extension-free test in it) uncollectable on a
# machine without the compiled extension. `extension_free_module` supplies that
# binding for the tests whose bookkeeping does not need the real one.

# What a Debugger owns that close() has nothing to undo for, with the reason.
# Every *other* public attribute of a Debugger is a manager that can write the
# target, so it must be in `_TEARDOWN_ORDER` and must have a teardown(). The
# reasons are here so the next manager gets classified deliberately: a new name
# that is neither registered nor listed makes the enumeration test red.
_READ_ONLY_MANAGERS = {
    "exception_policy": "a policy value object, not a manager",
    "process": "opens and releases process handles; _release_handles closes them",
    "windows": "enumerates the target's windows, writes nothing",
    "modules": "reads the module table",
    "disasm": "decodes bytes in the host",
    "assembler": "assembles in the host, never in the target",
    "stack_walker": "walks a context the caller already captured",
    "step_tracer": (
        "sets TF on a caller-owned thread handle; the pending step is session "
        "state that brk_sw.discard() clears"),
}


def _teardown_problems(dbg):
    """Everything wrong with how `dbg` registers its target writers.

    Returns a list of human-readable problems, empty when every manager that
    can write the target is registered and undoable. Kept as one function so
    the pass/fail test and the monkeypatch proofs exercise the same check.
    """
    order = tuple(dbg._TEARDOWN_ORDER)
    problems = []
    for name, manager in vars(dbg).items():
        if name.startswith("_") or name in _READ_ONLY_MANAGERS:
            continue
        if name not in order:
            problems.append(
                f"{name} ({type(manager).__name__}) writes the target but is "
                f"missing from _TEARDOWN_ORDER")
    for name in order:
        manager = getattr(dbg, name, None)
        if manager is None:
            problems.append(
                f"_TEARDOWN_ORDER names {name!r}, but Debugger has no such "
                f"attribute")
            continue
        if not callable(getattr(manager, "teardown", None)):
            problems.append(
                f"{name} ({type(manager).__name__}) is in _TEARDOWN_ORDER but "
                f"has no callable teardown()")
        if not callable(getattr(manager, "discard", None)):
            problems.append(
                f"{name} ({type(manager).__name__}) is in _TEARDOWN_ORDER but "
                f"has no callable discard()")
    for name, reason in _READ_ONLY_MANAGERS.items():
        if not hasattr(dbg, name):
            problems.append(
                f"{name} is declared read-only ({reason}), but Debugger has "
                f"no such attribute")
        if name in order:
            problems.append(
                f"{name} is declared read-only ({reason}) but is in "
                f"_TEARDOWN_ORDER")
    return problems


class TestManagerTeardown(unittest.TestCase):
    """Each manager undoes its own writes and reports the ones it could not."""

    def test_software_teardown_puts_every_byte_back(self):
        software = extension_free_module("pydbg.breakpoint.software")

        session = DebugSession()
        mgr = software.SoftwareBreakpointManager(session)
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
        software = extension_free_module("pydbg.breakpoint.software")

        session = DebugSession()
        mgr = software.SoftwareBreakpointManager(session)
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
        hardware = extension_free_module("pydbg.breakpoint.hardware")

        session = DebugSession()
        mgr = hardware.HardwareBreakpointManager(session)
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

    def test_symbol_teardown_reports_an_error_that_is_not_a_pydbg_error(self):
        """ADR-0004 says teardown never raises, whatever cleanup throws.

        SymCleanup is reached through the extension; catching only PydbgError
        let any other type escape close() and skip the rest of the chain.
        """
        resolver = SymbolResolver(DebugSession())

        def explode():
            raise RuntimeError("dbghelp session is already gone")

        resolver.cleanup = explode

        problems = resolver.teardown()

        self.assertEqual(len(problems), 1)
        self.assertEqual(problems[0][0], "dbghelp session")
        self.assertIn("dbghelp session is already gone", problems[0][1])

    def test_memory_teardown_owns_nothing_of_its_own(self):
        """Allocations belong to the instrumenters that asked for them.

        `alloc_remote`/`alloc_near` hand an address back by design and the
        caller frees it (`BblInstrumenter._release_setup`, the event buffer);
        this manager opens no handle either, so the honest answer is (). The
        method exists because the manager writes the target and must be in the
        teardown chain.
        """
        memory = extension_free_module("pydbg.memory.manager")

        mgr = memory.MemoryManager(DebugSession())
        self.assertEqual(mgr.teardown(), ())

    def test_memory_discard_forgets_nothing_because_it_records_nothing(self):
        """ADR-0004's other half: a killed target has no records to drop."""
        memory = extension_free_module("pydbg.memory.manager")

        mgr = memory.MemoryManager(DebugSession())
        self.assertIsNone(mgr.discard())

    def test_thread_teardown_owns_nothing_of_its_own(self):
        """Thread handles are opened and closed by their callers.

        `open()` returns the handle and the caller closes it; suspend/resume
        act on a caller-owned handle. So there is nothing this manager opened
        to release, and teardown answers ().
        """
        mgr = ThreadManager(DebugSession())
        self.assertEqual(mgr.teardown(), ())

    def test_thread_discard_forgets_nothing_because_it_records_nothing(self):
        """ADR-0004's other half: a killed target has no records to drop."""
        mgr = ThreadManager(DebugSession())
        self.assertIsNone(mgr.discard())


class _FakeTracer:
    """A tracer-shaped object: only the ADR-0004 contract close() needs."""

    def __init__(self, warnings=(), error=None, discard_error=None):
        self.warnings = warnings
        self.error = error
        self.discard_error = discard_error
        self.teardowns = 0
        self.discards = 0

    def teardown(self):
        self.teardowns += 1
        if self.error is not None:
            raise self.error
        return self.warnings

    def discard(self):
        self.discards += 1
        if self.discard_error is not None:
            raise self.discard_error


class TestTraceRegistry(unittest.TestCase):
    """The Debugger-owned list of tracers, undone as one teardown step.

    A tracer is caller-owned, so `close()` only learns about it through this
    registry. Its teardown returns the tracers' cleanup warnings as the
    `(what, why)` problems the rest of the chain uses.
    """

    def test_attach_keeps_each_tracer_once_and_in_order(self):
        registry = TraceRegistry()
        first, second = _FakeTracer(), _FakeTracer()

        self.assertIs(registry.attach(first), first)
        registry.attach(second)
        registry.attach(first)      # already registered: not attached twice

        self.assertEqual(len(registry), 2)
        self.assertEqual(list(registry), [first, second])

    def test_teardown_names_the_tracer_that_reported_a_warning(self):
        registry = TraceRegistry()
        tracer = _FakeTracer(warnings=("breakpoint left",))
        registry.attach(tracer)

        self.assertEqual(registry.teardown(),
                         [(f"trace 0 ({type(tracer).__name__})",
                           "breakpoint left")])

    def test_one_broken_teardown_does_not_hide_the_others(self):
        first = _FakeTracer(error=RuntimeError("exploded"))
        second = _FakeTracer(warnings=("breakpoint left",))
        registry = TraceRegistry()
        registry.attach(first)
        registry.attach(second)

        problems = registry.teardown()

        self.assertEqual(problems[0],
                         (f"trace 0 ({type(first).__name__})", "exploded"))
        self.assertEqual(problems[1],
                         (f"trace 1 ({type(second).__name__})",
                          "breakpoint left"))
        self.assertEqual((first.teardowns, second.teardowns), (1, 1),
                         "a raising teardown stopped the walk")

    def test_an_attached_object_without_teardown_is_reported(self):
        registry = TraceRegistry()
        registry.attach(object())

        self.assertEqual(registry.teardown(),
                         [("trace 0 (object)", "no teardown()")])

    def test_a_second_teardown_does_not_run_an_undone_tracer_again(self):
        """A tracer that let go is forgotten, so close() twice undoes once."""
        registry = TraceRegistry()
        first, second = _FakeTracer(), _FakeTracer()
        registry.attach(first)
        registry.attach(second)

        self.assertEqual(registry.teardown(), [])
        self.assertEqual(registry.teardown(), [])
        self.assertEqual((first.teardowns, second.teardowns), (1, 1),
                         "a second close() re-ran a tracer that was undone")

    def test_a_tracer_whose_teardown_raised_stays_for_a_later_retry(self):
        """It was not undone, so a later close() must still be able to try."""
        registry = TraceRegistry()
        broken = _FakeTracer(error=RuntimeError("exploded"))
        registry.attach(broken)

        self.assertEqual(len(registry.teardown()), 1)
        self.assertEqual(len(registry), 1,
                         "a tracer that could not let go was forgotten")

        broken.error = None
        self.assertEqual(registry.teardown(), [])
        self.assertEqual(broken.teardowns, 2)

    def test_discard_never_restores_and_never_stops_the_walk(self):
        first = _FakeTracer(discard_error=RuntimeError("already gone"))
        second = _FakeTracer()
        registry = TraceRegistry()
        registry.attach(first)
        registry.attach(second)

        registry.discard()

        self.assertEqual((first.discards, second.discards), (1, 1))
        self.assertEqual((first.teardowns, second.teardowns), (0, 0),
                         "the terminate path restored something")
        self.assertEqual(len(registry), 0,
                         "discard kept tracers for a target that is gone")


@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
class TestTeardownRegistration(unittest.TestCase):
    """A new target-writing manager cannot skip the teardown chain silently.

    `Debugger.close()` walks `_TEARDOWN_ORDER` and skips a name whose object has
    no `teardown`, so a manager that is never listed is never undone and nothing
    says so. This test is the membership check the tuple cannot perform on
    itself: every manager the Debugger owns is either registered for teardown or
    declared read-only above.
    """

    def _debugger(self):
        from pydbg import Debugger

        return Debugger()

    def test_every_target_writer_is_registered_and_undoable(self):
        dbg = self._debugger()
        try:
            problems = _teardown_problems(dbg)
        finally:
            dbg.close()      # an unattached Debugger must still close cleanly
        self.assertEqual(problems, [], "\n".join(problems))

    def test_the_check_goes_red_when_a_writer_drops_out_of_the_order(self):
        from pydbg import Debugger

        dbg = self._debugger()
        try:
            reduced = tuple(n for n in dbg._TEARDOWN_ORDER if n != "brk_hw")
            with mock.patch.object(Debugger, "_TEARDOWN_ORDER", reduced):
                problems = _teardown_problems(dbg)
        finally:
            dbg.close()
        self.assertTrue(
            any("brk_hw" in p and "_TEARDOWN_ORDER" in p for p in problems),
            f"a missing registration was not reported: {problems}")

    def test_the_check_goes_red_when_a_registered_manager_has_no_teardown(self):
        dbg = self._debugger()
        try:
            with mock.patch.object(type(dbg.traces), "teardown", None):
                problems = _teardown_problems(dbg)
        finally:
            dbg.close()
        self.assertTrue(
            any("traces" in p and "teardown" in p for p in problems),
            f"a missing teardown was not reported: {problems}")

    def test_the_check_goes_red_when_a_registered_manager_has_no_discard(self):
        """ADR-0004 has two halves: restore, and forget when it is too late."""
        dbg = self._debugger()
        try:
            with mock.patch.object(type(dbg.traces), "discard", None):
                problems = _teardown_problems(dbg)
        finally:
            dbg.close()
        self.assertTrue(
            any("traces" in p and "discard" in p for p in problems),
            f"a missing discard was not reported: {problems}")

    def test_the_check_goes_red_for_a_manager_added_to_the_debugger(self):
        """The regression the test exists for: a new writer, never registered."""
        dbg = self._debugger()
        dbg.modules_cache = mock.Mock()      # a new manager, present only now
        try:
            problems = _teardown_problems(dbg)
        finally:
            del dbg.modules_cache
            dbg.close()
        self.assertTrue(
            any("modules_cache" in p and "_TEARDOWN_ORDER" in p
                for p in problems),
            f"a newly added manager was not reported: {problems}")


@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
class TestDebuggerTraceRegistry(unittest.TestCase):
    """The Debugger owns the tracers, so close() disarms them before it lets go."""

    def test_traces_sits_between_the_detours_and_the_breakpoints(self):
        from pydbg import Debugger

        order = Debugger._TEARDOWN_ORDER
        self.assertLess(order.index("bbl_instrumenter"), order.index("traces"),
                        "a detour was left pointing into restored code")
        self.assertLess(order.index("traces"), order.index("brk_hw"),
                        "a trace slot was cleared after the debug registers")

    def test_a_tracer_handed_a_debugger_registers_itself(self):
        from pydbg import Debugger
        from pydbg.trace import (
            BblTracer, FunctionProbe, InstructionTracer, MemoryWatch,
        )

        dbg = Debugger()
        try:
            tracers = [
                BblTracer(dbg),
                InstructionTracer(dbg),
                MemoryWatch(dbg, 0x1000),
                FunctionProbe(dbg, 0x1000),
            ]
            self.assertEqual(list(dbg.traces), tracers)
        finally:
            dbg.close()

    def test_attach_trace_registers_and_returns_the_tracer(self):
        from pydbg import Debugger

        dbg = Debugger()
        tracer = _FakeTracer()
        try:
            self.assertIs(dbg.attach_trace(tracer), tracer)
            dbg.attach_trace(tracer)    # attaching twice is a no-op
            self.assertEqual(list(dbg.traces), [tracer])
        finally:
            dbg.close()

    def test_close_reports_a_tracer_warning_as_a_teardown_problem(self):
        from pydbg import Debugger

        dbg = Debugger()
        dbg.attach_trace(_FakeTracer(warnings=("breakpoint left",)))
        with self.assertRaises(TeardownError) as ctx:
            dbg.close()
        self.assertIn(f"trace 0 ({_FakeTracer.__name__}): breakpoint left",
                      str(ctx.exception))


@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
class TestClose(unittest.TestCase):
    """close() is the single owner: teardown, stop debugging, release handles."""

    def _started(self):
        from pydbg import Debugger
        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        return dbg, pid, tid

    def test_close_without_a_target_is_a_noop(self):
        """Every manager's teardown has to answer an empty state with ()."""
        from pydbg import Debugger

        dbg = Debugger()
        dbg.close()
        dbg.close()
        self.assertIsNone(dbg._session.process_handle)

    def test_close_disarms_an_armed_bbl_tracer_before_letting_go(self):
        """A caller-owned tracer is undone by close(), not left in the target.

        The probe runs just before the handles are released — the last moment
        the target is still readable — so the bytes must be back and no
        breakpoint record may still claim to be armed.
        """
        from pydbg.trace import BblTracer
        from tests.helpers import create_debugger

        dbg, pid, tid = create_debugger()
        tracer = BblTracer(dbg)
        self.assertGreater(tracer.plan(), 0)
        self.assertGreater(tracer.arm(), 0)
        armed_ids = dict(tracer._armed_ids)
        originals = {addr: dbg._session.breakpoints[bp_id].original
                     for addr, bp_id in armed_ids.items()}
        first = next(iter(originals))
        self.assertEqual(dbg.read_memory(first, 1), b"\xCC",
                         "the tracer did not write the INT3 it recorded")

        seen = {}
        release = dbg._release_handles

        def probe():
            seen["bytes"] = {addr: dbg.read_memory(addr, 1)
                             for addr in originals}
            seen["breakpoints"] = dbg.verify_breakpoints()
            seen["armed"] = dict(tracer._armed_ids)
            release()

        dbg._release_handles = probe
        dbg.close()

        self.assertEqual(seen["armed"], {},
                         "close() left the tracer thinking it is armed")
        self.assertEqual(seen["breakpoints"], [])
        self.assertEqual(seen["bytes"], originals,
                         "the bytes close() restored are not the originals")

    def test_close_disarms_an_armed_memory_watch_before_letting_go(self):
        """The same contract for the hardware half: the slot is freed."""
        from pydbg.trace import MemoryWatch
        from tests.helpers import create_debugger

        dbg, pid, tid = create_debugger()
        addr = dbg.memory.alloc_remote(0x1000)
        watch = MemoryWatch(dbg, addr, 4)
        watch.arm()
        self.assertIsNotNone(dbg.find_breakpoint(addr),
                             "the watch did not arm the slot it recorded")

        seen = {}
        release = dbg._release_handles

        def probe():
            seen["bp_id"] = watch._bp_id
            seen["slot"] = watch._slot
            seen["found"] = dbg.find_breakpoint(addr)
            release()

        dbg._release_handles = probe
        dbg.close()

        self.assertIsNone(seen["bp_id"])
        self.assertIsNone(seen["slot"])
        self.assertIsNone(seen["found"],
                          "close() left the watch's debug-register slot armed")

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
