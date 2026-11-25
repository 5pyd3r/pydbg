"""Tests for the instruction-window tracer (spec §9.4, §9.7).

The tracer is a debugger feature: it runs the target one instruction at a time
by setting the trap flag, and records one INSTR event per instruction that
executed. The live half of this file drives a real target with the Cython
extension, so it is skipped on a machine that never built it.

The decisions that do not need a target — no target, no module, an exhausted
budget, a start outside the module — are covered by a fake debugger, so they
run everywhere and fail fast when the stop reasons drift.
"""

import os
import tempfile
import unittest

from pydbg.core.status import ExitReason, ExitStatus
from pydbg.exceptions import PydbgError
from pydbg.trace import (
    INSTR, TRUNCATED_REASONS, InstructionTracer, TraceSummary, TraceWriter,
    read_trace,
    STOP_BREAKPOINT, STOP_EXCEPTION, STOP_IDLE_TIMEOUT, STOP_LEFT_MODULE,
    STOP_MAX_EVENTS, STOP_NO_MODULE, STOP_NO_TARGET, STOP_TARGET_EXITED,
)

try:
    from pydbg import _pydbg  # noqa: F401

    _has_cython = True
except ImportError:
    _has_cython = False


class _FakeSession:
    """The session fields the tracer reads, and nothing else."""

    def __init__(self, pid=4, tid=8):
        self.pid = pid
        self.tid = tid
        self.pending_single_step = {}


class _FakeDebugger:
    """A debugger stand-in for the decisions that never touch a target.

    It records any attempt to drive the target and raises instead: a tracer
    that claims to have stopped without running anything must not have run
    anything.
    """

    def __init__(self, pid=4, tid=8, modules=None):
        self._session = _FakeSession(pid, tid)
        self._modules = modules
        self.driven = []

    def enum_modules(self):
        if self._modules is None:
            raise PydbgError("no target")
        return self._modules

    def enum_regions(self):
        raise PydbgError("no target")

    def run(self, *args, **kwargs):
        self.driven.append((args, kwargs))
        raise AssertionError("the tracer drove the target without a module")


class TestStopReasons(unittest.TestCase):
    """The new reasons are named constants, and only budgets truncate."""

    def test_the_phase_3b_reasons_are_exported_with_documented_values(self):
        self.assertEqual(STOP_LEFT_MODULE, "left_module")
        self.assertEqual(STOP_BREAKPOINT, "breakpoint")
        self.assertEqual(STOP_EXCEPTION, "exception")
        self.assertEqual(STOP_NO_MODULE, "no module")
        self.assertEqual(STOP_NO_TARGET, "no target")

        reasons = (STOP_LEFT_MODULE, STOP_BREAKPOINT, STOP_EXCEPTION,
                   STOP_NO_MODULE, STOP_NO_TARGET)
        self.assertEqual(len(set(reasons)), len(reasons))
        for reason in reasons:
            self.assertNotIn(reason, TRUNCATED_REASONS,
                             "a rule stop must not report itself as a budget")
        self.assertIn(STOP_MAX_EVENTS, TRUNCATED_REASONS)
        self.assertIn(STOP_IDLE_TIMEOUT, TRUNCATED_REASONS)


class TestNoTarget(unittest.TestCase):
    """An unattached debugger is answered, not raised at."""

    def test_a_debugger_without_a_target_says_so(self):
        dbg = _FakeDebugger(pid=None, tid=None)
        summary = InstructionTracer(dbg).run()

        self.assertIsInstance(summary, TraceSummary)
        self.assertEqual(summary.events, 0)
        self.assertEqual(summary.instructions, 0)
        self.assertEqual(summary.blocks, 0)
        self.assertEqual(summary.reason, STOP_NO_TARGET)
        self.assertFalse(summary.truncated)
        self.assertEqual(summary.warnings, ())
        self.assertFalse(summary.single_step_pending)
        self.assertEqual(dbg.driven, [])


class TestModuleResolution(unittest.TestCase):
    """Without a base and a size there is no window to report on."""

    def test_a_module_that_cannot_be_resolved_is_reported_by_name(self):
        dbg = _FakeDebugger()
        summary = InstructionTracer(dbg).run()

        self.assertEqual(summary.events, 0)
        self.assertEqual(summary.reason, STOP_NO_MODULE)
        self.assertFalse(summary.truncated)
        self.assertEqual(dbg.driven, [])

    def test_a_start_outside_the_module_stops_before_anything_runs(self):
        dbg = _FakeDebugger()
        tracer = InstructionTracer(dbg, module=(0x400000, 0x1000))

        summary = tracer.run(start=0x401000)

        self.assertEqual(summary.events, 0)
        self.assertEqual(summary.reason, STOP_LEFT_MODULE)
        self.assertFalse(summary.truncated)
        self.assertEqual(dbg.driven, [])

    def test_a_start_below_the_module_is_outside_it_too(self):
        dbg = _FakeDebugger()
        tracer = InstructionTracer(dbg, module=(0x400000, 0x1000))

        summary = tracer.run(start=0x3FFFFF)

        self.assertEqual(summary.events, 0)
        self.assertEqual(summary.reason, STOP_LEFT_MODULE)
        self.assertEqual(dbg.driven, [])


class TestZeroBudget(unittest.TestCase):
    """A zero budget records nothing and does not touch the target's state."""

    def test_zero_instructions_is_a_truncated_stop(self):
        dbg = _FakeDebugger()
        tracer = InstructionTracer(dbg, module=(0x400000, 0x1000),
                                   max_instructions=0)

        summary = tracer.run()

        self.assertEqual(summary.events, 0)
        self.assertEqual(summary.instructions, 0)
        self.assertEqual(summary.reason, STOP_MAX_EVENTS)
        self.assertTrue(summary.truncated)
        self.assertEqual(dbg.driven, [])


class _ScriptedThread:
    """The thread capability object, forwarding to the fake's registers.

    `InstructionTracer` reaches the context through a handle (one open per
    run), so the fake has to expose the same capability shape the real
    `Debugger.thread` does.
    """

    def __init__(self, dbg):
        self._dbg = dbg

    def _tid(self, h_thread):
        """The tid a fake handle names, so the fake can key by tid as before."""
        base = 0x1000
        index = h_thread - base
        if 0 <= index < len(self._dbg.opened):
            return self._dbg.opened[index]
        return h_thread

    def get_context(self, h_thread):
        return self._dbg.get_registers(self._tid(h_thread))

    def set_context(self, h_thread, context):
        for name, value in context.items():
            self._dbg.set_register(self._tid(h_thread), name, value)

    def set_register(self, h_thread, name, value):
        self._dbg.set_register(self._tid(h_thread), name, value)


class _ScriptedDebugger(_FakeDebugger):
    """A debugger whose run() replays a fixed event list to the callback.

    The same shape as the block tracer's scripted tests: run()'s event handling
    is exercised through its public entry point, without a live target.
    """

    def __init__(self, events, ip=0x400800, eflags=0, error=None,
                 status=None):
        """`ip` defaults inside the (0x400000, 0x1000) window the tests name.

        It used to be 0x401000 — one past the window's end — which only worked
        because the tracer used to drive the target without checking the
        cursor. The pre-drive check is now a fact under test, so a fixture
        whose IP is outside the window would test the stop, not the loop.
        """
        super().__init__()
        self.events = list(events)
        self.ip = ip
        self.eflags = eflags
        self.error = error
        self.status = status or ExitStatus(None, ExitReason.STOPPED_BY_CALLBACK)
        self.register_writes = []
        self.opened = []
        self.closed = []
        self.thread = _ScriptedThread(self)

    def open_thread(self, tid):
        h_thread = 0x1000 + len(self.opened)
        self.opened.append(tid)
        return h_thread

    def close_handle(self, h_thread):
        self.closed.append(h_thread)

    def get_registers(self, tid):
        return {'rip': self.ip, 'eflags': self.eflags}

    def set_register(self, tid, name, value):
        self.register_writes.append((tid, name, value))
        if name == 'eflags':
            self.eflags = value

    def continue_event(self, pid=None, tid=None):
        pass

    def run(self, callback, **kwargs):
        if self.error is not None:
            raise self.error
        for event in self.events:
            if callback(event) is False:
                break
        return self.status


def _exception_event(code, addr, tid=8):
    """A debug event with just the fields the tracer's callback reads."""
    from types import SimpleNamespace

    return SimpleNamespace(type='EXCEPTION', exception_code=code,
                           exception_addr=addr, tid=tid)


class TestWindowStopsByRule(unittest.TestCase):
    """A fault or a caller's breakpoint ends the window and says so."""

    def test_a_caller_breakpoint_ends_the_window(self):
        from pydbg.constants import EXCEPTION_BREAKPOINT

        dbg = _ScriptedDebugger([_exception_event(EXCEPTION_BREAKPOINT,
                                                  0x401000)])
        tracer = InstructionTracer(dbg, module=(0x400000, 0x1000))

        summary = tracer.run()

        self.assertEqual(summary.events, 0,
                         "the breakpoint was recorded as an instruction")
        self.assertEqual(summary.reason, STOP_BREAKPOINT)
        self.assertFalse(summary.truncated,
                         "a rule stop is not a budget truncation")
        self.assertTrue(summary.single_step_pending,
                        "the caller owns the uncontinued debug event")

    def test_a_fault_ends_the_window(self):
        from pydbg.constants import EXCEPTION_ACCESS_VIOLATION

        dbg = _ScriptedDebugger([_exception_event(EXCEPTION_ACCESS_VIOLATION,
                                                  0x401000)])
        tracer = InstructionTracer(dbg, module=(0x400000, 0x1000))

        summary = tracer.run()

        self.assertEqual(summary.events, 0)
        self.assertEqual(summary.reason, STOP_EXCEPTION)
        self.assertFalse(summary.truncated)
        self.assertTrue(summary.single_step_pending)

    def test_the_window_arms_the_trap_flag_before_driving_the_target(self):
        """One instruction per set: TF is written, not assumed from last time."""
        dbg = _ScriptedDebugger([])
        tracer = InstructionTracer(dbg, module=(0x400000, 0x1000))

        tracer.run()

        self.assertEqual(len(dbg.register_writes), 1)
        tid, name, value = dbg.register_writes[0]
        self.assertEqual(tid, 8)
        self.assertEqual(name, 'eflags')
        self.assertEqual(value & 0x100, 0x100)

    def test_the_window_opens_one_thread_handle_and_closes_it(self):
        """One handle per run, not one per step: tid access enumerates threads."""
        dbg = _ScriptedDebugger([])
        tracer = InstructionTracer(dbg, module=(0x400000, 0x1000))

        tracer.run()

        self.assertEqual(dbg.opened, [8],
                         "the run must open the thread it steps")
        self.assertEqual(dbg.closed, [0x1000],
                         "the run must close the handle it opened")

    def test_an_idle_timeout_is_a_truncated_stop(self):
        from pydbg.exceptions import TimeoutError as PydbgTimeoutError

        dbg = _ScriptedDebugger([], error=PydbgTimeoutError("no event"))
        tracer = InstructionTracer(dbg, module=(0x400000, 0x1000))

        summary = tracer.run()

        self.assertEqual(summary.reason, STOP_IDLE_TIMEOUT)
        self.assertTrue(summary.truncated)
        self.assertFalse(summary.single_step_pending,
                         "a wedge leaves no event for the caller to continue")

    def test_a_target_that_exited_is_not_a_pending_stop(self):
        dbg = _ScriptedDebugger(
            [], status=ExitStatus(0, ExitReason.TARGET_EXITED))
        tracer = InstructionTracer(dbg, module=(0x400000, 0x1000))

        summary = tracer.run()

        self.assertEqual(summary.reason, STOP_TARGET_EXITED)
        self.assertFalse(summary.truncated)
        self.assertFalse(summary.single_step_pending)


def _instrument_target():
    """Path to instrument_target.exe, which loops calling an export forever."""
    return os.environ.get(
        "TEST_INSTRUMENT_TARGET_PATH",
        os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "target", "instrument_target.exe"))


@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
class _LiveWindowCase(unittest.TestCase):
    """A live instrument_target paused on its loader breakpoint, then released.

    The loader breakpoint has to be continued before the trap flag works, so
    every window test calls `release_loader()` right before `run()`.
    """

    def setUp(self):
        self.target = _instrument_target()
        if not os.path.isfile(self.target):
            self.skipTest(f"target not built: {self.target}")

        from tests.helpers import create_debugger, export_address

        self.dbg, self.pid, self.tid = create_debugger(self.target)
        module = self.dbg.enum_modules()[0]
        self.base = module['base_address']
        self.size = module['size']
        self.add_numbers = export_address(self.dbg, self.target, 'add_numbers')

    def tearDown(self):
        from tests.helpers import teardown

        teardown(self.dbg)

    def release_loader(self):
        """Continue the loader breakpoint; stepping does nothing before this."""
        self.dbg.continue_event(self.pid, self.tid)


class TestLiveWindow(_LiveWindowCase):
    """run(start=...) records real instructions and stops by the rules."""

    def test_a_window_from_an_export_records_its_instructions(self):
        recorded = []
        tracer = InstructionTracer(self.dbg)
        tracer.sink = recorded.append

        self.release_loader()
        summary = tracer.run(start=self.add_numbers)

        elapsed_s = summary.elapsed_ns / 1e9
        first_len = recorded[0].a if recorded else 0
        print(f"\ninstr window: events={summary.events} reason={summary.reason} "
              f"elapsed={elapsed_s:.3f}s first_len={first_len}")

        self.assertGreaterEqual(summary.events, 3,
                                "the window ended before it started")
        self.assertEqual(summary.blocks, 0,
                         "an instruction window has no block counts")
        self.assertEqual(summary.instructions, summary.events)
        self.assertEqual(len(recorded), summary.events,
                         "the sink saw a different number of events")
        self.assertGreater(summary.elapsed_ns, 0)

        first = recorded[0]
        self.assertEqual(first.rva, self.add_numbers - self.base,
                         "the first event must be the requested start")
        self.assertGreaterEqual(first.a, 1,
                                "the first instruction was not decoded")
        for event in recorded:
            self.assertEqual(event.kind, INSTR)
            self.assertGreaterEqual(event.rva, 0)
            self.assertLess(event.rva, self.size,
                            "an INSTR rva lies outside the module")
        self.assertIn(summary.reason, (STOP_LEFT_MODULE, STOP_TARGET_EXITED))

    def test_a_two_instruction_budget_stops_after_two(self):
        recorded = []
        tracer = InstructionTracer(self.dbg, max_instructions=2)
        tracer.sink = recorded.append

        self.release_loader()
        summary = tracer.run(start=self.add_numbers)

        self.assertEqual(summary.events, 2)
        self.assertEqual(summary.instructions, 2)
        self.assertEqual(len(recorded), 2)
        self.assertTrue(summary.truncated)
        self.assertEqual(summary.reason, STOP_MAX_EVENTS)
        self.assertTrue(summary.single_step_pending,
                        "a stopped window leaves its debug event uncontinued")
        self.assertEqual(summary.warnings, ())

        eflags = self.dbg.get_registers(self.tid)['eflags']
        self.assertEqual(eflags & 0x100, 0,
                         "the trap flag must be clear at a clean stop")

    def test_the_written_trace_reads_back_with_the_same_count(self):
        """The file is the trace: no INSTR may be lost between writer/reader."""
        tracer = InstructionTracer(self.dbg)

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "instructions.pdbgtrc")
            with TraceWriter(path) as writer:
                tracer.sink = writer.write
                self.release_loader()
                summary = tracer.run(start=self.add_numbers)
            written = list(read_trace(path))

        self.assertGreater(summary.events, 0)
        self.assertEqual(len(written), summary.events,
                         "writer and reader disagree on the event count")
        self.assertTrue(all(event.kind == INSTR for event in written))
        self.assertEqual(written[0].rva, self.add_numbers - self.base)

    def test_a_window_from_the_current_stop_starts_after_it(self):
        """start=None: the stopped instruction already ran and is not recorded."""
        from tests.helpers import stop_at

        self.release_loader()
        stop_at(self.dbg, self.add_numbers, timeout_ms=10000)

        recorded = []
        tracer = InstructionTracer(self.dbg)
        tracer.sink = recorded.append
        summary = tracer.run()

        print(f"\ninstr window (from stop): events={summary.events} "
              f"reason={summary.reason}")
        self.assertGreaterEqual(summary.events, 1)
        self.assertGreater(recorded[0].rva, self.add_numbers - self.base,
                           "the instruction the target stopped on was counted")
        for event in recorded:
            self.assertGreaterEqual(event.rva, 0)
            self.assertLess(event.rva, self.size)
        self.assertIn(summary.reason, (STOP_LEFT_MODULE, STOP_TARGET_EXITED))

    def test_a_current_ip_outside_the_named_window_stops_before_driving(self):
        """The window must not set TF/continue when the RIP is already outside.

        The loader stop's RIP is in the exe; the named window is a fresh
        allocation. Without the pre-drive check the tracer stepped once anyway
        and recorded an instruction whose RVA was outside the window — the
        exact bug §9.4's "rva always in [0, size)" claim rules out.
        """
        from tests.helpers import alloc_writable

        window = alloc_writable(self.dbg)
        self.assertNotEqual(window, 0, "the target refused the allocation")

        tracer = InstructionTracer(self.dbg, module=(window, 0x1000))
        summary = tracer.run()          # start=None: RIP is the loader stop

        self.assertEqual(summary.events, 0,
                         "an instruction outside the window was recorded")
        self.assertEqual(summary.reason, STOP_LEFT_MODULE)
        self.assertFalse(summary.truncated)
        self.assertFalse(summary.single_step_pending,
                         "nothing was driven, so no event is owed")
        eflags = self.dbg.get_registers(self.tid)['eflags']
        self.assertEqual(eflags & 0x100, 0,
                         "the trap flag was set without driving the target")

    def test_a_default_window_does_not_enumerate_threads_per_step(self):
        """Seven instructions are timed, not seven thread enumerations.

        Each `get_registers(tid)` enumerates the process's threads (~36 ms
        measured); a per-step regression puts this window at about half a
        second. The limit is deliberately loose: it catches the enumerating
        path, not machine load.
        """
        tracer = InstructionTracer(self.dbg)
        self.release_loader()
        summary = tracer.run(start=self.add_numbers)

        print(f"\ninstr default window: events={summary.events} "
              f"elapsed={summary.elapsed_ns / 1e9:.3f}s")
        self.assertEqual(summary.events, 7,
                         "the default window over add_numbers changed shape")
        self.assertLess(summary.elapsed_ns, 2_000_000_000,
                        "the window is enumerating threads on every step")
        self.assertIn(summary.reason, (STOP_LEFT_MODULE, STOP_TARGET_EXITED))

    def test_the_target_terminates_after_a_stopped_window(self):
        """A stopped window must leave nothing behind that blocks the target."""
        tracer = InstructionTracer(self.dbg, max_instructions=2)
        self.release_loader()
        summary = tracer.run(start=self.add_numbers)
        self.assertTrue(summary.truncated)

        # The window stopped on an uncontinued event; releasing it must let the
        # target run again instead of trapping on a stale single-step.
        self.dbg.continue_event(self.pid, self.tid)
        self.dbg.terminate_process(0)

        self.assertEqual(self.dbg.verify_breakpoints(), [])
        self.assertEqual(self.dbg.get_exit_code(), 0,
                         "the target did not terminate after the window")


class TestInstructionTracerTeardown(unittest.TestCase):
    """The window answers the teardown contract close() walks (ADR-0004).

    Unlike the other three tracers it owns no persistent arm: the trap flag is
    set and cleared inside `run()`, and the thread handle it opens is closed in
    the same `finally`. So teardown has nothing to undo — and must not touch the
    target to say so.
    """

    def test_teardown_has_no_persistent_write_to_undo(self):
        dbg = _FakeDebugger()
        tracer = InstructionTracer(dbg)
        tracer._events = 5
        tracer._h_thread = 0x55

        self.assertEqual(tracer.teardown(), ())
        self.assertEqual(dbg.driven, [],
                         "teardown drove the target it was not asked to touch")

    def test_discard_forgets_the_last_window_without_touching_the_target(self):
        dbg = _FakeDebugger()
        tracer = InstructionTracer(dbg)
        tracer._events = 5
        tracer._reason = STOP_MAX_EVENTS
        tracer._warnings = ["undecodable"]
        tracer._h_thread = 0x55

        tracer.discard()

        self.assertEqual(tracer._events, 0)
        self.assertIsNone(tracer._reason)
        self.assertEqual(tracer._warnings, [])
        self.assertIsNone(tracer._h_thread)
        self.assertEqual(dbg.driven, [])
        tracer.discard()        # idempotent


if __name__ == "__main__":
    unittest.main()
