"""Live tests for the block-level tracer (spec §8.3–§8.5).

The tracer is a *debugger* feature: it plans blocks from a live module's static
analysis, arms INT3s, and records a BLOCK event each time one fires. Every test
here drives a real target, so the whole file is gated on the Cython extension
and skipped on a machine that never built it.

The target is started and stopped at its initial (loader) breakpoint before any
planning happens, for two reasons: the module is mapped by then, so its bytes
can be read for analysis, and the entry point has not run yet, so a breakpoint
placed on the entry block fires. The documented order is plan() -> arm() ->
continue the pending loader event -> run(): arming while the target is still
paused is what closes the race in `run()`'s arm-if-needed path.
"""

import os
import tempfile
import unittest

from pydbg.core.status import ExitReason, ExitStatus
from pydbg.exceptions import BreakpointError
from pydbg.trace import (
    BblTracer, TraceSummary,
    STOP_IDLE_TIMEOUT, STOP_MAX_EVENTS, STOP_NO_BLOCKS, STOP_TARGET_EXITED,
)
from pydbg.trace.format import BLOCK, TraceWriter, read_trace

try:
    from pydbg import _pydbg  # noqa: F401

    _has_cython = True
except ImportError:
    _has_cython = False


class TestTraceSummary(unittest.TestCase):
    """The summary must not be able to contradict itself."""

    def summary(self, reason):
        return TraceSummary(events=0, blocks=0, reason=reason, elapsed_ns=0)

    def test_truncated_is_derived_from_the_stop_reason(self):
        """One field, so 'complete' and 'cut off' cannot both be true."""
        self.assertTrue(self.summary(STOP_MAX_EVENTS).truncated)
        self.assertTrue(self.summary(STOP_IDLE_TIMEOUT).truncated)
        self.assertFalse(self.summary(STOP_TARGET_EXITED).truncated)
        self.assertFalse(self.summary(STOP_NO_BLOCKS).truncated)
        self.assertFalse(self.summary(None).truncated)

    def test_there_is_no_stored_truncated_flag_to_disagree_with(self):
        with self.assertRaises(TypeError):
            TraceSummary(events=0, blocks=0, truncated=True, reason=None,
                         elapsed_ns=0)

    def test_the_stop_reasons_are_exported_as_distinct_constants(self):
        reasons = (STOP_MAX_EVENTS, STOP_TARGET_EXITED,
                   STOP_IDLE_TIMEOUT, STOP_NO_BLOCKS)
        self.assertEqual(len(set(reasons)), len(reasons))
        self.assertEqual(STOP_MAX_EVENTS, "max_events")
        self.assertEqual(STOP_IDLE_TIMEOUT, "idle_timeout")
        for reason in reasons:
            self.assertIsInstance(reason, str)

    def test_a_clean_summary_has_nothing_to_report(self):
        summary = self.summary(None)
        self.assertEqual(summary.warnings, ())
        self.assertFalse(summary.single_step_pending)


class _LiveTestCase(unittest.TestCase):
    """A target paused on its initial breakpoint, torn down afterwards.

    `tests.helpers.create_debugger` is the one implementation of "start the
    target and stop on the loader breakpoint"; a second copy here is how the
    two drifted apart in the first place.
    """

    def setUp(self):
        from tests.helpers import create_debugger

        self.dbg, self.pid, self.tid = create_debugger()

    def tearDown(self):
        from tests.helpers import teardown

        teardown(self.dbg)

    def resume_pending(self):
        """Continue the loader breakpoint so run() has an event to wait for."""
        self.dbg.continue_event(self.pid, self.tid)


class _RecordingDebugger:
    """A Debugger proxy that records what the tracer arms.

    Attributes it does not override delegate to the real debugger, so planning
    still reads the live target; `run()` is supplied by a subclass instead of
    waiting for whatever the target chooses to execute.
    """

    def __init__(self, dbg):
        self._dbg = dbg
        self.armed = []
        self.run_calls = []

    def __getattr__(self, name):
        return getattr(self._dbg, name)

    def set_breakpoint(self, addr, pid=None):
        self.armed.append(addr)
        return self._dbg.set_breakpoint(addr, pid)


class _ScriptedDebugger(_RecordingDebugger):
    """A proxy whose run() replays a fixed event list, or raises."""

    def __init__(self, dbg, events=(), error=None):
        super().__init__(dbg)
        self.events = list(events)
        self.error = error

    def run(self, callback, **kwargs):
        self.run_calls.append(kwargs)
        if self.error is not None:
            raise self.error
        for event in self.events:
            callback(event)
        return ExitStatus(None, ExitReason.STOPPED_BY_CALLBACK)


@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
class TestBblTracerPlanning(_LiveTestCase):
    """plan() decides what is traceable before a single byte is patched."""

    def test_plan_finds_blocks_in_the_main_module(self):
        tracer = BblTracer(self.dbg)
        count = tracer.plan()

        self.assertGreater(count, 0, "no breakable blocks found in the main module")
        self.assertLessEqual(count, tracer.max_blocks)
        # Planning twice is the same plan, not a second analysis.
        self.assertEqual(tracer.plan(), count)

    def test_plan_returns_zero_without_a_target(self):
        """An unattached debugger is untraceable, and says so instead of raising."""
        from pydbg import Debugger

        tracer = BblTracer(Debugger())

        self.assertEqual(tracer.plan(), 0)
        summary = tracer.run()
        self.assertEqual(summary.events, 0)
        self.assertEqual(summary.blocks, 0)
        self.assertFalse(summary.truncated)
        self.assertEqual(summary.reason, STOP_NO_BLOCKS,
                         "an untraceable module must state why, not be silent")


@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
class TestBblTracerRun(_LiveTestCase):
    """run() records BLOCK events and leaves nothing behind in the target."""

    def test_run_records_blocks_in_the_main_module(self):
        from pydbg.trace.format import TraceEvent

        tracer = BblTracer(self.dbg)
        planned = tracer.plan()
        self.assertGreater(planned, 0)
        self.assertEqual(tracer.arm(), planned)
        module = self.dbg.enum_modules()[0]
        base = module['base_address']
        size = module['size']

        recorded = []
        tracer.sink = recorded.append
        self.resume_pending()
        summary = tracer.run()

        self.assertIsInstance(summary, TraceSummary)
        self.assertGreaterEqual(summary.events, 1, "the target ran no planned block")
        self.assertFalse(summary.truncated)
        self.assertEqual(summary.reason, STOP_TARGET_EXITED)
        self.assertEqual(len(recorded), summary.events)
        self.assertEqual(summary.blocks, len({event.rva for event in recorded}))
        for event in recorded:
            self.assertIsInstance(event, TraceEvent)
            self.assertEqual(event.kind, BLOCK)
            # The plan works in RVAs; the module's own window is [base, base+size).
            self.assertGreaterEqual(event.rva, 0)
            self.assertLess(base + event.rva, base + size,
                            "a traced block lies outside the main module")
            self.assertGreater(event.a, 0, "a BLOCK must carry its instruction count")

        # The target exited during the run, so its bytes cannot be put back;
        # that is reported, and no own breakpoint is claimed to be left in a
        # live target.
        self.assertEqual(summary.warnings, ("target exited during cleanup",))
        self.assertFalse(summary.single_step_pending)
        self.assertEqual(self.dbg.get_exit_code(), 0,
                         "the target did not terminate normally after tracing")

    def test_max_events_truncates_and_stops_the_loop(self):
        tracer = BblTracer(self.dbg, max_events=1)
        self.assertGreater(tracer.plan(), 0)
        self.assertGreater(tracer.arm(), 0)

        self.resume_pending()
        summary = tracer.run()

        self.assertTrue(summary.truncated, "the event budget did not truncate the run")
        self.assertEqual(summary.reason, STOP_MAX_EVENTS)
        self.assertEqual(summary.events, 1)
        self.assertTrue(summary.single_step_pending,
                        "a stopped trace leaves its debug event uncontinued")
        self.assertEqual(summary.warnings, ())
        self.assertEqual(self.dbg.verify_breakpoints(), [])

    def test_the_target_still_terminates_after_a_truncated_trace(self):
        """No stale INT3 may stop the target from resuming and exiting.

        A trace stopped by its budget leaves the process paused on the
        breakpoint run() refused to continue. Resuming it must reach
        EXIT_PROCESS rather than hang on a breakpoint that was already removed.
        This test deliberately does not call arm(): run() must stay usable for
        a caller that already resumed the target (that path is racy, see run()).
        """
        from pydbg import ExitReason

        tracer = BblTracer(self.dbg, max_events=1)
        self.assertGreater(tracer.plan(), 0)
        self.resume_pending()
        summary = tracer.run()
        self.assertTrue(summary.truncated)

        self.dbg.continue_event()
        status = self.dbg.run(lambda event: None, timeout_ms=5000)

        self.assertIs(status.reason, ExitReason.TARGET_EXITED)
        self.assertEqual(status.exit_code, 0)
        self.assertEqual(self.dbg.verify_breakpoints(), [])

    def test_writer_and_reader_agree_on_every_event(self):
        """The trace file is the trace: no event may be lost between them."""
        tracer = BblTracer(self.dbg)
        self.assertGreater(tracer.plan(), 0)
        self.assertGreater(tracer.arm(), 0)

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "blocks.pdbgtrc")
            with TraceWriter(path) as writer:
                tracer.sink = writer.write
                # Arm while paused, then release the target; everything that
                # must happen while it is paused has to be done already.
                self.resume_pending()
                summary = tracer.run()
            written = len(list(read_trace(path)))

        self.assertGreater(summary.events, 0)
        self.assertEqual(written, summary.events,
                         "writer and reader disagree on how many events exist")
        self.assertGreater(summary.elapsed_ns, 0)

        elapsed_s = summary.elapsed_ns / 1e9
        rate = summary.blocks / elapsed_s if elapsed_s else 0.0
        print(f"\nbbl trace: events={summary.events} blocks={summary.blocks} "
              f"elapsed={elapsed_s:.3f}s ({rate:.0f} blocks/s)")


@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
class TestBblTracerArming(_LiveTestCase):
    """arm()/disarm() make the pause window explicit instead of a race."""

    def test_arm_installs_one_breakpoint_per_planned_block(self):
        tracer = BblTracer(self.dbg)
        planned = tracer.plan()
        self.assertGreater(planned, 0)

        self.assertEqual(tracer.arm(), planned)
        self.assertEqual(tracer.arm(), planned, "a second arm is the same arm")
        self.assertEqual(tracer.disarm(), ())
        self.assertEqual(self.dbg.verify_breakpoints(), [])

    def test_the_documented_sequence_arms_while_the_target_is_paused(self):
        tracer = BblTracer(self.dbg)
        self.assertGreater(tracer.plan(), 0)
        self.assertGreater(tracer.arm(), 0)
        self.resume_pending()
        summary = tracer.run()

        self.assertGreaterEqual(summary.events, 1)
        self.assertEqual(summary.reason, STOP_TARGET_EXITED)

    def test_run_rearms_after_a_disarm(self):
        tracer = BblTracer(self.dbg)
        self.assertGreater(tracer.plan(), 0)
        self.assertGreater(tracer.arm(), 0)
        self.assertEqual(tracer.disarm(), ())

        self.resume_pending()
        summary = tracer.run()

        self.assertGreaterEqual(summary.events, 1,
                                "run() did not arm the plan it already had")


@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
class TestBblTracerCleanup(_LiveTestCase):
    """Cleanup removes only what it armed, and reports what it could not."""

    def armed_tracer(self):
        proxy = _ScriptedDebugger(self.dbg)
        tracer = BblTracer(proxy)
        self.assertGreater(tracer.plan(), 0)
        self.assertGreater(tracer.arm(), 0)
        return tracer, proxy

    def test_a_caller_breakpoint_at_a_planned_start_is_reused(self):
        proxy = _ScriptedDebugger(self.dbg)
        tracer = BblTracer(proxy)
        planned = tracer.plan()
        self.assertGreater(planned, 0)
        self.assertEqual(tracer.arm(), planned)
        caller_addr = proxy.armed[0]
        self.assertEqual(tracer.disarm(), ())

        caller_id = self.dbg.set_breakpoint(caller_addr)
        proxy.armed.clear()
        self.assertEqual(tracer.arm(), planned - 1,
                         "the caller's breakpoint was armed over again")

        summary = tracer.run()
        self.assertIn("reused caller breakpoints", summary.warnings)
        self.assertEqual(self.dbg.find_breakpoint(caller_addr), caller_id,
                         "cleanup removed a breakpoint it did not own")

    def test_a_breakpoint_that_survives_cleanup_is_reported(self):
        tracer, proxy = self.armed_tracer()
        # A no-op removal leaves the record (and its byte) in place.
        proxy.remove_breakpoint = lambda bp_id: None

        self.assertEqual(tracer.disarm(), ("breakpoint left",))
        self.assertEqual(tracer.disarm(), (), "disarm is idempotent")

    def test_a_failed_removal_on_a_live_target_is_a_leftover(self):
        tracer, proxy = self.armed_tracer()

        def fail(bp_id):
            raise BreakpointError("the byte could not be restored")

        proxy.remove_breakpoint = fail
        self.assertEqual(tracer.disarm(), ("breakpoint left",))

    def test_cleanup_stops_once_the_target_is_gone(self):
        tracer, proxy = self.armed_tracer()
        calls = []
        real_remove = self.dbg.remove_breakpoint

        def counting_remove(bp_id):
            calls.append(bp_id)
            return real_remove(bp_id)

        proxy.remove_breakpoint = counting_remove
        self.dbg.terminate_process(0)
        warnings = tracer.disarm()

        self.assertEqual(warnings, ("target exited during cleanup",))
        self.assertNotIn("breakpoint left", warnings)
        self.assertEqual(len(calls), 1,
                         "cleanup kept trying to write to a dead target")


if __name__ == "__main__":
    unittest.main()
