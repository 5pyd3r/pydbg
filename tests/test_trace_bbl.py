"""Live tests for the block-level tracer (spec §8.3–§8.5).

The tracer is a *debugger* feature: it plans blocks from a live module's static
analysis, arms INT3s, and records a BLOCK event each time one fires. Every test
here drives a real target, so the whole file is gated on the Cython extension
and skipped on a machine that never built it.

The target is started and stopped at its initial (loader) breakpoint before any
planning happens, for two reasons: the module is mapped by then, so its bytes
can be read for analysis, and the entry point has not run yet, so a breakpoint
placed on the entry block fires. `plan()` itself can be called while the target
is paused, and `run()` is called only after that pending loader event is
continued — `Debugger.run()` starts by waiting for the next event, so a paused
event left uncontinued would look like a wedged target.
"""

import os
import tempfile
import unittest

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
        self.assertGreater(tracer.plan(), 0)
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

        self.assertEqual(self.dbg.verify_breakpoints(), [],
                         "breakpoints were left armed in the target")
        self.assertFalse(summary.single_step_pending)
        self.assertEqual(self.dbg.get_exit_code(), 0,
                         "the target did not terminate normally after tracing")

    def test_max_events_truncates_and_stops_the_loop(self):
        tracer = BblTracer(self.dbg, max_events=1)
        self.assertGreater(tracer.plan(), 0)

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

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "blocks.pdbgtrc")
            with TraceWriter(path) as writer:
                tracer.sink = writer.write
                # Resume only now: from this moment the target is free to run
                # until it hits an armed block, so everything that must happen
                # while it is paused has to be done already.
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


if __name__ == "__main__":
    unittest.main()
