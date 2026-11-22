"""Live tests for the function-entry probe (spec §9.6).

`FunctionProbe` places one hardware *execute* breakpoint at a function's entry:
no target byte is written, no detour is built, and the target keeps running as
usual. Every test here drives the real `instrument_target`, which loops forever
calling its exported `add_numbers(1, 2)` with a 20 ms sleep between calls, so
the whole file is gated on the Cython extension.

A hardware breakpoint armed while the target still sits on its initial loader
breakpoint never fires (measured; §9.1). Each test therefore first runs the
target to `add_numbers` with a temporary software breakpoint — `stop_at` — and
arms the probe at that normal stop. The stop also means a hit is at most one
20 ms sleep away.

The probe is deliberately single-threaded and records only what it can defend:
the return address (`[rsp]` on x64, `[esp]` on x86) and up to four int
arguments. It cannot report the return value; a caller that needs one has to
wait for the Phase 3c instrumentation path (see the module docstring).
"""

import os
import tempfile
import time
import unittest

from pydbg.exceptions import BreakpointError
from pydbg.trace import (
    API, STOP_MAX_EVENTS, STOP_NO_MODULE, STOP_NO_TARGET, FunctionProbe,
    ProbeCall, ProbeSummary, TraceWriter, read_trace,
)

try:
    from pydbg import _pydbg  # noqa: F401

    _has_cython = True
except ImportError:
    _has_cython = False

_TARGET_DIR = os.path.dirname(os.path.abspath(__file__))
_TARGET = os.environ.get(
    "TEST_INSTRUMENT_TARGET_PATH",
    os.path.join(_TARGET_DIR, "target", "instrument_target.exe"))


def _module_base(dbg, basename):
    """Base address of the module named `basename`."""
    for module in dbg.enum_modules():
        if module.get("name", "").split("\\")[-1].lower() == basename.lower():
            return module["base_address"], module["size"]
    raise AssertionError(f"module {basename} is not loaded")


@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
@unittest.skipUnless(os.path.isfile(_TARGET),
                     "target not built: instrument_target.exe (meson)")
class _LiveProbeTestCase(unittest.TestCase):
    """The target paused at a normal stop just before calling add_numbers."""

    def setUp(self):
        from tests.helpers import create_debugger, export_address, stop_at

        self.dbg, self.pid, self.tid = create_debugger(_TARGET)
        self.base, self.size = _module_base(
            self.dbg, os.path.basename(_TARGET))
        self.addr = export_address(self.dbg, _TARGET, "add_numbers")
        # The loader breakpoint is still holding the target on its pending
        # event; release it so run_until() inside stop_at() gets to run.
        self.dbg.continue_event(self.pid, self.tid)
        # A hardware breakpoint needs a normal stop, not the loader breakpoint.
        self._stopped = stop_at(self.dbg, self.addr)

    def tearDown(self):
        from tests.helpers import teardown

        teardown(self.dbg)

    def resume_after_stop(self):
        """Release the single-step event `stop_at` left the target on."""
        self.dbg.continue_event(self.pid, self.tid)


class TestFunctionProbeCalls(_LiveProbeTestCase):
    """A call becomes a fact: thread, return RVA, int args, timestamp."""

    def test_three_calls_record_args_and_return_rva(self):
        probe = FunctionProbe(self.dbg, self.addr, params=2, max_calls=3)
        hook_id = probe.arm()
        self.assertIsInstance(hook_id, int)
        self.assertEqual(probe.hook_id, hook_id)

        self.resume_after_stop()
        summary = probe.run(max_idle_timeouts=5)

        self.assertIsInstance(summary, ProbeSummary)
        self.assertEqual(len(summary.calls), 3,
                         "max_calls=3 must record exactly three calls")
        self.assertEqual(summary.reason, STOP_MAX_EVENTS)
        self.assertTrue(summary.truncated,
                        "a call-budget stop is a truncation")
        self.assertTrue(summary.single_step_pending,
                        "the stopped run owns an uncontinued debug event")
        last_ts = 0
        for call in summary.calls:
            self.assertIsInstance(call, ProbeCall)
            self.assertEqual(call.tid, self.tid)
            self.assertEqual(call.args, (1, 2),
                             "add_numbers is called as add_numbers(1, 2)")
            self.assertGreater(call.rva, 0,
                               "the return address must be in the module")
            self.assertLess(call.rva, self.size)
            self.assertGreater(call.ts, last_ts, "timestamps must increase")
            last_ts = call.ts

        self.assertEqual(probe.disarm(), ())
        self.assertEqual(self.dbg.verify_breakpoints(), [])
        self.dbg.terminate_process(0)
        self.assertEqual(self.dbg.get_exit_code(), 0,
                         "the target must still terminate normally")


class TestFunctionProbeBudget(_LiveProbeTestCase):
    """The call budget stops the run and says the caller owns the event."""

    def test_max_calls_one_records_one_call_and_leaves_the_event(self):
        probe = FunctionProbe(self.dbg, self.addr, params=2, max_calls=1)
        probe.arm()
        self.resume_after_stop()

        summary = probe.run(max_idle_timeouts=5)

        self.assertEqual(len(summary.calls), 1)
        self.assertEqual(summary.calls[0].args, (1, 2))
        self.assertEqual(summary.reason, STOP_MAX_EVENTS)
        self.assertTrue(summary.truncated)
        self.assertTrue(summary.single_step_pending,
                        "the caller owns the uncontinued debug event")
        self.assertIsNotNone(self.dbg.find_breakpoint(self.addr),
                             "run() must not disarm: the caller owns that")
        self.assertEqual(probe.disarm(), ())
        self.assertEqual(self.dbg.find_breakpoint(self.addr), None)

    def test_max_calls_zero_stops_on_the_first_hit_and_records_nothing(self):
        probe = FunctionProbe(self.dbg, self.addr, max_calls=0)
        probe.arm()
        self.resume_after_stop()

        summary = probe.run(max_idle_timeouts=5)

        self.assertEqual(summary.calls, (),
                         "the budget is checked before recording")
        self.assertEqual(summary.reason, STOP_MAX_EVENTS)
        self.assertTrue(summary.truncated)
        self.assertTrue(summary.single_step_pending)
        self.assertEqual(probe.disarm(), ())

    def test_the_target_runs_on_after_a_budget_stop(self):
        """The stopped event must remain continuable, without stray hits.

        A budget stop leaves the event uncontinued; the caller's next move is
        continue_event(). The slot address was cleared before returning, so the
        target must run without delivering another probe stop to nobody.
        """
        probe = FunctionProbe(self.dbg, self.addr, max_calls=1)
        probe.arm()
        self.resume_after_stop()
        summary = probe.run(max_idle_timeouts=5)
        self.assertTrue(summary.single_step_pending)

        self.dbg.continue_event(self.pid, self.tid)
        stray = []
        deadline = time.monotonic() + 0.15
        while time.monotonic() < deadline:
            event = self.dbg.wait_event(50)
            if event is None:
                continue
            stray.append(event)
            self.dbg.continue_event(event.pid, event.tid)

        self.assertEqual(stray, [],
                         "a stopped probe left hardware hits behind")
        self.assertEqual(probe.disarm(), ())


class TestFunctionProbeSlots(_LiveProbeTestCase):
    """Four debug-register slots are the whole budget, shared with watches."""

    def test_a_fifth_probe_is_refused_with_a_named_error(self):
        probes = [FunctionProbe(self.dbg, self.addr) for _ in range(4)]
        for probe in probes:
            self.assertIsInstance(probe.arm(), int)

        fifth = FunctionProbe(self.dbg, self.addr)
        with self.assertRaises(BreakpointError) as raised:
            fifth.arm()
        self.assertIn("no free debug-register slot", str(raised.exception))
        self.assertIsNone(fifth.hook_id,
                          "a refused arm must not pretend to have an id")

        for probe in probes:
            self.assertEqual(probe.disarm(), ())
        self.assertIsNone(self.dbg.find_breakpoint(self.addr))


class TestFunctionProbeSink(_LiveProbeTestCase):
    """A sink receives the same calls the summary counts, as API events."""

    def test_writer_and_reader_agree_with_the_recorded_calls(self):
        probe = FunctionProbe(self.dbg, self.addr, params=2, max_calls=2)
        hook_id = probe.arm()

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "calls.pdbgtrc")
            with TraceWriter(path) as writer:
                probe.sink = writer.write
                self.resume_after_stop()
                summary = probe.run(max_idle_timeouts=5)
            events = list(read_trace(path))

        self.assertEqual(len(events), 2)
        self.assertEqual(len(events), len(summary.calls))
        for event, call in zip(events, summary.calls):
            self.assertEqual(event.kind, API)
            self.assertEqual(event.a, hook_id,
                             "the hook id must be the breakpoint id")
            self.assertEqual(event.rva, call.rva)
            self.assertEqual(event.tid, call.tid)
            self.assertEqual(event.ts, call.ts)

        self.assertEqual(probe.disarm(), ())


@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
class TestFunctionProbeArguments(unittest.TestCase):
    """The constructor refuses what it cannot do, before touching a target."""

    def test_more_than_four_params_is_refused(self):
        from pydbg import Debugger

        for params in (5, -1):
            with self.assertRaises(ValueError) as raised:
                FunctionProbe(Debugger(), 0x1000, params=params)
            self.assertIn("0-4", str(raised.exception),
                          "the error must name the supported range")


class TestFunctionProbeHonestStops(_LiveProbeTestCase):
    """No module, or no target, is a reason — not an empty, silent run."""

    def test_a_module_without_a_base_reports_no_module(self):
        probe = FunctionProbe(self.dbg, self.addr, module=(0, 0))

        summary = probe.run()

        self.assertEqual(summary.calls, ())
        self.assertEqual(summary.reason, STOP_NO_MODULE)
        self.assertFalse(summary.truncated)
        self.assertIsNone(probe.hook_id, "it must not arm what it cannot map")

    def test_no_target_reports_no_target(self):
        from pydbg import Debugger

        summary = FunctionProbe(Debugger(), 0x1000).run()

        self.assertEqual(summary.calls, ())
        self.assertEqual(summary.reason, STOP_NO_TARGET)
        self.assertFalse(summary.truncated)


if __name__ == "__main__":
    unittest.main()
