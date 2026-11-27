"""The phase-6 scale budgets, measured and printed (spec §13.5).

One test per path, each printing its own `measured=` figure:

- static: `pe_builder`-synthesised 10,000-function image -> `analyze_bytes`
  under 60 s;
- dynamic single-step: the Phase 3b `InstructionTracer` 10^4-instruction
  window on `loop_target` under 10 s;
- dynamic instrumented: 1,000,000 BBL hits on `loop_target` under 120 s.

The ceilings are deliberately loose: they catch an order-of-magnitude
regression, not machine load. That is the repo's own precedent (§10.6(6):
publish the measurement, keep the threshold wide). A failing instrumented run
prints the last RIP and the installed block count, so a dead detour reads
differently from a slow one.

Why the single-step budget has two samples. `loop_target`'s in-module loop is
the spec's 10^4 sample: it can fill the Phase 3b window, so the count-bearing
budget is measured there. The `instrument_target` run is kept as a guard —
its loop calls `Sleep()`, and the tracer stops when control leaves the module,
so that window fills a handful of instructions, not 10^4. Both are reported;
neither replaces the other.

The 10^6 promise is for the instrumented path only. `trace/bbl.py` says why a
breakpoint tracer cannot reach it: one stop, a byte restore and a single-step
resume per block — that is a DBI engine's job, and Phase 3b did not build one.

The static image is built in memory (`build_function_image` returns bytes), so
the number measured is the analysis, not the fixture, and no temp file has to
be cleaned up.
"""

import os
import time
import unittest

try:
    import capstone  # noqa: F401

    _has_capstone = True
except ImportError:                      # pragma: no cover - environment
    _has_capstone = False

try:
    import keystone  # noqa: F401

    _has_keystone = True
except ImportError:                      # pragma: no cover - environment
    _has_keystone = False

try:
    from pydbg import _pydbg  # noqa: F401

    _has_cython = True
except ImportError:                      # pragma: no cover - environment
    _has_cython = False

_HERE = os.path.dirname(os.path.abspath(__file__))

# The targets are built by meson; `TEST_*_PATH` is only set under `meson test`,
# so the default names the same artefact beside the sources. Every skip says
# which path was missing instead of letting the run go quiet.
_INSTRUMENT_TARGET = os.environ.get(
    "TEST_INSTRUMENT_TARGET_PATH",
    os.path.join(_HERE, "target", "instrument_target.exe"))
_LOOP_TARGET = os.environ.get(
    "TEST_LOOP_TARGET_PATH",
    os.path.join(_HERE, "target", "loop_target.exe"))

needs_capstone = unittest.skipUnless(
    _has_capstone, "optional dependency: capstone")
needs_keystone = unittest.skipUnless(
    _has_keystone, "optional dependency: keystone-engine")
needs_cython = unittest.skipUnless(
    _has_cython, "optional dependency: Cython extension")
needs_instrument_target = unittest.skipUnless(
    os.path.isfile(_INSTRUMENT_TARGET),
    "target not built: " + _INSTRUMENT_TARGET)
needs_loop_target = unittest.skipUnless(
    os.path.isfile(_LOOP_TARGET), "target not built: " + _LOOP_TARGET)

# The three budgets from spec §13.5.
STATIC_BUDGET_S = 60.0
SINGLE_STEP_BUDGET_S = 10.0
INSTRUMENTED_BUDGET_S = 120.0

# The samples, sized to the spec's table rather than to what the machine can do.
FUNCTION_COUNT = 10_000
# A synthetic image carries the loader's own function table, so this is a floor
# for the count, not the number the fixture was built with: a regression that
# loses a seed class must fail, not silently analyze a smaller program.
MIN_FUNCTIONS = 9_000
INSTRUCTION_WINDOW = 10_000
LOOP_ITERATIONS = 1_000_000


def _last_rip(dbg, tid):
    """The stopped thread's instruction pointer, or why it is unavailable."""
    try:
        registers = dbg.get_registers(tid)
    except Exception as exc:              # pragma: no cover - dead target
        return f"unavailable ({exc})"
    for name in ("rip", "eip"):
        value = registers.get(name)
        if value is not None:
            return f"0x{value:X}"
    return "unavailable (no instruction pointer in the context)"


def _diagnostics(dbg, tid, installed):
    """The two facts that tell a dead detour from a slow one."""
    return f"last RIP={_last_rip(dbg, tid)}, installed blocks={installed}"


class TestStaticTenThousandFunctions(unittest.TestCase):
    """10,000 functions analysed from an in-memory PE32+ within 60 s."""

    @needs_capstone
    def test_ten_thousand_functions_analyze_within_budget(self):
        from pydbg.analysis import analyze_bytes
        from tests.bench_helpers import build_function_image

        image = build_function_image(FUNCTION_COUNT)

        started = time.perf_counter()
        result = analyze_bytes(image)
        elapsed = time.perf_counter() - started

        stats = result.stats
        print(f"\nscale static: functions={stats.func_starts} "
              f"confident={stats.func_starts_confident} "
              f"insns={stats.insns} measured={elapsed:.3f}s "
              f"budget={STATIC_BUDGET_S:.0f}s")

        self.assertGreaterEqual(
            stats.func_starts, MIN_FUNCTIONS,
            f"the analysis recovered {stats.func_starts} of {FUNCTION_COUNT} "
            f"functions: a seed class or the sweep is short")
        self.assertFalse(
            stats.budget_exhausted,
            "the instruction ceiling stopped the sweep: the count is a floor")
        self.assertLess(
            elapsed, STATIC_BUDGET_S,
            f"10k functions took {elapsed:.1f}s (budget {STATIC_BUDGET_S:.0f}s)")


class TestSingleStepTenThousand(unittest.TestCase):
    """The Phase 3b instruction window: 10^4 single steps under 10 s."""

    @needs_cython
    @needs_instrument_target
    def test_instrument_target_window_runs_within_budget(self):
        """A second budget guard, not the 10^4 measurement.

        `instrument_target` calls `Sleep()` every iteration, and the tracer
        stops when control leaves the module, so this window ends after a few
        instructions. The test still does its job — a 10,000-instruction
        ceiling must not wedge the tracer — but the number that proves 10^4
        *were* recorded is the `loop_target` test below, which is the spec's
        named sample (§13.5).
        """
        from pydbg.trace.instr import InstructionTracer
        from tests.helpers import create_debugger, export_address, teardown

        dbg, pid, tid = create_debugger(_INSTRUMENT_TARGET)
        try:
            add_numbers = export_address(
                dbg, _INSTRUMENT_TARGET, "add_numbers")
            # Stepping does nothing before the loader breakpoint is released.
            dbg.continue_event(pid, tid)
            tracer = InstructionTracer(
                dbg, max_instructions=INSTRUCTION_WINDOW)
            summary = tracer.run(start=add_numbers)
        finally:
            teardown(dbg)

        elapsed = summary.elapsed_ns / 1e9
        print(f"\nscale single-step (instrument_target): events={summary.events} "
              f"reason={summary.reason} measured={elapsed:.3f}s "
              f"budget={SINGLE_STEP_BUDGET_S:.0f}s")

        self.assertGreater(summary.events, 0, "the window recorded nothing")
        self.assertLessEqual(summary.events, INSTRUCTION_WINDOW)
        self.assertLess(
            elapsed, SINGLE_STEP_BUDGET_S,
            f"the window took {elapsed:.1f}s "
            f"(budget {SINGLE_STEP_BUDGET_S:.0f}s); reason={summary.reason}")

    @needs_cython
    @needs_loop_target
    def test_loop_target_fills_a_ten_thousand_instruction_window(self):
        """The 10^4 budget with the count it is named for.

        `loop_target`'s hot loop calls only an in-module function, so control
        never leaves the module and the tracer has to reach its own
        `max_instructions` ceiling: `events == 10_000` is the fact that makes
        the timing a 10^4 measurement rather than a program-exit measurement.
        """
        from pydbg.trace.instr import InstructionTracer
        from tests.helpers import create_debugger, export_address, teardown

        dbg, pid, tid = create_debugger(_LOOP_TARGET)
        try:
            bump = export_address(dbg, _LOOP_TARGET, "bump")
            dbg.continue_event(pid, tid)
            tracer = InstructionTracer(
                dbg, max_instructions=INSTRUCTION_WINDOW)
            summary = tracer.run(start=bump)
        finally:
            teardown(dbg)

        elapsed = summary.elapsed_ns / 1e9
        print(f"\nscale single-step (loop_target): events={summary.events} "
              f"reason={summary.reason} measured={elapsed:.3f}s "
              f"budget={SINGLE_STEP_BUDGET_S:.0f}s")

        self.assertEqual(
            summary.events, INSTRUCTION_WINDOW,
            f"the window stopped at {summary.events} instructions "
            f"(reason={summary.reason}) instead of the 10^4 ceiling")
        self.assertTrue(summary.truncated)
        self.assertLess(
            elapsed, SINGLE_STEP_BUDGET_S,
            f"10^4 single steps took {elapsed:.1f}s "
            f"(budget {SINGLE_STEP_BUDGET_S:.0f}s)")


class TestInstrumentedMillionBlocks(unittest.TestCase):
    """1,000,000 instrumented block hits on `loop_target` within 120 s.

    One explicit detour, on the block that starts at `bump`. Every iteration
    of the target's loop calls `bump` exactly once, so one detour produces
    exactly one BLOCK record per iteration and the ring's write count is the
    iteration count.
    """

    @needs_keystone
    @needs_cython
    @needs_loop_target
    def test_one_million_instrumented_blocks_within_budget(self):
        from pydbg.analysis import analyze_process
        from pydbg.exceptions import TimeoutError as PydbgTimeoutError
        from pydbg.instrument.bbl import BblInstrumenter
        from tests.helpers import create_debugger, export_address, teardown

        dbg, pid, tid = create_debugger(_LOOP_TARGET)
        instrumenter = None
        report = None
        try:
            module = dbg.enum_modules()[0]
            base = module["base_address"]
            bump_rva = export_address(dbg, _LOOP_TARGET, "bump") - base
            done = export_address(dbg, _LOOP_TARGET, "loop_done")
            result = analyze_process(
                dbg._session, base, module_size=module["size"])

            # The ring has to hold every hit before the first drain: a smaller
            # max_events would wrap at capacity and `events()` would report the
            # truncation instead of the count the budget is about.
            instrumenter = BblInstrumenter(
                dbg, module=module, result=result, blocks=[bump_rva],
                max_events=LOOP_ITERATIONS)
            report = instrumenter.install()
            self.assertEqual(
                report.installed, (bump_rva,),
                f"the bump block was not instrumented: {report.refused}")

            dbg.continue_event(pid, tid)
            started = time.perf_counter()
            try:
                dbg.run_until(done, max_wait_ms=120_000,
                              max_idle_timeouts=3)
            except PydbgTimeoutError as exc:
                installed = len(report.installed) if report else 0
                self.fail(
                    f"the loop did not reach loop_done: {exc}; "
                    f"{_diagnostics(dbg, tid, installed)}")
            events = instrumenter.events()
            elapsed = time.perf_counter() - started

            print(f"\nscale instrumented: blocks={len(events)} "
                  f"installed={len(report.installed)} "
                  f"measured={elapsed:.3f}s "
                  f"budget={INSTRUMENTED_BUDGET_S:.0f}s")
            self.assertGreaterEqual(
                len(events), LOOP_ITERATIONS,
                f"the detour fired {len(events)} times for "
                f"{LOOP_ITERATIONS} iterations: "
                f"{_diagnostics(dbg, tid, len(report.installed))}")
            self.assertLess(
                elapsed, INSTRUMENTED_BUDGET_S,
                f"1e6 instrumented blocks took {elapsed:.1f}s "
                f"(budget {INSTRUMENTED_BUDGET_S:.0f}s): "
                f"{_diagnostics(dbg, tid, len(report.installed))}")
            self.assertEqual(
                {event.rva for event in events}, {bump_rva},
                "an event names a block that was not the one instrumented")
        finally:
            if instrumenter is not None:
                try:
                    instrumenter.uninstall()
                except Exception:         # pragma: no cover - best effort
                    pass
            teardown(dbg)


if __name__ == "__main__":
    unittest.main()
