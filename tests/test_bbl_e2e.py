"""End-to-end acceptance for BBL instrumentation (spec §12.5).

This is the file that runs the three pieces together on a real target: the
block plan (`BblInstrumenter.plan()`), the thread-checked patch writer
(`install()`/`uninstall()`) and the target-side event ring (`events()`). It
answers the questions §12.5 asks, not the ones the unit tests already answer:

1. a detour fires for exactly the blocks a `BblTracer` INT3 fires on, over the
   same execution slice, and no block that was not instrumented produces an
   event;
2. every displaced byte comes back on `uninstall()`;
3. the target can still be terminated normally and nothing is left armed;
4. a thread parked inside the patch window refuses that block with
   `target busy`, and its bytes are untouched;
5. overhead is recorded and printed, with no hard threshold;
6. the live tests declare the three skip families (`optional dependency:
   keystone-engine`, `optional dependency: Cython extension`,
   `target not built:`), so a machine that cannot run them says which
   precondition failed instead of going quiet.

The execution slice is "loader stop -> first `add_numbers` call". The target is
an infinite loop, so a slice has to be delimited by an address rather than by
exit; `add_numbers` is the one deterministic stop both mechanisms can share.
`add_numbers` itself is left undetoured (and its RVA is excluded from the
comparison) because `run_until` needs a real instruction there to break on.

One defect the live path found and this file now covers offline: the decoder
returns VA-addressed instructions while the CFG speaks RVAs, so `plan()` must
lift the block RVA into the decoder's space before comparing addresses
(`test_plan_accepts_va_addressed_instructions`). Without that, every block is
planned as unrelocatable on a real image and the acceptance below cannot even
start.
"""

import os
import time
import unittest
from types import SimpleNamespace

from pydbg.analysis import analyze_process
from pydbg.analysis.cfg import cfg_of
from pydbg.constants import EXCEPTION_BREAKPOINT, STATUS_WX86_BREAKPOINT
from pydbg.disasm.engine import Instruction
from pydbg.instrument import bbl
from pydbg.instrument.bbl import BblInstrumenter
from pydbg.trace import BblTracer
from pydbg.trace.format import BLOCK

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
_TARGET = os.environ.get(
    "TEST_INSTRUMENT_TARGET_PATH",
    os.path.join(_HERE, "target", "instrument_target.exe"))

# The three declared skip families. A machine missing one of these cannot run
# the live acceptance, and must say which instead of passing silently.
needs_keystone = unittest.skipUnless(
    _has_keystone, "optional dependency: keystone-engine")
needs_cython = unittest.skipUnless(
    _has_cython, "optional dependency: Cython extension")
needs_target = unittest.skipUnless(
    os.path.isfile(_TARGET), "target not built: " + _TARGET)

_BREAKPOINT_CODES = frozenset((EXCEPTION_BREAKPOINT, STATUS_WX86_BREAKPOINT))

# GetExitCodeProcess answers this while the process is still running.
_STILL_ACTIVE = 259


class _DictDecoder:
    """The decoder's one method `_decode_block` asks for.

    Keyed by the RVA it is asked for, returning a VA-addressed instruction —
    the same asymmetry the real `InstructionDecoder` has.
    """

    def __init__(self, instructions):
        self._by_rva = {rva: insn for rva, insn in instructions}

    def decode_one(self, rva):
        return self._by_rva.get(rva)


class TestPlanAddressSpace(unittest.TestCase):
    """plan() must reconcile the CFG's RVAs with the decoder's VAs.

    `InstructionDecoder.decode_one()` decodes at the instruction's *virtual*
    address — that is what makes RIP-relative resolution and branch targets
    meaningful (analysis/decoder.py). The CFG block list is RVAs. A planner that
    compares the two spaces directly sees every block as "the first instruction
    is not at the block entry" and plans it as unrelocatable, which is silent:
    the plan is non-empty, every prefix is 0, and install() has nothing to do.
    """

    BASE = 0x140000000
    RVA = 0x2010

    def result(self):
        decoded = [Instruction(
            address=self.BASE + self.RVA + offset, size=1, mnemonic="nop",
            op_str="", raw_bytes=b"\x90") for offset in range(6)]
        image = SimpleNamespace(is_exec=lambda rva: True)
        return SimpleNamespace(
            image=image,
            decoder=_DictDecoder(
                (self.RVA + offset, insn) for offset, insn in enumerate(decoded)))

    def test_plan_accepts_va_addressed_instructions(self):
        instrumenter = BblInstrumenter(
            SimpleNamespace(), result=self.result(), blocks=[self.RVA])

        (plan,) = instrumenter.plan()

        self.assertEqual(plan.rva, self.RVA)
        self.assertEqual(plan.prefix_size, bbl.DETOUR_SIZE,
                         "a 6-byte NOP run must yield a 5-byte prefix")
        self.assertTrue(plan.relocatable)
        self.assertEqual(plan.span, 6,
                         "span is bytes from the block entry, not a VA")


def _prepare(dbg):
    """(module, base, analysis, add_numbers RVA) for the live target."""
    from tests.helpers import export_address

    module = dbg.enum_modules()[0]
    base = module["base_address"]
    result = analyze_process(dbg._session, base, module_size=module["size"])
    add_rva = export_address(dbg, _TARGET, "add_numbers") - base
    return module, base, result, add_rva


def _entry_candidates(dbg, module, base, result, add_rva):
    """Relocatable blocks of the entry function, minus the stop address.

    The entry function is the slice the target walks first; its blocks are the
    ones the execution below can actually reach before `add_numbers`. Blocks
    that cannot host an E9 (no 5-byte prefix, branch in the prefix) are
    excluded because `install()` would only refuse them, and the acceptance
    reconciles *installed* blocks.
    """
    from tests.helpers import entry_point

    entry_rva = entry_point(dbg) - base
    cfg = cfg_of(result, entry_rva)
    entry_blocks = ({block.rva for block in cfg.blocks.values()}
                    if cfg is not None else set())
    plans = BblInstrumenter(dbg, module=module, result=result).plan()
    chosen = [plan for plan in plans
              if plan.relocatable and plan.rva in entry_blocks
              and plan.rva != add_rva]
    if not chosen:
        raise AssertionError(
            "no relocatable block of the entry function was planned")
    return chosen


class _StopAtTracer(BblTracer):
    """A tracer whose run ends on the first hit at `stop_address`.

    `BblTracer.run()` stops for a budget, target exit or a callback returning
    False. The detour run is delimited by reaching `add_numbers`, so this
    tracer ends the loop at the same instruction, making both observed sets
    describe the same execution slice.
    """

    def __init__(self, dbg, stop_address, **kwargs):
        super().__init__(dbg, **kwargs)
        self.stop_address = stop_address

    def _on_event(self, event):
        result = super()._on_event(event)
        if (event.type == "EXCEPTION"
                and getattr(event, "exception_code", None) in _BREAKPOINT_CODES
                and getattr(event, "exception_addr", None) == self.stop_address):
            return False
        return result


class _RipInWindow:
    """A debugger proxy whose thread context reports a RIP inside `window`.

    Only `get_registers()` is faked; suspension, memory and allocation go to
    the real target. That is what §12.5(2) asks for: a *fake thread context*
    parked inside the bytes about to be rewritten, so the refusal path is
    exercised without editing a live thread's context.
    """

    def __init__(self, dbg, address, size):
        self._wrapped = dbg
        self._rip = address + max(size // 2, 1)

    def __getattr__(self, name):
        return getattr(self._wrapped, name)

    def get_registers(self, handle):
        return {"rip": self._rip}


@needs_keystone
@needs_cython
@needs_target
class TestBblAcceptance(unittest.TestCase):
    """§12.5 on the real `instrument_target`: run, reconcile, restore, exit."""

    def detour_slice(self):
        """Install entry-function detours and run to the first add_numbers.

        Returns the executed block set, the events, the installed RVAs, the
        plans and the wall time of the detoured run. Uninstall runs while the
        target is still paused at the stop, which is the documented point to
        drain the ring and restore bytes.
        """
        from tests.helpers import create_debugger, teardown

        dbg, pid, tid = create_debugger(_TARGET)
        try:
            module, base, result, add_rva = _prepare(dbg)
            chosen = _entry_candidates(dbg, module, base, result, add_rva)
            instrumenter = BblInstrumenter(
                dbg, module=module, result=result,
                blocks=[plan.rva for plan in chosen], max_events=1024)
            planned = {plan.rva: plan for plan in instrumenter.plan()}
            self.assertEqual(set(planned), {plan.rva for plan in chosen})

            report = instrumenter.install()
            self.assertEqual(set(report.installed), set(planned),
                             f"blocks were refused: {report.refused}")
            self.assertEqual(report.warnings, ())

            dbg.continue_event(pid, tid)
            started = time.perf_counter()
            dbg.run_until(base + add_rva, max_wait_ms=15000,
                          max_idle_timeouts=3)
            elapsed = max(time.perf_counter() - started, 1e-9)

            events = instrumenter.events()
            self.assertTrue(events, "the detoured blocks recorded no event")
            self.assertEqual(instrumenter.uninstall(), ())
            return {
                "events": events,
                "blocks": {event.rva for event in events},
                "installed": set(report.installed),
                "add_rva": add_rva,
                "elapsed": elapsed,
            }
        finally:
            teardown(dbg)

    def tracer_slice(self, stop_rva):
        """The blocks a full-plan `BblTracer` hits from loader to add_numbers.

        The full plan is kept on purpose: the comparison then has to *exclude*
        the blocks the detour path could not install, which is what proves the
        reconciliation is over the instrumented window and not a tautology.
        """
        from tests.helpers import create_debugger, teardown

        dbg, pid, tid = create_debugger(_TARGET)
        try:
            _module, base, _result, _ = _prepare(dbg)
            stop_address = base + stop_rva
            # Armed while still paused and reused by arm(), so the stop cannot
            # be missed by a race between resume and set_breakpoint.
            dbg.set_breakpoint(stop_address)
            recorded = []
            tracer = _StopAtTracer(dbg, stop_address)
            self.assertGreater(tracer.plan(), 0, "the target planned no blocks")
            tracer.sink = recorded.append

            dbg.continue_event(pid, tid)
            summary = tracer.run(max_idle_timeouts=3)

            self.assertGreater(summary.events, 0,
                               "the tracer hit no planned block")
            self.assertIn("reused caller breakpoints", summary.warnings,
                          "the stop breakpoint was not reused")
            blocks = {event.rva for event in recorded}
            self.assertIn(stop_rva, blocks,
                          "the tracer did not reach the shared stop block")
            return blocks
        finally:
            teardown(dbg)

    def test_detour_events_match_the_breakpoint_tracer(self):
        detour = self.detour_slice()
        traced = self.tracer_slice(detour["add_rva"])

        self.assertTrue(detour["installed"])
        # Only BLOCK records, with the fields the stub can actually know (§12.1).
        for event in detour["events"]:
            self.assertEqual(event.kind, BLOCK)
            self.assertEqual(event.tid, 0, "the stub cannot know a tid")
            self.assertEqual(event.ts, 0, "the stub cannot know a ts")
            self.assertGreater(event.a, 0, "a BLOCK carries its instruction count")

        # A block that was not instrumented must not appear in the ring.
        self.assertFalse(detour["blocks"] - detour["installed"],
                         "an event names a block that was never detoured")

        # The same execution slice, the same instrumented blocks.
        self.assertEqual(detour["blocks"], traced & detour["installed"],
                         "detour events and tracer hits disagree")
        self.assertTrue(traced - detour["installed"],
                        "nothing outside the instrumented window executed; "
                        "the reconciliation would be vacuous")

        blocks_per_second = len(detour["blocks"]) / detour["elapsed"]
        print(f"\nbbl e2e: detours={len(detour['installed'])} "
              f"events={len(detour['events'])} blocks={len(detour['blocks'])} "
              f"run={detour['elapsed']:.3f}s "
              f"({blocks_per_second:.0f} blocks/s)")

    def test_uninstall_restores_every_displaced_byte(self):
        from tests.helpers import create_debugger, teardown

        dbg, pid, tid = create_debugger(_TARGET)
        try:
            module, base, result, add_rva = _prepare(dbg)
            chosen = _entry_candidates(dbg, module, base, result, add_rva)
            instrumenter = BblInstrumenter(
                dbg, module=module, result=result,
                blocks=[plan.rva for plan in chosen], max_events=1024)
            planned = {plan.rva: plan for plan in instrumenter.plan()}
            for plan in planned.values():
                self.assertGreaterEqual(plan.prefix_size, bbl.DETOUR_SIZE,
                                        "a planned prefix is shorter than a detour")
            snapshots = {
                base + rva: dbg.read_memory(base + rva, plan.prefix_size)
                for rva, plan in planned.items()
            }

            report = instrumenter.install()
            self.assertEqual(set(report.installed), set(planned), report.refused)
            dbg.continue_event(pid, tid)
            dbg.run_until(base + add_rva, max_wait_ms=15000,
                          max_idle_timeouts=3)
            self.assertTrue(instrumenter.events(),
                            "the run proved nothing; no detour fired")

            self.assertEqual(instrumenter.uninstall(), ())
            for address, original in snapshots.items():
                self.assertEqual(
                    dbg.read_memory(address, len(original)), original,
                    f"block 0x{address:X} was not restored byte for byte")
            self.assertEqual(dbg.verify_breakpoints(), [])
        finally:
            teardown(dbg)

    def test_the_target_terminates_cleanly_after_uninstall(self):
        from tests.helpers import create_debugger, teardown

        dbg, pid, tid = create_debugger(_TARGET)
        try:
            module, base, result, add_rva = _prepare(dbg)
            chosen = _entry_candidates(dbg, module, base, result, add_rva)
            instrumenter = BblInstrumenter(
                dbg, module=module, result=result,
                blocks=[plan.rva for plan in chosen], max_events=1024)
            report = instrumenter.install()
            self.assertTrue(report.installed, report.refused)

            dbg.continue_event(pid, tid)
            dbg.run_until(base + add_rva, max_wait_ms=15000,
                          max_idle_timeouts=3)
            self.assertEqual(instrumenter.uninstall(), ())
            self.assertEqual(dbg.verify_breakpoints(), [],
                             "a breakpoint was overwritten by the detours")

            # run_until leaves the stop's single-step pending; release it so
            # the target is not left half-stopped, then terminate it.
            dbg.continue_event(pid, tid)
            dbg.terminate_process(0)

            # The process handle outlives the kill, so GetExitCodeProcess is
            # the fact that says the target is gone: STILL_ACTIVE would mean it
            # is still running. Deliberately not compared with the value passed
            # to terminate_process() above -- that would assert an echo of our
            # own argument, not that the process ended (§12.5(1)).
            # terminate_process() drains the EXIT_PROCESS event itself, so the
            # exit code is the observable that remains.
            self.assertNotEqual(dbg.get_exit_code(), _STILL_ACTIVE,
                                "the target did not actually terminate")
            self.assertEqual(dbg.verify_breakpoints(), [],
                             "teardown left a software breakpoint behind")
        finally:
            teardown(dbg)

    def test_a_thread_inside_the_window_refuses_that_block(self):
        from tests.helpers import create_debugger, teardown

        dbg, pid, tid = create_debugger(_TARGET)
        try:
            module, base, result, add_rva = _prepare(dbg)
            plan = _entry_candidates(dbg, module, base, result, add_rva)[0]
            address = base + plan.rva
            before = dbg.read_memory(address, plan.prefix_size)

            proxy = _RipInWindow(dbg, address, plan.prefix_size)
            instrumenter = BblInstrumenter(
                proxy, module=module, result=result, blocks=[plan.rva])
            report = instrumenter.install()

            self.assertEqual(report.installed, (),
                             "a conflicting block was patched anyway")
            self.assertEqual(len(report.refused), 1)
            rva, reason = report.refused[0]
            self.assertEqual(rva, plan.rva)
            self.assertIn("target busy", reason)
            self.assertEqual(dbg.read_memory(address, plan.prefix_size), before,
                             "the refused block's bytes were changed")
            self.assertEqual(instrumenter.events(), ())
        finally:
            teardown(dbg)


if __name__ == "__main__":
    unittest.main()
