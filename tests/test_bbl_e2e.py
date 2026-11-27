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

`TestBblAcceptance` runs the case on the x64 `instrument_target`.
`TestBblAcceptance32` is §12.5 item 6: the same case on the WOW64
`loop_target32` that `scripts/build-target32.ps1` builds, with only the target,
the stop export and the context's instruction-pointer name changed. It is
gated on a 64-bit host as well, because a 32-bit host cannot debug WOW64.

The execution slice is "loader stop -> first call of the stop export". The
targets loop, so a slice has to be delimited by an address rather than by exit;
the stop export (`add_numbers` on x64, `bump` on the 32-bit target) is the one
deterministic stop both mechanisms can share. It is left undetoured (and its
RVA is excluded from the comparison) because `run_until` needs a real
instruction there to break on.

One defect the live path found and this file now covers offline: the decoder
returns VA-addressed instructions while the CFG speaks RVAs, so `plan()` must
lift the block RVA into the decoder's space before comparing addresses
(`test_plan_accepts_va_addressed_instructions`). Without that, every block is
planned as unrelocatable on a real image and the acceptance below cannot even
start.
"""

import os
import struct
import sys
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
# The 32-bit acceptance target is a product of scripts/build-target32.ps1
# (meson has no x86 toolchain); tests/meson.build exports its path.
_TARGET32 = os.environ.get(
    "TEST_LOOP_TARGET32_PATH",
    os.path.join(_HERE, "target", "loop_target32.exe"))

# The declared skip families. A machine missing one of these cannot run the
# live acceptance, and must say which instead of passing silently.
needs_keystone = unittest.skipUnless(
    _has_keystone, "optional dependency: keystone-engine")
needs_cython = unittest.skipUnless(
    _has_cython, "optional dependency: Cython extension")
needs_target = unittest.skipUnless(
    os.path.isfile(_TARGET), "target not built: " + _TARGET)
needs_target32 = unittest.skipUnless(
    os.path.isfile(_TARGET32),
    "target not built: " + _TARGET32 + " (scripts/build-target32.ps1)")


def _wow64_available():
    """True only on 64-bit Windows (a 32-bit host cannot debug WOW64)."""
    return struct.calcsize("P") == 8 and sys.platform == "win32"


needs_wow64 = unittest.skipUnless(
    _wow64_available(), "environment: 64-bit Windows host")

_BREAKPOINT_CODES = frozenset((EXCEPTION_BREAKPOINT, STATUS_WX86_BREAKPOINT))

# GetExitCodeProcess answers this while the process is still running.
_STILL_ACTIVE = 259

# The tracer's 100_000-event default is below what this slice costs on a CI
# runner. loop_target32 statically links the CRT, so the startup that scans the
# inherited environment block runs in the module and yields block events: a
# 33 KB environment costs ~180_000 hits before `bump` is reached, against
# ~27_000 for a developer's 3 KB one. With the default budget the run is cut off
# during startup (reason `max_events`) while the stop block is planned and
# armed, so the tracer never reaches it. 500_000 is ~3x the measured worst case
# for the largest environment block CreateProcess may pass (32 KB).
_TRACER_MAX_EVENTS = 500_000


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


def _target_module(dbg, target):
    """The `enum_modules()` record for `target`'s own image.

    `enum_modules()` is ordered by load, and other images can precede the
    debuggee, so match by basename (like `helpers.module_base`) and fall back to
    the first entry only when the name is not there yet.
    """
    wanted = os.path.basename(target).lower()
    modules = dbg.enum_modules()
    for module in modules:
        if os.path.basename(module.get("name") or "").lower() == wanted:
            return module
    return modules[0]


def _prepare(dbg, target, stop_export):
    """(module, base, analysis, stop RVA) for the live target."""
    from tests.helpers import export_address

    module = _target_module(dbg, target)
    base = module["base_address"]
    result = analyze_process(dbg._session, base, module_size=module["size"])
    stop_rva = export_address(dbg, target, stop_export) - base
    return module, base, result, stop_rva


def _entry_candidates(dbg, module, base, result, stop_rva, target):
    """Relocatable blocks of the entry function, minus the stop address.

    The entry function is the slice the target walks first; its blocks are the
    ones the execution below can actually reach before the stop export. Blocks
    that cannot host an E9 (no 5-byte prefix, branch in the prefix) are
    excluded because `install()` would only refuse them, and the acceptance
    reconciles *installed* blocks.
    """
    from tests.helpers import entry_point

    entry_rva = entry_point(dbg, image=target) - base
    cfg = cfg_of(result, entry_rva)
    entry_blocks = ({block.rva for block in cfg.blocks.values()}
                    if cfg is not None else set())
    plans = BblInstrumenter(dbg, module=module, result=result).plan()
    chosen = [plan for plan in plans
              if plan.relocatable and plan.rva in entry_blocks
              and plan.rva != stop_rva]
    if not chosen:
        raise AssertionError(
            "no relocatable block of the entry function was planned")
    return chosen


def _create_debugger32(target, attempts=200):
    """A debugger stopped at a loader breakpoint with `target`'s image readable.

    A WOW64 target has two loader breakpoints: the 64-bit bootstrap one, then
    the 32-bit (WX86) one. The 32-bit image is not necessarily mapped at the
    first, and the debuggee is paused at every event, so waiting cannot make an
    unreadable image readable: the earlier events are continued instead, and the
    first event that finds the image is left pending. That is still before the
    entry point, which is the point `plan()` and `install()` need.
    """
    from pydbg import Debugger
    from pydbg.exceptions import MemError
    from tests.helpers import module_base

    dbg = Debugger()
    pid, tid = dbg.create_process(target)
    for _ in range(attempts):
        event = dbg.wait_event(5000)
        if event is None or event.type == "EXIT_PROCESS":
            break
        try:
            readable = dbg.read_memory(module_base(dbg, target), 2) == b"MZ"
        except (AssertionError, MemError):
            readable = False
        if event.type == "EXCEPTION" and readable:
            return dbg, pid, tid
        dbg.continue_event(event.pid, event.tid)
    raise AssertionError(
        f"{target}: the 32-bit image never became readable at a loader stop")


class _StopAtTracer(BblTracer):
    """A tracer whose run ends on the first hit at `stop_address`.

    `BblTracer.run()` stops for a budget, target exit or a callback returning
    False. The detour run is delimited by reaching the stop export, so this
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


class _IpInWindow:
    """A debugger proxy whose thread context reports an IP inside `window`.

    Only `get_registers()` is faked; suspension, memory and allocation go to
    the real target. That is what §12.5(2) asks for: a *fake thread context*
    parked inside the bytes about to be rewritten, so the refusal path is
    exercised without editing a live thread's context. The register is RIP on
    an x64 target and EIP on a WOW64 one, because that is what the patch
    window check reads.
    """

    def __init__(self, dbg, address, size, ip_name="rip"):
        self._wrapped = dbg
        self._context = {ip_name: address + max(size // 2, 1)}

    def __getattr__(self, name):
        return getattr(self._wrapped, name)

    def get_registers(self, handle):
        return dict(self._context)


@needs_keystone
@needs_cython
@needs_target
class TestBblAcceptance(unittest.TestCase):
    """§12.5 on the real `instrument_target`: run, reconcile, restore, exit."""

    # The three facts a target contributes; the 32-bit subclass overrides them.
    target = _TARGET
    stop_export = "add_numbers"
    ip_name = "rip"
    wow64 = False

    def start(self):
        """A debugger paused at a loader stop, before the target's entry point."""
        from tests.helpers import create_debugger

        if self.wow64:
            return _create_debugger32(self.target)
        return create_debugger(self.target)

    def detour_slice(self):
        """Install entry-function detours and run to the first stop export.

        Returns the executed block set, the events, the installed RVAs, the
        plans and the wall time of the detoured run. Uninstall runs while the
        target is still paused at the stop, which is the documented point to
        drain the ring and restore bytes.
        """
        from tests.helpers import teardown

        dbg, pid, tid = self.start()
        try:
            module, base, result, stop_rva = _prepare(
                dbg, self.target, self.stop_export)
            chosen = _entry_candidates(
                dbg, module, base, result, stop_rva, self.target)
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
            dbg.run_until(base + stop_rva, max_wait_ms=15000,
                          max_idle_timeouts=3)
            elapsed = max(time.perf_counter() - started, 1e-9)

            events = instrumenter.events()
            self.assertTrue(events, "the detoured blocks recorded no event")
            self.assertEqual(instrumenter.uninstall(), ())
            return {
                "events": events,
                "blocks": {event.rva for event in events},
                "installed": set(report.installed),
                "stop_rva": stop_rva,
                "elapsed": elapsed,
            }
        finally:
            teardown(dbg)

    def tracer_slice(self, stop_rva):
        """The blocks a full-plan `BblTracer` hits from loader to stop export.

        The full plan is kept on purpose: the comparison then has to *exclude*
        the blocks the detour path could not install, which is what proves the
        reconciliation is over the instrumented window and not a tautology.

        The tracer gets a larger event budget than the 100_000 default. The
        32-bit target statically links the CRT, so the startup that scans the
        inherited environment block runs in the module and produces block
        events; a CI runner's environment is an order of magnitude larger than
        a developer's, and the default budget then truncates the run during
        startup. The stop block is planned and armed in that case, it is
        simply never reached — so the budget, not the plan, is what has to
        cover the target's startup (`_TRACER_MAX_EVENTS`).
        """
        from tests.helpers import teardown

        dbg, pid, tid = self.start()
        try:
            module, base, _result, _ = _prepare(
                dbg, self.target, self.stop_export)
            stop_address = base + stop_rva
            # Armed while still paused and reused by arm(), so the stop cannot
            # be missed by a race between resume and set_breakpoint.
            dbg.set_breakpoint(stop_address)
            recorded = []
            tracer = _StopAtTracer(dbg, stop_address, module=module,
                                   max_events=_TRACER_MAX_EVENTS)
            self.assertGreater(tracer.plan(), 0, "the target planned no blocks")
            tracer.sink = recorded.append

            dbg.continue_event(pid, tid)
            summary = tracer.run(max_idle_timeouts=3)

            self.assertGreater(summary.events, 0,
                               "the tracer hit no planned block")
            self.assertIn("reused caller breakpoints", summary.warnings,
                          "the stop breakpoint was not reused")
            self.assertFalse(
                summary.truncated,
                f"the trace was cut short by {summary.reason} after "
                f"{summary.events} events, before the shared stop block: a "
                f"truncated run cannot reconcile the two slices")
            blocks = {event.rva for event in recorded}
            self.assertIn(stop_rva, blocks,
                          "the tracer did not reach the shared stop block")
            return blocks
        finally:
            teardown(dbg)

    def test_detour_events_match_the_breakpoint_tracer(self):
        detour = self.detour_slice()
        traced = self.tracer_slice(detour["stop_rva"])

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
        print(f"\nbbl e2e ({self.target}): detours={len(detour['installed'])} "
              f"events={len(detour['events'])} blocks={len(detour['blocks'])} "
              f"run={detour['elapsed']:.3f}s "
              f"({blocks_per_second:.0f} blocks/s)")

    def test_uninstall_restores_every_displaced_byte(self):
        from tests.helpers import teardown

        dbg, pid, tid = self.start()
        try:
            module, base, result, stop_rva = _prepare(
                dbg, self.target, self.stop_export)
            chosen = _entry_candidates(
                dbg, module, base, result, stop_rva, self.target)
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
            dbg.run_until(base + stop_rva, max_wait_ms=15000,
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
        from tests.helpers import teardown

        dbg, pid, tid = self.start()
        try:
            module, base, result, stop_rva = _prepare(
                dbg, self.target, self.stop_export)
            chosen = _entry_candidates(
                dbg, module, base, result, stop_rva, self.target)
            instrumenter = BblInstrumenter(
                dbg, module=module, result=result,
                blocks=[plan.rva for plan in chosen], max_events=1024)
            report = instrumenter.install()
            self.assertTrue(report.installed, report.refused)

            dbg.continue_event(pid, tid)
            dbg.run_until(base + stop_rva, max_wait_ms=15000,
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
        from tests.helpers import teardown

        dbg, pid, tid = self.start()
        try:
            module, base, result, stop_rva = _prepare(
                dbg, self.target, self.stop_export)
            plan = _entry_candidates(
                dbg, module, base, result, stop_rva, self.target)[0]
            address = base + plan.rva
            before = dbg.read_memory(address, plan.prefix_size)

            proxy = _IpInWindow(dbg, address, plan.prefix_size, self.ip_name)
            instrumenter = BblInstrumenter(
                proxy, module=module, result=result, blocks=[plan.rva])
            report = instrumenter.install()

            self.assertEqual(report.installed, (),
                             "a conflicting block was patched anyway")
            self.assertEqual(len(report.refused), 1)
            rva, reason = report.refused[0]
            self.assertEqual(rva, plan.rva)
            self.assertIn("target busy", reason)
            self.assertIn(f"0x{address:X}", reason,
                          "the refusal did not name the window it refused")
            self.assertEqual(dbg.read_memory(address, plan.prefix_size), before,
                             "the refused block's bytes were changed")
            self.assertEqual(instrumenter.events(), ())
        finally:
            teardown(dbg)


@needs_keystone
@needs_cython
@needs_wow64
@needs_target32
class TestBblAcceptance32(TestBblAcceptance):
    """§12.5 item 6: the same acceptance on the WOW64 `loop_target32`.

    The target is the 32-bit loop sample: its own in-module loop calls `bump`
    once per iteration, so the instrumentation runs 32-bit code that never
    leaves the module. `plan()` must be non-empty here -- an architecture check
    that rejected every block would fail the inherited first assertion -- and
    the x86 `relocatable` criterion is the same "no branch in the prefix", with
    no RIP-relative case to consider (spec §12.1).
    """

    target = _TARGET32
    stop_export = "bump"
    ip_name = "eip"
    wow64 = True


if __name__ == "__main__":
    unittest.main()
