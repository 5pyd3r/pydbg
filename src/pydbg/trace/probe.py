"""FunctionProbe — count a function's calls with one hardware execute breakpoint.

The static analyzer can say where a function starts. This module makes the
dynamic half answerable: how often it was called, from where, and with which
int arguments (docs/analysis-coverage.md §9.6).

The probe writes no target byte and builds no detour. It arms one of the CPU's
four debug-register slots with an *execute* breakpoint at the function's entry
and walks the single-step dance the hardware requires: at a hit the instruction
has not run yet, so the slot address and dr6 are cleared and TF is set. The
following single-step event means the original instruction has now executed;
the slot address and the dr7 enable bit are put back there. Skipping the
restore is not cosmetic — the hardware forgets the address as the step retires
it, so every later hit silently disappears (measured).

What it can and cannot see is a deliberate boundary (spec §9.1 and §9.6):

* up to four int arguments, from the ABI registers on x64 (rcx/rdx/r8/r9) or
  the stack on x86 ([esp+4+4*i]), as their low 32 bits;
* the return address found at the function's entry, hence the caller's RVA;
* the thread that made the call.

It cannot see the return value: the entry has not produced one yet, and the
return address cannot in general be watched with the same four shared slots.
Return values and block-level detours stay with the Phase 3c instrumentation
path. The probe is *single-threaded*: `tid` defaults to the session's main
thread and calls on other threads are not recorded. Slots are shared with
`MemoryWatch`, so a process supports at most four armed hardware breakpoints.

A hardware breakpoint armed while the target still sits on its initial loader
breakpoint never fires (measured; §9.1). Arm it at a normal stop instead, for
example after `tests.helpers.stop_at()` or `Debugger.run_until()`:

    probe = FunctionProbe(dbg, add_numbers_addr, params=2, max_calls=3)
    probe.arm()                  # target paused at a normal stop
    dbg.continue_event(pid, tid)  # release the pending stop
    summary = probe.run()
    probe.disarm()
"""

import struct
import time
from dataclasses import dataclass

from ..constants import EXCEPTION_SINGLE_STEP, STATUS_WX86_SINGLE_STEP
from ..exceptions import BreakpointError, PydbgError
from . import _shared
from .bbl import (
    STOP_MAX_EVENTS, STOP_NO_MODULE, STOP_NO_TARGET, TRUNCATED_REASONS,
)
from .format import API, TraceEvent

# A single-step stop, including the WOW64 status code a 32-bit target under a
# 64-bit debugger reports (the pair the debugger's own dispatch checks).
_SINGLE_STEP_CODES = frozenset((EXCEPTION_SINGLE_STEP, STATUS_WX86_SINGLE_STEP))

# The x64 integer-argument registers, in ABI order. The x86 path reads stack
# slots instead; both are limited to four because that is what Windows x64
# passes in registers.
_ARG_REGS_X64 = ("rcx", "rdx", "r8", "r9")
_MAX_PARAMS = len(_ARG_REGS_X64)

# One warning may repeat for every call; the summary carries it once.
_RETURN_ADDRESS_OUTSIDE_MODULE = "return address outside module"


@dataclass(frozen=True)
class ProbeCall:
    """One observed call to the probed function.

    'tid' is the thread that called it, 'rva' the return address relative to
    the module base (0 when the return address was outside the module, with a
    warning on the summary), 'args' the first 'params' int arguments as their
    low 32 bits, and 'ts' a `time.perf_counter_ns()` reading taken when the
    call was observed.
    """

    tid: int
    rva: int
    args: tuple
    ts: int


@dataclass(frozen=True)
class ProbeSummary:
    """What one `FunctionProbe.run()` observed, and why it stopped.

    'reason' is one of the STOP_* constants; 'warnings' names anything that
    made a recorded call less complete (for example a return address that was
    not inside the module). 'single_step_pending' is True when the run stopped
    on a debug event it did not continue — the caller owns that event and must
    continue it before running the target again.

    'truncated' is not stored: it is derived from 'reason', so a summary cannot
    claim to be complete while its reason says a budget stopped it.
    """

    calls: tuple
    reason: str | None
    elapsed_ns: int
    warnings: tuple[str, ...] = ()
    single_step_pending: bool = False

    @property
    def truncated(self):
        """True when a budget stopped the run, not the target."""
        return self.reason in TRUNCATED_REASONS


class FunctionProbe:
    """Record the calls to one function in a live process.

    Usage (arm while the target is paused at a normal stop):

        probe = FunctionProbe(dbg, addr, params=2)
        probe.arm()
        dbg.continue_event(pid, tid)
        summary = probe.run()
        probe.disarm()

    `run()` arms when `arm()` was not called, so a caller that already resumed
    the target can still use it — that order is racy for the same reason the
    bbl tracer documents, and should be avoided.

    `run()` deliberately does not disarm: the same probe can be run again after
    a budget stop, and the caller owns that decision. `disarm()` only removes
    the breakpoint this probe armed; another probe or watch in the same slot is
    never touched.
    """

    def __init__(self, dbg, addr, params=0, module=None, max_calls=10_000,
                 tid=None, sink=None):
        """Bind a probe to one function entry.

        Args:
            dbg: A `Debugger` with a target created or attached.
            addr: Absolute address of the function's entry.
            params: How many int arguments to read; 0-4, because Windows x64
                passes only four in registers.
            module: A module dict from `dbg.enum_modules()`, a
                `(base_address, size)` tuple naming any region, or None for the
                process's main module (the first one). Its base and size turn
                the return address into an RVA.
            max_calls: Stop the run after this many calls; 0 stops on the first
                hit and records nothing.
            tid: The thread to probe. None means the session's main thread —
                this probe does not aggregate threads.
            sink: Callable taking each `TraceEvent`; None counts without
                storing.

        Raises:
            ValueError: 'params' is not in 0-4.
        """
        if not 0 <= params <= _MAX_PARAMS:
            raise ValueError(
                f"params must be an integer in 0-4, got {params!r}")
        self.dbg = dbg
        self.addr = addr
        self.params = params
        self.module = module
        self.max_calls = max_calls
        self.sink = sink
        # Resolve the thread once: "the session's main thread" is what the
        # caller asked for, and a later session change must not move the probe.
        self._tid = tid if tid is not None else dbg._session.tid
        # Debug-register slot and breakpoint id filled by arm(); the bp id is
        # also the API event's hook id.
        self._slot = None
        self._bp_id = None
        # Thread handle for the probed thread, opened by arm() and closed by
        # disarm(). The register helpers take a thread id or a handle, but a
        # *tid* makes them enumerate the process's threads to tell the two
        # apart — measured at ~36 ms per context access here, which would make
        # a 20 ms-call target spend 150 ms per recorded call. The handle is
        # opened once and reused; it is closed even when removal fails.
        self._h_thread = None
        self._base = 0
        self._size = 0
        self._calls = []
        self._reason = None
        self._warnings = []
        # True between a hit's TF-setting step and the single-step event that
        # completes it; the slot address must be restored on that event.
        self._step_pending = False
        # True when the run ended on an uncontinued debug event.
        self._uncontinued = False
        _shared.attach_tracer(dbg, self)

    @property
    def hook_id(self):
        """The breakpoint id, which is also the API event's hook id.

        None before `arm()` — an id that has not been assigned cannot be
        reported as one.
        """
        return self._bp_id

    # ── arming ─────────────────────────────────────────────────

    def arm(self):
        """Take a free debug-register slot and arm the entry; return its id.

        Slots 0-3 are shared with every hardware breakpoint in the process
        (`MemoryWatch` included). A slot already in use is skipped; when all
        four are taken, the answer is a `BreakpointError` naming that, not a
        silent reuse that would clobber somebody else's watch.

        Arming twice returns the id already armed and writes nothing.

        Raises:
            BreakpointError: every slot is in use, there is no target thread,
                or the thread's debug registers cannot be written.
        """
        if self._bp_id is not None:
            return self._bp_id
        if self._tid is None:
            raise BreakpointError(
                "no target thread to probe (tid is None)")

        try:
            h_thread = self.dbg.open_thread(self._tid)
        except (PydbgError, OSError) as exc:
            raise BreakpointError(
                f"cannot open thread {self._tid} to probe: {exc}")

        try:
            self._bp_id, self._slot = _shared.arm_free_slot(
                self.dbg, self.addr, "x", 1, self._tid)
        except BaseException:
            self._close_thread(h_thread)
            raise
        self._h_thread = h_thread
        return self._bp_id

    def _close_thread(self, h_thread):
        """Close a thread handle, ignoring a failure to close a dead one."""
        if h_thread is None:
            return
        try:
            self.dbg.close_handle(h_thread)
        except (PydbgError, OSError):
            pass

    def disarm(self):
        """Remove the breakpoint this probe armed; return cleanup warnings.

        Idempotent: the second call owns nothing and reports nothing.

        A failed removal is not assumed harmless. The target having exited is
        reported once as "target exited during cleanup" — its debug registers
        are gone with it; a live target whose slot could not be cleared is
        reported as "breakpoint left", the same vocabulary `BblTracer.disarm()`
        uses.
        """
        bp_id = self._bp_id
        h_thread = self._h_thread
        self._bp_id = None
        self._slot = None
        self._h_thread = None
        self._step_pending = False
        if bp_id is None:
            self._close_thread(h_thread)
            return ()

        try:
            # This probe reports a failed removal but does not re-check a
            # non-raising one; recheck_removed=False keeps that exact contract.
            return _shared.remove_breakpoints(
                self.dbg, ((self.addr, bp_id),), recheck_removed=False)
        finally:
            self._close_thread(h_thread)

    def teardown(self):
        """Undo the probe as one manager-contract step (ADR-0004).

        `Debugger.close()` calls it through the `traces` registry. It is
        `disarm()` under the name close() looks for: the same slot removal,
        the same warnings, and the same idempotence.

        Returns:
            tuple[str, ...]: cleanup warnings ("breakpoint left",
            "target exited during cleanup"), empty when the slot came back.
        """
        return tuple(self.disarm())

    def discard(self):
        """Forget the armed slot without touching the target (it is gone).

        For `Debugger.terminate_process()`: the debug registers died with the
        process, so there is no write to attempt, but the thread handle this
        probe opened still belongs to this process and is closed here.
        """
        h_thread = self._h_thread
        self._bp_id = None
        self._slot = None
        self._h_thread = None
        self._step_pending = False
        self._close_thread(h_thread)
        self._reset()

    # ── running ────────────────────────────────────────────────

    def run(self, max_idle_timeouts=3):
        """Arm if needed, run the target, record hits, and report a summary.

        The target must already be past a normal stop (a hardware breakpoint
        armed at the initial loader stop never fires). The caller has usually
        resumed the target with `continue_event()` just before this call.

        A run stopped by `max_calls` leaves the debug event uncontinued and
        `single_step_pending` True: the caller owns that event and must
        continue it (or terminate the target) before doing anything else.

        `run()` does not disarm; call `disarm()` when the probe is done.

        Args:
            max_idle_timeouts: Consecutive empty WaitForDebugEvent waits
                tolerated before the debugger gives up, as for `BblTracer.run`.
                A timeout stops the run with STOP_IDLE_TIMEOUT.
        """
        started = time.perf_counter_ns()
        self._reset()

        if self.dbg._session.pid is None or self._tid is None:
            self._reason = STOP_NO_TARGET
        else:
            region = self._resolve_module()
            if region is None:
                self._reason = STOP_NO_MODULE
            else:
                self._base, self._size = region
                if self._bp_id is None:
                    self.arm()
                reason = _shared.run_target(
                    self.dbg, self._on_event, max_idle_timeouts)
                if reason is not None:
                    self._reason = reason

        return ProbeSummary(
            calls=tuple(self._calls),
            reason=self._reason,
            elapsed_ns=time.perf_counter_ns() - started,
            warnings=tuple(self._warnings),
            single_step_pending=_shared.single_step_pending(
                self.dbg, self._uncontinued),
        )

    def _reset(self):
        """Forget the previous run's calls, reason and warnings.

        The slot, its armed state and `_step_pending` are intentionally kept:
        a second run continues the same hardware breakpoint, and a pending
        step that was not completed is still owed to the same slot.
        """
        self._calls = []
        self._reason = None
        self._warnings = []
        self._uncontinued = False

    # ── module ─────────────────────────────────────────────────

    def _resolve_module(self):
        """(base, size) of the probed module, or None when either is unknown.

        A region with no size cannot turn a return address into an RVA, so the
        honest answer is STOP_NO_MODULE rather than an RVA against a guessed
        window.
        """
        module = _shared.find_module(self.dbg, self.module)
        if module is None:
            return None
        try:
            base, size = _shared.module_region(module)
        except (TypeError, ValueError):
            return None
        if not base:
            return None
        size = _shared.module_size(self.dbg, module) if not size else size
        if not size:
            return None
        return base, size

    # ── the hit / step-over dance ──────────────────────────────

    def _on_event(self, event):
        """Record a call on a hit, and restore the slot on its single-step.

        A hardware execute breakpoint reports as a single-step exception with
        the slot's bit set in dr6, and the instruction pointer still on the
        probed address: the instruction has *not* executed yet. The step that
        follows the hit is a second single-step event with dr6's low bits
        clear, and is where the slot address has to be put back.
        """
        if event.type != 'EXCEPTION':
            return None
        if event.exception_code not in _SINGLE_STEP_CODES:
            return None
        if self._slot is None:
            return None

        regs = self._get_context()
        fired = (regs.get('dr6', 0) >> self._slot) & 1
        if not fired:
            if self._step_pending:
                self._finish_step(regs)
            return None
        return self._record_hit(event, regs)

    def _record_hit(self, event, regs):
        """Record one call, then either step over it or stop at the budget."""
        if len(self._calls) >= self.max_calls:
            self._stop_at_budget()
            return False

        rva = self._return_rva(regs)
        ts = time.perf_counter_ns()
        self._calls.append(ProbeCall(
            tid=event.tid, rva=rva, args=self._read_args(regs), ts=ts))
        if self.sink is not None:
            self.sink(TraceEvent(kind=API, tid=event.tid, rva=rva, ts=ts,
                                 a=self._bp_id))

        if len(self._calls) >= self.max_calls:
            self._stop_at_budget()
            return False

        self._begin_step(regs)
        return None

    def _begin_step(self, regs):
        """Disable the slot address for this thread and set TF to step over.

        The address must be cleared first: an execute breakpoint left armed on
        the instruction would fire again when the single-step retires it.
        """
        self._set_context({
            f'dr{self._slot}': 0,
            'dr6': 0,
            'eflags': regs.get('eflags', 0) | 0x100,
        })
        self._step_pending = True

    def _finish_step(self, regs):
        """Restore the slot address and its dr7 enable bit after the step.

        The step-over retires the address from the debug registers, so this is
        the only place a later hit becomes possible again.
        """
        self._set_context({
            f'dr{self._slot}': self.addr,
            'dr7': regs.get('dr7', 0) | (1 << (2 * self._slot)),
            'dr6': 0,
        })
        self._step_pending = False

    def _stop_at_budget(self):
        """Clear the slot address, leave TF alone, and stop on this event.

        TF is deliberately not set: the target has not been single-stepped, so
        the caller may simply continue the event and the instruction executes
        normally. The hit count is checked before recording, so max_calls=0
        records nothing and this is still where it stops.
        """
        self._set_context({f'dr{self._slot}': 0, 'dr6': 0})
        self._reason = STOP_MAX_EVENTS
        self._uncontinued = True

    # ── reading the call ───────────────────────────────────────

    def _get_context(self):
        """The probed thread's context, through the handle arm() opened.

        Deliberately the capability object rather than `dbg.get_registers(tid)`:
        the facade's register helpers accept a tid by enumerating the process's
        threads to tell it apart from a handle (~36 ms measured per call), and
        the probed target calls its function every 20 ms. The README allows
        capability objects by attribute; ADR-0002's facade rule is about the
        public debugger surface, not about a component holding a handle it
        opened. See docs/KNOWN_ISSUES.md §追踪.
        """
        return self.dbg.thread.get_context(self._h_thread)

    def _set_context(self, context):
        """Write registers on the probed thread through the same handle."""
        return self.dbg.thread.set_context(self._h_thread, context)

    def _machine(self):
        """32 or 64 for the probed thread's process."""
        return self.dbg._session.arch_for_tid(self._tid)

    def _return_rva(self, regs):
        """The caller's RVA, or 0 (plus a warning) when it is outside."""
        if self._machine() == 32:
            raw = self.dbg.read_memory(regs.get('esp', 0), 4)
            ret = struct.unpack('<I', raw)[0]
        else:
            raw = self.dbg.read_memory(regs.get('rsp', 0), 8)
            ret = struct.unpack('<Q', raw)[0]

        if _shared.in_module(ret, self._base, self._size):
            return ret - self._base
        self._warn(_RETURN_ADDRESS_OUTSIDE_MODULE)
        return 0

    def _read_args(self, regs):
        """The first 'params' int arguments, as their low 32 bits."""
        if not self.params:
            return ()
        if self._machine() == 32:
            raw = self.dbg.read_memory(regs.get('esp', 0) + 4, 4 * self.params)
            return tuple(
                struct.unpack_from('<I', raw, 4 * i)[0]
                for i in range(self.params))
        return tuple(regs.get(name, 0) & 0xFFFFFFFF
                     for name in _ARG_REGS_X64[:self.params])

    def _warn(self, message):
        """Record a warning once, however many calls it applies to."""
        if message not in self._warnings:
            self._warnings.append(message)
