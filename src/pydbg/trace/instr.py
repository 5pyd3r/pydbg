"""InstructionTracer — record a single-thread instruction window with the TF.

A block tracer stops once per basic block; this one stops once per *instruction*,
which is the only way to see what happened inside a block — a decoder that
found a boundary in the wrong place, a call that never returns, a branch the
static CFG did not know. The window is deliberately small and single-threaded
(default: 10,000 instructions, one thread): a whole-run instruction trace needs
a code cache or static rewriting, and that is a DBI engine, which Phase 3b does
not build (docs/analysis-coverage.md §9.1).

The mechanism is the x86 trap flag, not breakpoints. Before each continue the
tracer reads RIP as the `cursor` and sets TF; the CPU executes exactly one
instruction and raises EXCEPTION_SINGLE_STEP, whose ExceptionAddress is the
*next* instruction. That header is the whole reason `executed = cursor`: the
event does not name the instruction that ran, only where control went. TF is
cleared when the exception is delivered, so it has to be set again on every
step — setting it once traces one instruction.

A window that begins at an address needs `run_until()` first, which leaves the
breakpoint's own single-step pending. That step is completed here (continue,
wait, `handle_ss_manual`) before the window starts, and the instruction it ran
is recorded as the first event; otherwise the first INSTR would belong to the
instruction *after* `start`, silently off by one. Hardware/instruction stepping
only works after the loader breakpoint has been continued, so the caller must
release that event (or use a normal stop point) before asking for a window.

Honest stops: a window that leaves the module, hits a caller's breakpoint or
meets an exception ends with that `reason` in the summary, and the target is
left paused on the uncontinued debug event (the caller owns it). Nothing here
records instructions that did not execute to fill a gap.
"""

import time

from ..constants import (
    EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP, STATUS_WX86_BREAKPOINT,
    STATUS_WX86_SINGLE_STEP,
)
from ..disasm import DisasmEngine
from ..exceptions import (
    PydbgError, ThreadError, TimeoutError as PydbgTimeoutError,
)
from . import _shared
from .bbl import (
    STOP_MAX_EVENTS, STOP_NO_MODULE, STOP_NO_TARGET, STOP_TARGET_EXITED,
    TraceSummary,
)
from .format import INSTR, TraceEvent

# Why a single-step window stopped. The first two are budgets (shared with the
# block tracer); the rest are rules — a trace that ended because the window
# moved somewhere it cannot describe, not because it was cut short. The
# no-module/no-target reasons are shared with every tracer and live in bbl.
STOP_LEFT_MODULE = "left_module"
STOP_BREAKPOINT = "breakpoint"
STOP_EXCEPTION = "exception"

# Native and WOW64 status codes. A 32-bit target under a 64-bit debugger reports
# the WOW64 pair, and recognising only the native one means the tracer waits
# for an event that already arrived.
_SINGLE_STEP_CODES = frozenset(
    (EXCEPTION_SINGLE_STEP, STATUS_WX86_SINGLE_STEP))
_BREAKPOINT_CODES = frozenset(
    (EXCEPTION_BREAKPOINT, STATUS_WX86_BREAKPOINT))

# The trap flag in EFLAGS.
_TRAP_FLAG = 0x100

# x86 instructions are at most 15 bytes; reading 16 lets capstone decode the
# longest one from a single read.
_DECODE_BYTES = 16

# How many debug events may pass while finishing a breakpoint's single-step
# before the wait is called wedged. One is the normal number; the rest cover
# loader bookkeeping and other threads' events.
_STEP_EVENT_BUDGET = 16

# WaitForDebugEvent timeout while finishing that single step. The event is
# already on its way (the thread was just resumed), so this is a wedge guard,
# not a performance budget.
_STEP_WAIT_MS = 10_000

_UNDECODABLE = "undecodable instruction"

# A defensive warning when a recorded cursor is outside the named window. The
# pre-drive checks should make this unreachable; if it ever fires, the trace
# says so instead of silently producing an out-of-window rva.
_OUTSIDE_MODULE = "instruction outside module"


class InstructionTracer:
    """Record up to `max_instructions` of one thread's instructions, live.

    Usage (the target must have passed its loader breakpoint):

        tracer = InstructionTracer(dbg)
        summary = tracer.run(start=add_numbers)

    `start` is an absolute address; when it is None the window begins at the
    instruction after the target's current stop, which counts as already
    executed and is not recorded. Either way the target is left paused on a
    debug event, and `summary.single_step_pending` says the caller owns it.

    A budget of zero records nothing and does not drive the target at all.
    """

    def __init__(self, dbg, module=None, max_instructions=10_000, sink=None):
        """Bind the tracer to a debugger and a module window.

        Args:
            dbg: A `Debugger` with a target created or attached.
            module: A module dict from `dbg.enum_modules()`, a
                `(base_address, size)` tuple naming any region, or None for the
                process's main module (the first one).
            max_instructions: Stop after this many INSTR events. Zero records
                nothing and is reported as a truncated stop.
            sink: Callable taking each `TraceEvent`; None counts without
                storing.
        """
        self.dbg = dbg
        self.module = module
        self.max_instructions = max_instructions
        self.sink = sink
        self._base = None
        self._size = None
        self._tid = None
        self._cursor = None
        self._events = 0
        self._reason = None
        self._warnings = []
        self._uncontinued = False
        self._engine_cache = None
        # Thread handle opened once per run(); see `run()` for why.
        self._h_thread = None
        _shared.attach_tracer(dbg, self)

    # ── module resolution ──────────────────────────────────────

    # ── running ────────────────────────────────────────────────

    def run(self, start=None, max_idle_timeouts=3):
        """Trace instructions from `start` (or the current stop) and return why.

        Args:
            start: Absolute address of the first instruction to record. None
                means the target is already stopped and the window begins with
                the instruction after the stop.
            max_idle_timeouts: Consecutive empty waits tolerated during the
                step loop before the run is reported as STOP_IDLE_TIMEOUT.

        Raises:
            TimeoutError: `run_until()` never reached `start`, or the target
                stopped answering while the breakpoint's single-step was being
                completed. Not swallowed: nothing about the window is known.
            PydbgError: capstone is unavailable, so no length can be decoded.
        """
        started = time.perf_counter_ns()
        self._reset()
        pid, tid = self.dbg._session.pid, self.dbg._session.tid
        if pid is None or tid is None:
            self._reason = STOP_NO_TARGET
            return self._summary(started)

        module = _shared.find_module(self.dbg, self.module)
        if module is None:
            self._reason = STOP_NO_MODULE
            return self._summary(started)
        base, size = _shared.module_region(module)
        size = _shared.module_size(self.dbg, module) if not size else size
        if not base or not size:
            self._reason = STOP_NO_MODULE
            return self._summary(started)
        self._base, self._size, self._tid = base, size, tid

        if self.max_instructions <= 0:
            # The caller asked for no instructions: nothing runs, and the
            # summary says a budget stopped it instead of claiming a clean end.
            self._reason = STOP_MAX_EVENTS
            return self._summary(started)

        if start is not None and not _shared.in_module(start, base, size):
            # Nothing to run to: the requested window is not in this module.
            self._reason = STOP_LEFT_MODULE
            return self._summary(started)

        # One thread handle for the whole run. Reading a context through a *tid*
        # makes the facade enumerate the target's threads on every access
        # (~36 ms measured here); a step loop doing that twice per instruction
        # would spend nearly all its time enumerating. The handle is the
        # capability object the README allows, not a second debugger API.
        h_thread = self.dbg.open_thread(tid)
        self._h_thread = h_thread
        try:
            if start is not None:
                first_length = self._decode_length(start)
                self.dbg.run_until(start, max_idle_timeouts=max_idle_timeouts)
                event = self._finish_pending_step(pid, tid)
                if event is None:
                    return self._summary(started)
                self._record(start, first_length, tid)
                if self._events >= self.max_instructions:
                    self._reason = STOP_MAX_EVENTS
                    self._uncontinued = True
                    return self._summary(started)
                self._cursor = self._current_ip()
                if not _shared.in_module(self._cursor, base, size):
                    # `start` was the window's last instruction: the next one
                    # is outside it. Stop before driving, so no INSTR can be
                    # recorded for an address in another module.
                    self._reason = STOP_LEFT_MODULE
                    self._uncontinued = True
                    return self._summary(started)
            else:
                finished_step = False
                if tid in self.dbg._session.pending_single_step:
                    # The caller stopped on a breakpoint; finish its single step
                    # so the window starts after the instruction stopped on.
                    event = self._finish_pending_step(pid, tid)
                    if event is None:
                        return self._summary(started)
                    finished_step = True
                self._cursor = self._current_ip()
                if not _shared.in_module(self._cursor, base, size):
                    # The current stop is already outside the window: there is
                    # nothing honest to record and no reason to drive.
                    self._reason = STOP_LEFT_MODULE
                    self._uncontinued = finished_step
                    return self._summary(started)

            self._set_tf()
            self.dbg.continue_event(pid, tid)
            reason = _shared.run_target(
                self.dbg, self._on_event, max_idle_timeouts)
            if reason is not None:
                self._reason = reason
            return self._summary(started)
        finally:
            self._close_thread(h_thread)

    def _reset(self):
        self._cursor = None
        self._events = 0
        self._reason = None
        self._warnings = []
        self._uncontinued = False
        self._h_thread = None

    def disarm(self):
        """There is no persistent arm to remove; return ().

        A window writes the trap flag one instruction at a time and the
        single-step event clears it again, and the thread handle is closed in
        `run()`'s finally. Named so all four tracers can be asked the same
        question, not because a stale write can outlive a run.
        """
        return ()

    def teardown(self):
        """Report that the window left nothing armed (ADR-0004).

        `Debugger.close()` calls it through the `traces` registry. Unlike the
        other three tracers, this one owns no INT3 or debug-register slot: the
        trap flag is set and cleared inside `run()` and its thread handle is
        closed there. The method exists so the four tracers share one teardown
        contract, and so a future owned write has an obvious home.
        """
        return tuple(self.disarm())

    def discard(self):
        """Forget the last window without touching the target (it is gone)."""
        self._reset()

    def _summary(self, started):
        """The run's facts, with the pending-stop flag derived, not stored."""
        return TraceSummary(
            events=self._events,
            blocks=0,
            reason=self._reason,
            elapsed_ns=time.perf_counter_ns() - started,
            instructions=self._events,
            warnings=tuple(self._warnings),
            single_step_pending=_shared.single_step_pending(
                self.dbg, self._uncontinued),
        )

    # ── stepping ───────────────────────────────────────────────

    def _on_event(self, event):
        """Record the instruction the cursor named, then set up the next step.

        The event that proves an instruction executed carries the address of the
        *next* one, so the recorded address is `self._cursor`, not the event's.
        Returning False leaves the debug event uncontinued — the target stays
        paused exactly where the window ended, which is what every rule stop
        means.
        """
        if event.type != 'EXCEPTION':
            return None
        code = event.exception_code
        if code not in _SINGLE_STEP_CODES:
            # A breakpoint or a real fault inside the window. Both end it: the
            # trace says where it stopped instead of inventing the rest.
            self._reason = (STOP_BREAKPOINT if code in _BREAKPOINT_CODES
                            else STOP_EXCEPTION)
            self._uncontinued = True
            return False
        if event.tid != self._tid:
            return None

        executed = self._cursor
        if not _shared.in_module(executed, self._base, self._size):
            # Defense in depth: the run's pre-drive checks should have stopped
            # before stepping an out-of-window address. If one slips through,
            # do not record it — an rva outside [0, size) would be a lie.
            self._warn(_OUTSIDE_MODULE)
            self._reason = STOP_LEFT_MODULE
            self._uncontinued = True
            return False
        if self._events >= self.max_instructions:
            self._reason = STOP_MAX_EVENTS
            self._uncontinued = True
            return False

        self._record(executed, self._decode_length(executed), event.tid)
        self._cursor = event.exception_addr

        if not _shared.in_module(self._cursor, self._base, self._size):
            self._reason = STOP_LEFT_MODULE
            self._uncontinued = True
            return False
        if self._events >= self.max_instructions:
            self._reason = STOP_MAX_EVENTS
            self._uncontinued = True
            return False

        # TF was cleared when this exception was delivered, so every step has to
        # set it again; setting it once traces exactly one instruction.
        self._set_tf()
        return None

    def _record(self, address, length, tid):
        """Hand one INSTR to the sink and count it."""
        if self.sink is not None:
            self.sink(TraceEvent(kind=INSTR, tid=tid,
                                 rva=address - self._base,
                                 ts=time.perf_counter_ns(), a=length))
        self._events += 1

    def _decode_length(self, address):
        """Length of the instruction at `address`, or 0 when it cannot be read.

        The failure is reported once as a warning and the step continues with
        `a=0`: an unreadable byte does not disprove that the instruction ran,
        and stopping there would hide the rest of the window. A missing
        capstone is different — `_engine()` raises `PydbgError` before the read,
        so an installation problem is never reported as a bad instruction.
        """
        engine = self._engine()
        try:
            data = self.dbg.read_memory(address, _DECODE_BYTES)
            instructions = engine.disasm(address, data)
        except (PydbgError, OSError, ValueError):
            instructions = []
        if not instructions:
            if _UNDECODABLE not in self._warnings:
                self._warnings.append(_UNDECODABLE)
            return 0
        return instructions[0].size

    def _engine(self):
        """The shared disassembler; decodes in the target's own mode."""
        if self._engine_cache is None:
            engine = DisasmEngine(self.dbg._session)
            engine.mode()       # fail here, once, when capstone is absent
            self._engine_cache = engine
        return self._engine_cache

    def _warn(self, message):
        """Record a warning once, however many steps it applies to."""
        if message not in self._warnings:
            self._warnings.append(message)

    def _current_ip(self):
        """The thread's RIP (or EIP), the address of the next instruction."""
        registers = self.dbg.thread.get_context(self._h_thread)
        address = registers.get('rip') or registers.get('eip')
        if address is None:
            raise ThreadError(
                "no instruction pointer in the thread context; the window "
                "cannot be placed")
        return address

    def _set_tf(self):
        """Arm the trap flag for exactly one instruction."""
        registers = self.dbg.thread.get_context(self._h_thread)
        self.dbg.thread.set_context(
            self._h_thread, {'eflags': registers.get('eflags', 0) | _TRAP_FLAG})

    def _close_thread(self, h_thread):
        """Close the run's thread handle, ignoring a dead thread's refusal."""
        try:
            self.dbg.close_handle(h_thread)
        except (PydbgError, OSError):
            pass

    def _finish_pending_step(self, pid, tid):
        """Complete a breakpoint's single step; leave the target paused on it.

        `run_until()` (and a caller's own manual breakpoint stop) rewinds RIP
        onto the breakpoint and sets TF, leaving one single-step pending. The
        event has to be continued, waited for, and handed to `handle_ss_manual`
        so the breakpoint bookkeeping finishes; the target is then paused on
        that single-step event with RIP past the instruction.

        Returns the single-step event, or None when the window cannot start:
        the target exited, or a different exception arrived first (that reason
        is recorded and the event is left uncontinued for the caller).
        """
        self.dbg.continue_event(pid, tid)
        for _ in range(_STEP_EVENT_BUDGET):
            event = self.dbg.wait_event(_STEP_WAIT_MS)
            if event is None:
                raise PydbgTimeoutError(
                    "no single-step event after continuing a breakpoint; the "
                    "window cannot start")
            if event.type == 'EXIT_PROCESS':
                # The target is gone; continuing this event is how the
                # debugger finishes the exit instead of holding it forever.
                self.dbg.continue_event(event.pid, event.tid)
                self._reason = STOP_TARGET_EXITED
                return None
            if event.type != 'EXCEPTION':
                self.dbg.continue_event(event.pid, event.tid)
                continue
            code = event.exception_code
            if event.tid == tid and code in _SINGLE_STEP_CODES:
                self.dbg.handle_ss_manual(tid)
                return event
            self._reason = (STOP_BREAKPOINT if code in _BREAKPOINT_CODES
                            else STOP_EXCEPTION)
            self._uncontinued = True
            return None
        raise PydbgTimeoutError(
            "no single-step event after continuing a breakpoint; the window "
            "cannot start")
