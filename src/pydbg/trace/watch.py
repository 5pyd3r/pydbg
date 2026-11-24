"""MemoryWatch — record writes to one memory range with a hardware breakpoint.

A hardware data breakpoint is the only write watch a plain Win32 debugger can
offer, and it is per-thread hardware: up to four debug-register slots, no target
byte touched, no code cache. The range is therefore narrow on purpose — a single
address and 1/2/4/8 bytes at it — because a whole-memory trace would need the
instrumentation path this phase does not have (docs/analysis-coverage.md §9.1).

Two consequences shape the events:

* The CPU reports a data breakpoint *after* the write, as a single-step
  exception whose ExceptionAddress is the **next** instruction. That address is
  not where the write landed, so every MEM_WRITE carries ``rva=0``; the watched
  address is ``a`` and its length is ``b``.
* ``dr6`` says which of the four slots fired (bits 0-3). The bit has to be
  cleared after every hit, or the next single-step cannot be told apart from
  this one. The watch clears it through ``set_registers`` and stops with the
  warning "could not clear dr6" if it cannot.

Only writes are recorded. Windows offers write and read/write conditions, and a
read/write hit does not say which direction was executed, so labelling those
MEM_READ would be a guess; §9.1 refuses to guess. ``MEM_READ`` stays for a later
instrumentation phase.

Hardware breakpoints armed at the initial loader stop are dropped by the next
continue (measured on this machine), so arm the watch at a normal stop — for
example after ``tests.helpers.stop_at(dbg, entry)``:

    stop_at(dbg, add_numbers_addr)     # a normal debug stop
    watch = MemoryWatch(dbg, g_sum, 4)
    watch.arm()                        # take a free slot
    dbg.continue_event(...)            # release the stop
    summary = watch.run()              # needs at least one write
    watch.disarm()                     # run() never disarms

The caller owns the armed state: a watch can span several ``run()`` calls, and a
run stopped by its event budget leaves the current single-step event
uncontinued. ``summary.single_step_pending`` says so, and the caller must
continue that event before resuming the target.
"""

import time

from ..core.status import ExitReason
from ..exceptions import (
    BreakpointError, ProcessError, PydbgError,
    TimeoutError as PydbgTimeoutError,
)
from . import _shared
from .bbl import (
    STOP_IDLE_TIMEOUT, STOP_MAX_EVENTS, STOP_TARGET_EXITED, TraceSummary,
)
from .format import MEM_WRITE, TraceEvent

# A data breakpoint is delivered as a single-step exception, in the native code
# and in the WOW64 status code a 32-bit target under a 64-bit debugger reports.
_SINGLE_STEP_CODES = frozenset((0x80000004, 0x4000001E))

# The only lengths the debug registers encode; 8 is additionally refused by the
# manager on an x86 target.
_LENGTHS = (1, 2, 4, 8)


class MemoryWatch:
    """Watch writes to one address range and record each as a MEM_WRITE.

    Args:
        dbg: A `Debugger` with a live target, paused at a normal stop.
        addr: Absolute address of the watched range.
        length: Number of watched bytes: 1, 2, 4 or 8. Windows requires
            ``addr % length == 0``; both the length and the alignment are
            checked by `arm()`, which raises `BreakpointError` otherwise.
        max_events: Stop the next `run()` after this many recorded writes.
            Checked before recording, so 0 stops on the first hit with no
            events.
        tid: Arm only this thread; None is process-wide (including new threads
            as the debugger replicates process-wide hardware breakpoints).
        sink: Callable taking each `TraceEvent`; None counts without storing.

    Slots 0-3 are shared with every other hardware breakpoint in the process,
    including another `MemoryWatch` or a `FunctionProbe`. `arm()` takes the
    first free slot it can and says "no free debug-register slot" when there is
    none. It never overrides a slot someone else owns.
    """

    def __init__(self, dbg, addr, length=4, max_events=10_000, tid=None,
                 sink=None):
        self.dbg = dbg
        self.addr = addr
        self.length = length
        self.max_events = max_events
        self.tid = tid
        self.sink = sink
        # The bp this watch owns, and the slot its dr6 bit names. Both are
        # cleared by disarm(), so a watch never removes a breakpoint it did
        # not arm.
        self._bp_id = None
        self._slot = None
        self._events = 0
        self._reason = None
        self._warnings = []
        self._uncontinued = False
        # tid -> thread handle opened once per thread and closed by disarm().
        # A tid-based register access makes the facade enumerate threads
        # (~36 ms measured); caching the handle keeps a watch cheap enough to
        # observe a target that writes every 20 ms.
        self._h_threads = {}

    # ── arming ─────────────────────────────────────────────────

    def arm(self):
        """Take a free debug-register slot and arm a write breakpoint.

        Returns the bp id. Arming twice returns the same id instead of taking
        a second slot. The alignment and length rules are checked here rather
        than in the constructor, so an invalid watch can be built and only
        fails when it tries to touch the target.

        Raises:
            BreakpointError: the length is not 1/2/4/8, ``addr`` is not
                aligned to ``length``, all four slots are in use
                ("no free debug-register slot"), or the target refused the
                write (that error is propagated, not mistaken for a busy slot).
        """
        if self._bp_id is not None:
            return self._bp_id
        if self.length not in _LENGTHS:
            raise BreakpointError(
                f"watch length must be 1, 2, 4 or 8 bytes, got {self.length!r}")
        if self.addr % self.length:
            raise BreakpointError(
                f"watch address 0x{self.addr:X} is not aligned to "
                f"{self.length} bytes")

        self._bp_id, self._slot = _shared.arm_free_slot(
            self.dbg, self.addr, "w", self.length, self.tid)
        return self._bp_id

    def disarm(self):
        """Remove only the breakpoint this watch armed; return warnings.

        Calling it twice is harmless: the second call owns nothing. The
        cleanup wording matches `BblTracer.disarm()` — "breakpoint left" when a
        live target may still hold the slot, "target exited during cleanup"
        once its debug registers are gone with it. Every cached thread handle
        is closed here too: the watch may have opened several for a
        process-wide watch, and nothing else owns them.
        """
        own = self._bp_id
        self._bp_id = None
        self._slot = None
        handles = self._h_threads
        self._h_threads = {}
        try:
            if own is None:
                return ()
            try:
                self.dbg.remove_breakpoint(own)
            except (BreakpointError, ProcessError):
                if _shared.target_exited(self.dbg):
                    return ("target exited during cleanup",)
                return ("breakpoint left",)

            # A removal that raised is the only normal failure; if the
            # breakpoint record survived a non-raising removal, that is still a
            # leftover. Ask the public lookups, not the session's dict.
            if self.dbg.find_breakpoint(self.addr) is not None:
                return ("breakpoint left",)
            return ()
        finally:
            for h_thread in handles.values():
                try:
                    self.dbg.close_handle(h_thread)
                except (PydbgError, OSError):
                    pass

    def _thread_handle(self, tid):
        """The thread's handle, opened on first use and cached per tid."""
        h_thread = self._h_threads.get(tid)
        if h_thread is None:
            h_thread = self.dbg.open_thread(tid)
            self._h_threads[tid] = h_thread
        return h_thread

    def _get_context(self, tid):
        """The thread's context, through the cached handle (not by tid)."""
        return self.dbg.thread.get_context(self._thread_handle(tid))

    def _set_context(self, tid, context):
        """Write registers through the cached handle (not by tid)."""
        return self.dbg.thread.set_context(self._thread_handle(tid), context)

    # ── running ────────────────────────────────────────────────

    def run(self, max_idle_timeouts=3):
        """Drive the target until a budget, exit or idle timeout stops it.

        Arms first if `arm()` was not called (the same fallback
        `BblTracer.run()` documents), but never disarms: the caller may run the
        same watch again, and owns the breakpoint until it calls `disarm()`.

        A run stopped by ``max_events`` returns before continuing the current
        single-step event, so the target stays paused and the summary reports
        ``single_step_pending``. Target exit and an idle timeout continue (or
        never had) an event, so they report False.

        Args:
            max_idle_timeouts: Consecutive empty WaitForDebugEvent waits
                tolerated before the run is called idle and stopped with
                STOP_IDLE_TIMEOUT.
        """
        started = time.perf_counter_ns()
        self._reset()
        if self._bp_id is None:
            self.arm()

        try:
            status = self.dbg.run(
                self._on_event, max_idle_timeouts=max_idle_timeouts)
        except PydbgTimeoutError:
            self._reason = STOP_IDLE_TIMEOUT
        else:
            if (status is not None
                    and status.reason is ExitReason.TARGET_EXITED):
                self._reason = STOP_TARGET_EXITED

        return TraceSummary(
            events=self._events,
            blocks=0,
            reason=self._reason,
            elapsed_ns=time.perf_counter_ns() - started,
            warnings=tuple(dict.fromkeys(self._warnings)),
            single_step_pending=_shared.single_step_pending(
                self.dbg, self._uncontinued),
            # A watch is one address, so every recorded hit is a write to
            # self.addr; keeping the address in the summary is what lets a
            # caller name the hit without re-deriving it from the watch.
            mem_writes=((self.addr, self._events),) if self._events else (),
        )

    def _reset(self):
        self._events = 0
        self._reason = None
        self._warnings = []
        self._uncontinued = False

    def _on_event(self, event):
        """Record a hit on our slot; leave every other single-step alone.

        A hardware data breakpoint arrives as a single-step exception. The
        exception code is necessary but not sufficient: only the thread's dr6
        bit for *our* slot proves this watch fired. A single-step belonging to
        a software breakpoint (or another slot) returns None and is left to
        the debugger.

        The budget is checked before recording, so ``max_events=0`` records
        nothing instead of one event that then trips the limit. Either way the
        hit is real: its dr6 bit is cleared before the stop, so the caller's
        next single-step cannot be mistaken for another write.
        """
        if event.type != 'EXCEPTION':
            return None
        if event.exception_code not in _SINGLE_STEP_CODES:
            return None
        if self._slot is None:
            return None

        try:
            dr6 = self._get_context(event.tid).get('dr6', 0)
        except (OSError, PydbgError):
            return None
        if not dr6 & (1 << self._slot):
            return None

        if self._events >= self.max_events:
            self._stop_at_budget(event.tid)
            return False

        recorded = TraceEvent(kind=MEM_WRITE, tid=event.tid, rva=0,
                              ts=time.perf_counter_ns(),
                              a=self.addr, b=self.length)
        if self.sink is not None:
            self.sink(recorded)
        self._events += 1

        # Clear the slot's dr6 bit: it latches, and without this the next
        # single-step could not be told apart from this hit.
        try:
            self._set_context(event.tid, {'dr6': 0})
        except (OSError, PydbgError):
            self._warnings.append("could not clear dr6")
            self._uncontinued = True
            return False
        return None

    def _stop_at_budget(self, tid):
        """Clear the latched slot and stop with the event uncontinued.

        The hit that trips the budget is a real hardware hit, so dr6's slot bit
        is set. Leaving it there would make the caller's next single-step look
        like another write; a failure to clear it is reported with the same
        warning the post-record path uses and the run still stops.
        """
        try:
            self._set_context(tid, {'dr6': 0})
        except (OSError, PydbgError):
            self._warnings.append("could not clear dr6")
        self._reason = STOP_MAX_EVENTS
        self._uncontinued = True
