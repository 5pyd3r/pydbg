"""BblTracer — record the basic blocks a target executed, with INT3s.

The static analyzer already knows where each function's blocks begin. This
module turns that list into software breakpoints, lets the debugger run the
target, and writes one BLOCK event per hit — so "which code ran" becomes a fact
that can be stored, replayed and counted rather than an impression
(docs/analysis-coverage.md §8.3–§8.5).

A breakpoint path, not a DBI engine: every block costs a stop, a byte restore
and a single-step resume, so this is the tracer that works on any Windows
target, not a high-throughput one. That trade is deliberate — it needs nothing
beyond the Win32 debug API the package already has. Events carry the block's
RVA and its instruction count; individual instructions are Phase 3b.

The plan trusts the static decoder's block starts, and that has a known cost: a
start the decoder placed *inside* a real instruction is never fetched as an
instruction, so its INT3 is never delivered and sits in that instruction's
operand until the run ends — a byte the target can observe. The overlap figures
in the analysis report say whether the decode had such drift; filtering to
confident functions would narrow the plan but is not what §8.4 asks for.

The target must be paused when `plan()` reads its image. Arming is separate
from running so the breakpoints can be placed while it is still paused, before
any debug event is continued:

    tracer = BblTracer(dbg)
    tracer.plan()
    tracer.arm()                  # while paused: no arming race
    dbg.continue_event(...)       # release the pending stop
    summary = tracer.run()

`run()` still arms when `arm()` was not called, so a caller that has already
resumed the target can use it; that order is racy, because code that ran
before the breakpoint was written is never seen. A run stopped by a budget
leaves its debug event uncontinued and the target paused —
`summary.single_step_pending` says so, and the caller owns that event.
"""

import time
from dataclasses import dataclass

from ..analysis import analyze_process
from ..analysis.cfg import cfg_of
from ..constants import EXCEPTION_BREAKPOINT, STATUS_WX86_BREAKPOINT
from ..core.status import ExitReason
from ..exceptions import (
    BreakpointError, ProcessError, PydbgError, TimeoutError as PydbgTimeoutError,
)
from .format import BLOCK, TraceEvent

# GetExitCodeProcess answers this while the process is still running.
_STILL_ACTIVE = 259

# A breakpoint stop, including the WOW64 status code a 32-bit target under a
# 64-bit debugger reports (same pair the debugger's own dispatch checks).
_BREAKPOINT_CODES = frozenset((EXCEPTION_BREAKPOINT, STATUS_WX86_BREAKPOINT))

# Why a run stopped. These are exported so callers compare against a name and
# not a string literal that can drift. Two of them mean the trace is partial.
STOP_MAX_EVENTS = "max_events"
STOP_TARGET_EXITED = "target_exited"
STOP_IDLE_TIMEOUT = "idle_timeout"
STOP_NO_BLOCKS = "no traceable blocks"

# The reasons that mean "a budget cut this run short". `TraceSummary.truncated`
# is derived from this set, so it cannot disagree with `reason`.
TRUNCATED_REASONS = frozenset((STOP_MAX_EVENTS, STOP_IDLE_TIMEOUT))


@dataclass(frozen=True)
class TraceSummary:
    """What one `BblTracer.run()` saw, and why it stopped.

    'events' counts BLOCK events recorded; 'blocks' counts the *distinct* block
    starts among them, because a loop can execute one block a thousand times.

    'reason' is the stop reason, one of the STOP_* constants or None when the
    loop ended without setting one. 'truncated' is not stored: it is derived
    from 'reason', so a summary cannot claim to be complete while its reason
    says a budget stopped it.

    'elapsed_ns' is wall time for the whole run, the target's own execution
    included — it is what a caller measures, not the tracer's overhead alone.

    'warnings' names cleanup problems that did not raise, such as a breakpoint
    that could not be taken out or a breakpoint the caller already owned.
    'single_step_pending' is True when the debugger still holds a pending
    single-step for a thread: the caller owns that uncontinued debug event and
    must continue it before running the target again.
    """

    events: int
    blocks: int
    reason: str | None
    elapsed_ns: int
    warnings: tuple[str, ...] = ()
    single_step_pending: bool = False

    @property
    def truncated(self):
        """True when a budget stopped the run, not the target."""
        return self.reason in TRUNCATED_REASONS


class BblTracer:
    """Plan and record block-level execution of one module in a live process.

    Usage (the target should be paused before `plan()` reads its image):

        tracer = BblTracer(dbg)
        tracer.plan()                 # 0 means "not traceable", never a guess
        tracer.arm()                  # still paused: place the INT3s
        dbg.continue_event(...)       # release the pending stop
        summary = tracer.run()        # runs the target, records, removes

    Breakpoints are removed in a `finally`, including when `run()` raises, so a
    failed trace does not leave INT3s behind for the next run to step on.
    Removal and arming are separate public steps so a caller can also arm,
    inspect the target, and disarm without running it at all.
    """

    def __init__(self, dbg, module=None, max_events=100_000, max_blocks=4096,
                 sink=None):
        """Bind the tracer to a debugger.

        Args:
            dbg: A `Debugger` with a target created or attached.
            module: A module dict from `dbg.enum_modules()` to trace, or None
                for the process's main module (the first one).
            max_events: Stop the run after this many BLOCK events.
            max_blocks: Never plan more block starts than this.
            sink: Callable taking each `TraceEvent`; None counts without
                storing (useful to measure cost before choosing a destination).
        """
        self.dbg = dbg
        self.module = module
        self.max_events = max_events
        self.max_blocks = max_blocks
        self.sink = sink
        # Block RVA -> its instruction count, filled by plan(). Sorted so the
        # breakpoint arming order (and any report over it) is stable.
        self._blocks = {}
        self._base = None
        # VA -> RVA, built by arm() so it names the same plan that was armed.
        self._addresses = {}
        # VA -> bp_id for the breakpoints this tracer set. Only these ids are
        # ever removed: a breakpoint the caller already had at a planned
        # address is reused, never owned.
        self._armed_ids = {}
        # Warnings collected by arm() for the current armed state.
        self._arming_warnings = []
        self._events = 0
        self._seen = set()
        self._reason = None
        self._warnings = []

    # ── planning ───────────────────────────────────────────────

    def plan(self):
        """Collect the block starts worth breaking on; 0 means untraceable.

        Reuses the static analysis of the module instead of decoding bytes a
        second time: for every recovered function, `cfg_of` names the blocks
        and the number of instructions each holds. A block that could not be
        decoded, or that is not in an executable section, is skipped rather
        than armed at an address that would never fire.

        Calling it twice answers with the same plan; an empty plan is recomputed
        because a module that was not loaded yet is the normal reason for one.
        """
        if self._blocks:
            return len(self._blocks)

        module = self._find_module()
        if module is None:
            return 0
        base = module.get('base_address') or 0
        if not base:
            return 0

        self._base = base
        module_size = self._module_size(module)
        result = analyze_process(self.dbg._session, base,
                                 module_size=module_size)

        blocks = {}
        for function in result.functions.functions():
            cfg = cfg_of(result, function.rva)
            if cfg is None:
                continue
            for block in cfg.blocks.values():
                if not block.instructions:
                    continue        # undecodable: nothing to count or arm
                if not result.image.is_exec(block.rva):
                    continue        # data, not code
                blocks.setdefault(block.rva, len(block.instructions))
                if len(blocks) >= self.max_blocks:
                    break
            if len(blocks) >= self.max_blocks:
                break

        self._blocks = dict(sorted(blocks.items()))
        return len(self._blocks)

    def _find_module(self):
        """The module to analyze, or None when there is nothing to trace."""
        if self.module is not None:
            return self.module
        if getattr(self.dbg._session, 'pid', None) is None:
            return None         # not attached: no module table to enumerate
        try:
            modules = self.dbg.enum_modules()
        except (PydbgError, OSError, TypeError):
            return None
        return modules[0] if modules else None

    def _module_size(self, module):
        """Byte span of the module: its PE image size, or its mapped region."""
        size = module.get('size')
        if size:
            return size
        base = module.get('base_address')
        try:
            for region in self.dbg.enum_regions():
                if region.get('base_address') == base:
                    return region.get('region_size')
        except (PydbgError, OSError, TypeError):
            return None
        return None

    # ── arming ─────────────────────────────────────────────────

    def arm(self):
        """Place one INT3 per planned block; return how many this tracer owns.

        Call it while the target is paused: a breakpoint written after the
        target has resumed can miss code that already ran, which is the race
        `run()` documents for its no-arm() path.

        An address that already has a breakpoint — software or hardware — is
        left alone. That breakpoint belongs to the caller (or another
        component), so it is neither re-armed nor removed, and the summary
        reports "reused caller breakpoints". Arming twice returns the same
        count and writes nothing the second time.

        If a later set fails, the breakpoints already placed here are removed
        before the exception propagates, so a failed arm does not leave a
        half-armed target behind.
        """
        if self._armed_ids:
            return len(self._armed_ids)
        if not self._blocks:
            self.plan()
        if not self._blocks:
            return 0

        self._arming_warnings = []
        self._addresses = {self._base + rva: rva for rva in self._blocks}
        self._armed_ids = {}
        reused = False
        try:
            for address in sorted(self._addresses):
                if self.dbg.find_breakpoint(address) is not None:
                    reused = True
                    continue
                self._armed_ids[address] = self.dbg.set_breakpoint(address)
        except BaseException:
            self.disarm()
            raise
        if reused:
            self._arming_warnings.append("reused caller breakpoints")
        return len(self._armed_ids)

    def disarm(self):
        """Remove the breakpoints this tracer armed; return cleanup warnings.

        Only ids recorded by arm() are removed; the caller's own breakpoints
        are never touched.

        A failed removal is not assumed harmless. The breakpoint manager drops
        its record before restoring the byte, so the record being gone does
        not prove the byte went back — when the target is still alive that is
        reported as 'breakpoint left'. After the target has exited the byte
        cannot be put back at all: that is reported once as "target exited
        during cleanup", and the remaining removals are abandoned because
        every one would fail the same way. It is deliberately not called
        'breakpoint left', which would name a live target's leftover.

        After the loop every own address is asked for again; a record that
        survived removal is a real leftover. Calling disarm() twice is
        harmless: the second call owns nothing and reports nothing.
        """
        own = self._armed_ids
        self._armed_ids = {}
        self._arming_warnings = []
        if not own:
            return ()

        warnings = []
        leftover_ids = set()
        target_exited = False
        for address, bp_id in own.items():
            try:
                self.dbg.remove_breakpoint(bp_id)
            except (BreakpointError, ProcessError):
                if self._target_exited():
                    warnings.append("target exited during cleanup")
                    target_exited = True
                    break
                leftover_ids.add(address)
                warnings.append("breakpoint left")

        if not target_exited:
            for address in own:
                if address in leftover_ids:
                    continue
                if self.dbg.find_breakpoint(address) is not None:
                    warnings.append("breakpoint left")
                    break
        return tuple(dict.fromkeys(warnings))

    def _target_exited(self):
        """Whether the target is gone, so its bytes can no longer be restored.

        The process handle outlives EXIT_PROCESS so the exit code stays
        readable, which makes GetExitCodeProcess the honest answer: the
        STILL_ACTIVE pseudo-code means it is still there. A failed query means
        the handle is gone too — equally unable to restore a byte.
        """
        try:
            return self.dbg.get_exit_code() != _STILL_ACTIVE
        except (PydbgError, OSError):
            return True

    # ── running ────────────────────────────────────────────────

    def run(self, max_idle_timeouts=3):
        """Arm if needed, run the target, record hits, remove own INT3s.

        The documented sequence is plan() -> arm() -> continue the pending
        debug event -> run(). When arm() was not called this arms here, which
        still works for a caller that has already resumed the target but is
        racy: a breakpoint written after the target has run some code is never
        hit for that code, so the trace silently under-reports it. Prefer
        arm() while the target is paused.

        Plans first when no plan exists. When there is nothing to trace it
        returns a summary whose `reason` is STOP_NO_BLOCKS instead of
        pretending an empty trace means the target ran nothing.

        Args:
            max_idle_timeouts: Consecutive empty WaitForDebugEvent waits
                tolerated before the debugger gives up. Three waits (30 s at
                the default timeout) is long enough for a busy target and
                short enough that an idle or wedged one does not spin forever.
                A timeout stops the trace with reason STOP_IDLE_TIMEOUT and
                `truncated` True, rather than propagating as an error.

        A run stopped by `max_events` (or by an idle timeout) leaves the debug
        event uncontinued and the target paused. The summary says so in
        `single_step_pending`; the caller owns that event and must continue it
        before doing anything else with the target.

        Breakpoints are removed on the way out whether the run succeeded or
        raised. The summary's `warnings` reports cleanup that could not be
        completed, plus "reused caller breakpoints" for breakpoints this
        tracer deliberately did not own.
        """
        started = time.perf_counter_ns()
        self._reset()

        try:
            if not self._blocks:
                self.plan()

            if not self._blocks:
                self._reason = STOP_NO_BLOCKS
            else:
                if not self._armed_ids:
                    self.arm()
                try:
                    status = self.dbg.run(
                        self._on_event,
                        max_idle_timeouts=max_idle_timeouts)
                except PydbgTimeoutError:
                    self._reason = STOP_IDLE_TIMEOUT
                else:
                    if (status is not None
                            and status.reason is ExitReason.TARGET_EXITED):
                        self._reason = STOP_TARGET_EXITED
        finally:
            arming_warnings = list(self._arming_warnings)
            cleanup_warnings = self.disarm()
            self._warnings = list(dict.fromkeys(
                arming_warnings + list(cleanup_warnings)))

        return TraceSummary(
            events=self._events,
            blocks=len(self._seen),
            reason=self._reason,
            elapsed_ns=time.perf_counter_ns() - started,
            warnings=tuple(self._warnings),
            single_step_pending=bool(self.dbg._session.pending_single_step),
        )

    def _reset(self):
        self._events = 0
        self._seen = set()
        self._reason = None
        self._warnings = []

    def _on_event(self, event):
        """Record a BLOCK per breakpoint hit; stop the loop at the budget.

        A hit needs two facts, not one: the exception is a breakpoint (native
        or WOW64) *and* its address is a planned block start. An access
        violation delivered at a block start is not evidence the block ran —
        counting every exception by address would turn a fault into coverage.
        `Debugger.run()` has already restored the original instruction and is
        about to single-step over it, so a real breakpoint hit names a block
        that began executing. Returning False leaves the target paused, which
        is the debugger's documented stop semantics.

        The budget is checked before recording, so `max_events=0` records
        nothing instead of one event that then trips the limit.
        """
        if event.type != 'EXCEPTION':
            return None
        if event.exception_code not in _BREAKPOINT_CODES:
            return None

        rva = self._addresses.get(event.exception_addr)
        if rva is None:
            return None

        if self._events >= self.max_events:
            self._reason = STOP_MAX_EVENTS
            return False

        recorded = TraceEvent(kind=BLOCK, tid=event.tid, rva=rva,
                              ts=time.perf_counter_ns(),
                              a=self._blocks[rva])
        if self.sink is not None:
            self.sink(recorded)
        self._events += 1
        self._seen.add(rva)

        if self._events >= self.max_events:
            self._reason = STOP_MAX_EVENTS
            return False
        return None
