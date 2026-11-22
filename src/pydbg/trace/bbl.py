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

The target must be paused when `plan()` reads its image, and `run()` must be
called with no debug event still pending — `Debugger.run()` begins by waiting
for the next event, so an event left uncontinued would look like a wedged
target. Starting the process and stopping on its initial breakpoint, then
planning, then continuing that event into `run()` is the flow the tests use.
"""

import time
from dataclasses import dataclass

from ..analysis import analyze_process
from ..analysis.cfg import cfg_of
from ..core.status import ExitReason
from ..exceptions import BreakpointError, PydbgError
from .format import BLOCK, TraceEvent

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
        summary = tracer.run()        # arms, runs the target, removes

    Breakpoints are removed in a `finally`, including when `run()` raises, so a
    failed trace does not leave INT3s behind for the next run to step on.
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
        # VA -> RVA, built in run() because a module can be rebased between
        # planning and arming and the mapping must follow the plan it belongs to.
        self._addresses = {}
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

    # ── running ────────────────────────────────────────────────

    def run(self):
        """Arm a breakpoint per planned block, run the target, record hits.

        Plans first when no plan exists. When there is nothing to trace it
        returns a summary whose `reason` says so instead of pretending an empty
        trace means the target ran nothing.

        Breakpoints are removed on the way out whether the run succeeded or
        raised, and the removal is checked: if any software breakpoint is still
        armed the reason becomes 'breakpoints left', so a failed cleanup is
        visible in the summary rather than only in the target.
        """
        started = time.perf_counter_ns()
        self._reset()

        armed = []
        status = None
        try:
            if not self._blocks:
                self.plan()

            if not self._blocks:
                self._reason = STOP_NO_BLOCKS
            else:
                self._addresses = {self._base + rva: rva
                                   for rva in self._blocks}
                for address in sorted(self._addresses):
                    armed.append(self.dbg.set_breakpoint(address))
                status = self.dbg.run(self._on_event)
                if (status is not None
                        and status.reason is ExitReason.TARGET_EXITED):
                    self._reason = STOP_TARGET_EXITED
        finally:
            unrestored = self._remove_breakpoints(armed)
            if self.dbg.verify_breakpoints():
                self._reason = 'breakpoints left'
            elif unrestored and not self._target_exited(status):
                # Removal failed while the process is still alive, so its
                # bytes may still hold an INT3 even though the records are
                # gone. That is the same "left behind" the verify check
                # reports — the one case it cannot see, because remove() drops
                # the record before attempting the byte restore.
                self._reason = 'breakpoints left'

        return TraceSummary(
            events=self._events,
            blocks=len(self._seen),
            reason=self._reason,
            elapsed_ns=time.perf_counter_ns() - started,
            warnings=tuple(self._warnings),
            single_step_pending=bool(self.dbg._session.pending_single_step),
        )

    @staticmethod
    def _target_exited(status):
        """Whether run() ended because the process was gone."""
        return status is not None and status.reason is ExitReason.TARGET_EXITED

    def _reset(self):
        self._addresses = {}
        self._events = 0
        self._seen = set()
        self._reason = None
        self._warnings = []

    def _on_event(self, event):
        """Record a BLOCK per breakpoint hit; stop the loop at the budget.

        A hit is any EXCEPTION whose address is one of the planned block
        starts. `Debugger.run()` has already restored the original instruction
        and is about to single-step over it, so the event names a block that
        really began executing. Returning False leaves the target paused, which
        is the debugger's documented stop semantics.
        """
        if event.type != 'EXCEPTION':
            return None

        rva = self._addresses.get(event.exception_addr)
        if rva is None:
            return None

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

    def _remove_breakpoints(self, bp_ids):
        """Remove what run() armed, even when the run raised.

        A removal can fail because the breakpoint is already gone (the target
        overwrote the byte) or because the target has terminated and its memory
        can no longer be written. Neither may mask the run's outcome or stop
        the remaining removals. Returns True when some byte could not be put
        back, so the caller can report it.
        """
        unrestored = False
        for bp_id in bp_ids:
            try:
                self.dbg.remove_breakpoint(bp_id)
            except BreakpointError:
                unrestored = True
        return unrestored
