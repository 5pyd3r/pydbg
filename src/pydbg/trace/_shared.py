"""One implementation of the questions every live tracer asks.

`BblTracer`, `InstructionTracer`, `MemoryWatch` and `FunctionProbe` all need the
same few answers — which module is being traced, how big it is, whether the
target is gone, whether the debugger still owes a debug event, which debug
register slot is free. Each had grown its own copy, and the copies had already
started to drift: one recognised a busy slot by matching the exception's text
instead of its type.

This module is the single seam for those questions; the tracers keep their
public behaviour and delegate here.

It also owns the shell every tracer's `run()` shares: the `dbg.run()` call and
the translation of how it ended into a stop reason, the `attach_trace()`
handshake that puts a tracer in its debugger's teardown chain, and the cleanup
warnings a `disarm()` reports. A tracer keeps what it arms, what it records and
what it summarises; only "what a stop reason means" lives here, so that changes
in one place.

Importing it stays extension-free (ADR-0001): the busy-slot exception lives
beside the hardware manager, which imports `_pydbg`, so that import happens
inside `arm_free_slot()` — only a caller with a live target can reach it.
"""

from ..core.status import ExitReason
from ..exceptions import (
    BreakpointError, ProcessError, PydbgError,
    TimeoutError as PydbgTimeoutError,
)

# GetExitCodeProcess answers this while the process is still running.
_STILL_ACTIVE = 259

# Why a run stopped. These are exported so callers compare against a name and
# not a string literal that can drift. Two of them mean the trace is partial.
# They live here, beside the shell that translates them, because every tracer
# can end with one: a change to what a stop reason means has one place to
# change. `pydbg.trace.bbl` re-exports them under their published names.
STOP_MAX_EVENTS = "max_events"
STOP_TARGET_EXITED = "target_exited"
STOP_IDLE_TIMEOUT = "idle_timeout"
STOP_NO_BLOCKS = "no traceable blocks"
STOP_NO_MODULE = "no module"
STOP_NO_TARGET = "no target"

# The reasons that mean "a budget cut this run short". `TraceSummary.truncated`
# and `ProbeSummary.truncated` are derived from this set, so neither can
# disagree with `reason`.
TRUNCATED_REASONS = frozenset((STOP_MAX_EVENTS, STOP_IDLE_TIMEOUT))


def attach_tracer(dbg, tracer):
    """Join `dbg`'s teardown chain when it is a lifecycle owner (ADR-0004).

    A real `Debugger` owns its tracers and disarms them on close(); a fake or
    proxy without `attach_trace()` is simply not a lifecycle owner, and a
    tracer must not require one to be constructed.
    """
    attach = getattr(dbg, "attach_trace", None)
    if callable(attach):
        attach(tracer)


def run_target(dbg, on_event, max_idle_timeouts):
    """Drive the target and name how the run loop ended.

    Every tracer's `run()` makes the same call and the same attribution: a
    timeout is a truncated stop rather than an exception the caller sees, and
    the target exiting is named so the summary says why nothing can be
    restored afterwards.

    Returns:
        A STOP_* constant for the outcomes this shell owns, or None when the
        debugger stopped for a reason the tracer recorded itself (its callback
        asked to stop) — a None must not overwrite that reason.
    """
    try:
        status = dbg.run(on_event, max_idle_timeouts=max_idle_timeouts)
    except PydbgTimeoutError:
        return STOP_IDLE_TIMEOUT
    if status is not None and status.reason is ExitReason.TARGET_EXITED:
        return STOP_TARGET_EXITED
    return None


def remove_breakpoints(dbg, owned):
    """Remove the breakpoints a tracer owns; return the cleanup warnings.

    `owned` is an iterable of (address, bp_id) pairs in the order they were
    armed. A failed removal is not assumed harmless. When the target is gone
    the bytes and debug registers went with it, so that is reported once as
    "target exited during cleanup" and the remaining removals are abandoned —
    every one would fail the same way. A live target's failed removal is
    "breakpoint left".

    A removal that returned without raising is asked for again: a record still
    there after the call that claimed to remove it is a real leftover, not a
    clean removal. The question is asked by breakpoint id, not by address
    alone, because the four debug-register slots can hold the same address
    (four probes of one entry) and another owner's record is not evidence
    that this record survived.

    Returns:
        tuple[str, ...]: the distinct warnings, in encounter order.
    """
    owned = tuple(owned)
    warnings = []
    failed_addresses = set()
    exited = False
    for address, bp_id in owned:
        try:
            dbg.remove_breakpoint(bp_id)
        except (BreakpointError, ProcessError):
            if target_exited(dbg):
                warnings.append("target exited during cleanup")
                exited = True
                break
            failed_addresses.add(address)
            warnings.append("breakpoint left")

    if not exited:
        for address, bp_id in owned:
            if address in failed_addresses:
                continue
            if dbg.find_breakpoint(address) == bp_id:
                warnings.append("breakpoint left")
                break
    return tuple(dict.fromkeys(warnings))


def find_module(dbg, module):
    """The module a tracer was asked for, or None when there is nothing.

    An explicit `module` (dict or `(base, size)` tuple) is returned as given.
    `None` means the process's main module — the first one — and an unattached
    debugger has no module table: `enum_modules()` fails with TypeError when
    there is no process handle, and that is the answer rather than a reason to
    peek at session state first.
    """
    if module is not None:
        return module
    try:
        modules = dbg.enum_modules()
    except (PydbgError, OSError, TypeError):
        return None
    return modules[0] if modules else None


def module_region(module):
    """(base_address, size) for a module dict or a (base, size) tuple."""
    if isinstance(module, dict):
        return module.get('base_address') or 0, module.get('size')
    base, size = module
    return base or 0, size


def module_size(dbg, module):
    """Byte span of the module: its PE image size, or its mapped region."""
    base, size = module_region(module)
    if size:
        return size
    try:
        for region in dbg.enum_regions():
            if region.get('base_address') == base:
                return region.get('region_size')
    except (PydbgError, OSError, TypeError):
        return None
    return None


def target_exited(dbg):
    """Whether the target is gone, so its bytes/registers cannot be restored.

    The process handle outlives EXIT_PROCESS so the exit code stays readable,
    which makes GetExitCodeProcess the honest answer: the STILL_ACTIVE
    pseudo-code means it is still there. A failed query means the handle is
    gone too — equally unable to restore anything.
    """
    try:
        return dbg.get_exit_code() != _STILL_ACTIVE
    except (PydbgError, OSError):
        return True


def arm_free_slot(dbg, addr, condition, length, tid):
    """Arm a hardware breakpoint in the first free debug-register slot.

    Slots 0-3 are shared by every hardware breakpoint in the process. A slot
    the hardware manager reports as busy is skipped; any other breakpoint error
    is the caller's to see (a refused write is not a full house).

    Returns:
        (bp_id, slot): the slot is returned because the data watch and the
        probe need its dr6 bit, and only the manager that took it knows it.
        (The ticket sketched `-> bp_id`; the slot is the same fact the callers
        already had from their own loop, kept rather than re-derived.)

    Raises:
        BreakpointError: every slot is in use ("no free debug-register slot").
    """
    # Lazy: importing the hardware manager loads `_pydbg` (ADR-0001).
    from ..breakpoint.hardware import BreakpointSlotBusy

    for slot in range(4):
        try:
            return dbg.set_hw_breakpoint(
                addr, condition, length, slot, tid), slot
        except BreakpointSlotBusy:
            continue
    raise BreakpointError("no free debug-register slot")


def single_step_pending(dbg, uncontinued=False):
    """Whether the caller owns an uncontinued debug event after this run.

    Two facts answer it: the tracer stopped on an event it did not continue
    (`uncontinued`), or the debugger itself still holds a pending single-step
    for a thread. Every tracer used to derive this separately; the derivation
    lives here so a summary cannot disagree with what the event loop did.
    """
    return bool(uncontinued or dbg._session.pending_single_step)


def in_module(address, base, size):
    """Whether a callback address lies in `[base, base + size)`."""
    return (address is not None and base is not None
            and base <= address < base + size)
