"""One implementation of the questions every live tracer asks.

`BblTracer`, `InstructionTracer`, `MemoryWatch` and `FunctionProbe` all need the
same few answers — which module is being traced, how big it is, whether the
target is gone, whether the debugger still owes a debug event, which debug
register slot is free. Each had grown its own copy, and the copies had already
started to drift: one recognised a busy slot by matching the exception's text
instead of its type.

This module is the single seam for those questions; the tracers keep their
public behaviour and delegate here.

Importing it stays extension-free (ADR-0001): the busy-slot exception lives
beside the hardware manager, which imports `_pydbg`, so that import happens
inside `arm_free_slot()` — only a caller with a live target can reach it.
"""

from ..exceptions import BreakpointError, PydbgError

# GetExitCodeProcess answers this while the process is still running.
_STILL_ACTIVE = 259


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
