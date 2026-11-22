"""Shared helpers for live-process integration tests (unittest-compatible)."""

import struct

from pydbg import Debugger, _pydbg
from tests import TEST_TARGET_PATH


def create_debugger(target=TEST_TARGET_PATH):
    """Create a Debugger + process, consume events until the initial loader
    breakpoint. Returns (dbg, pid, tid) with the process paused at the loader."""
    dbg = Debugger()
    pid, tid = dbg.create_process(target)
    event = dbg.wait_event(5000)
    if event is not None:
        dbg.continue_event(event.pid, event.tid)
    for _ in range(50):
        event = dbg.wait_event(2000)
        if event is None or event.type == "EXIT_PROCESS":
            break
        if event.type == "EXCEPTION":
            break
        dbg.continue_event(event.pid, event.tid)
    return dbg, pid, tid


def stop_at(dbg, addr, timeout_ms=5000):
    """Run to addr with a temporary breakpoint, then finish its single-step.

    Leaves the target paused on the single-step debug event, with no pending
    breakpoint single-step. The caller resumes it with continue_event().
    """
    dbg.run_until(addr, max_wait_ms=timeout_ms, max_idle_timeouts=3)
    pid, tid = dbg._session.pid, dbg._session.tid
    dbg.continue_event(pid, tid)
    event = dbg.wait_event(timeout_ms)
    if event is None or not dbg.handle_ss_manual(tid):
        raise AssertionError("expected the temporary breakpoint's single-step")
    return event


def teardown(dbg):
    """Robust teardown: terminate, drain events, close handles. Never raises."""
    try:
        dbg.terminate_process(0)
    except Exception:
        pass
    for name in ("process_handle", "thread_handle"):
        h = getattr(dbg._session, name, None)
        if h:
            try:
                dbg.close_handle(h)
            except Exception:
                pass


def module_base(dbg):
    """Base address of the target's first loaded module (the exe itself)."""
    return dbg.enum_modules()[0]["base_address"]


def export_address(dbg, path, name):
    """Absolute address of an export of the target's main module.

    The base is the first module `dbg` reports, which is the image both the
    instrument and the probe targets start from; `path` is the PE on disk whose
    export table names the RVA. One implementation, because three tests had
    drifted copies of it.
    """
    from pydbg.pe import PE

    base = module_base(dbg)
    for export in PE.from_file(path).exports:
        if export.name == name:
            return base + export.rva
    raise AssertionError(f"export {name} not found in {path}")


def entry_point(dbg):
    """Absolute address of the target PE entry point — a guaranteed-executed
    code address (reliable breakpoint/hook target)."""
    base = module_base(dbg)
    dos = dbg.read_memory(base, 0x40)
    e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
    ntheaders = dbg.read_memory(base + e_lfanew, 4 + 20 + 16 + 4)
    # AddressOfEntryPoint sits at offset 16 within the optional header,
    # for both PE32 (0x10B) and PE32+ (0x20B).
    entry_rva = struct.unpack_from("<I", ntheaders, 4 + 20 + 16)[0]
    return base + entry_rva


def alloc_writable(dbg, size=0x1000):
    """Allocate PAGE_EXECUTE_READWRITE memory in the target. Returns base or 0."""
    try:
        result = _pydbg.virtual_alloc(dbg._session.process_handle, size, 0x3000, 0x40)
        return result.get("base_address", 0)
    except OSError:
        return 0
