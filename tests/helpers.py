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
