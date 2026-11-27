"""Shared helpers for live-process integration tests (unittest-compatible)."""

import os
import struct
import time

from pydbg import Debugger, _pydbg
from pydbg.exceptions import MemError
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


def _basename(path):
    return (path or "").split("\\")[-1].split("/")[-1].lower()


def module_base(dbg, image=None):
    """Base address of the target's own image, not a system DLL.

    `enum_modules()` is ordered by load, and "the exe is entry 0" is not a
    promise: at the loader breakpoint the list can arrive in another order (or
    only partly filled from the event fallback), and picking [0] then produced a
    base that was not the image the test meant — measured as an intermittent CI
    failure where the strict read below raised ERROR_PARTIAL_COPY. Match the
    image by name when it is known, otherwise take the first module that is not
    under %SystemRoot% (the debugged exe is the only such image in these tests),
    and fall back to the first entry only when nothing else fits.
    """
    modules = dbg.enum_modules()
    if not modules:
        raise AssertionError("no modules enumerated for the target")
    wanted = _basename(image or TEST_TARGET_PATH)
    for module in modules:
        if _basename(module.get("name")) == wanted:
            return module["base_address"]
    system_root = os.environ.get("SystemRoot", r"C:\Windows").lower()
    for module in modules:
        name = (module.get("name") or "").lower()
        if name and not name.startswith(system_root):
            return module["base_address"]
    return modules[0]["base_address"]


def export_address(dbg, path, name):
    """Absolute address of an export of the target's main module.

    The base is the module whose name matches `path` (see `module_base`, which
    stopped assuming the first entry is the target image); `path` is the PE on
    disk whose export table names the RVA. One implementation, because three
    tests had drifted copies of it.
    """
    from pydbg.pe import PE

    base = module_base(dbg, path)
    for export in PE.from_file(path).exports:
        if export.name == name:
            return base + export.rva
    raise AssertionError(f"export {name} not found in {path}")


def entry_point(dbg, attempts=40, image=None):
    """Absolute address of the target PE entry point — a guaranteed-executed
    code address (reliable breakpoint/hook target).

    `image` names the module to match when the debuggee is not the default
    target (a 32-bit target, say); it is passed through to `module_base`.

    `create_debugger()` returns at the FIRST debug event, which on Windows is
    the loader's breakpoint — before the target image is necessarily mapped and
    readable. Reading the headers there is therefore a race, not a fact: CI hit
    it as an intermittent ERROR_PARTIAL_COPY. Wait for the image to become
    readable instead of assuming it is.
    """
    last = None
    for _ in range(attempts):
        try:
            base = module_base(dbg, image)
            dos = dbg.read_memory(base, 0x40)
            if dos[:2] != b"MZ":
                raise AssertionError(f"no MZ signature at 0x{base:X}")
            e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
            ntheaders = dbg.read_memory(base + e_lfanew, 4 + 20 + 16 + 4)
        except (AssertionError, MemError) as exc:
            # Not mapped (or not enumerated) yet; the loader is still working.
            last = exc
            time.sleep(0.05)
            continue
        # AddressOfEntryPoint sits at offset 16 within the optional header,
        # for both PE32 (0x10B) and PE32+ (0x20B).
        entry_rva = struct.unpack_from("<I", ntheaders, 4 + 20 + 16)[0]
        return base + entry_rva
    raise AssertionError(
        f"target image was not readable after {attempts} attempts: {last}")


def alloc_writable(dbg, size=0x1000):
    """Allocate PAGE_EXECUTE_READWRITE memory in the target. Returns base or 0."""
    try:
        result = _pydbg.virtual_alloc(dbg._session.process_handle, size, 0x3000, 0x40)
        return result.get("base_address", 0)
    except OSError:
        return 0
