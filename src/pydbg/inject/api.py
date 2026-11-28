"""The extension-backed half of `pydbg.inject`.

Every function here takes a `Debugger` (or anything with the same session
surface: `_session.process_handle`, `_session.pid`, `memory`). Remote memory is
allocated with `VirtualAllocEx` through `dbg.memory`, never freed on success,
and the address comes back in the `InjectionReport`; the caller owns both the
allocation and the thread handle. Failures raise `InjectionError` with the
stage and, when Windows refused a call, the Win32 code, because an injection
that fails at `alloc` and one that fails at `CreateRemoteThread` need different
fixes.

There are two address spaces to keep apart, not one. For a 64-bit target the
`LoadLibraryW` address is resolved in *this* process's kernel32: Windows maps
kernel32 at the same base in every 64-bit process of a session, which is the
same assumption `demo/dll_injector.py` makes. A WOW64 target gets no such
shortcut — its 32-bit code cannot execute a 64-bit address — so `LoadLibraryW`
there is resolved from the target's own 32-bit kernel32, found through the
32-bit module table (`_target_export`). Every remote address a 32-bit target
will dereference is also allocated below 4 GiB (`_alloc`), and an answer from
`VirtualAllocEx` above that is refused rather than truncated. Before the loader
has mapped the 32-bit image, that module table does not exist yet; the resolve
then raises `InjectionError` instead of falling back to the 64-bit answer.
"""

import os
import struct

from .. import _pydbg
from ..analysis.process_source import ProcessSource
from ..exceptions import InjectionError, MemError, PydbgError
from ..pe import PE, LoadedView
from . import InjectionReport

_MEM_COMMIT_RESERVE = 0x3000     # MEM_COMMIT | MEM_RESERVE
_PAGE_READWRITE = 0x04
_PAGE_EXECUTE_READWRITE = 0x40
_THREAD_SET_CONTEXT = 0x0010     # what QueueUserAPC requires
_THREAD_SUSPEND_RESUME = 0x0002  # what SuspendThread/ResumeThread require

_WIN32_INVALID_PARAMETER = 87
_WIN32_FILE_NOT_FOUND = 2
_WIN32_BAD_EXE_FORMAT = 193
_WIN32_PARTIAL_COPY = 299

# A 32-bit target cannot form an address at or above this, so no pointer it will
# dereference — path string, shellcode, APC parameter block — can live there.
_WOW64_LIMIT = 0x1_0000_0000

# Candidate bases for a WOW64 allocation, in the order they are tried. They are
# fixed, 64KB-aligned and below 2GB: "wherever the allocator likes" is not a
# contract a 32-bit target can be held to, and each of these fits a 2GB as well
# as a LARGEADDRESSAWARE 4GB address space. The trailing 0 asks Windows to
# place the block itself once every fixed base is already mapped.
_WOW64_ALLOC_HINTS = (0x10000000, 0x20000000, 0x30000000, 0x40000000,
                      0x50000000, 0x60000000, 0x70000000, 0)

# IMAGE_FILE_HEADER.Machine -> the bitness of a DLL a caller asked to inject.
_MACHINE_ARCH = {0x14C: 32, 0x8664: 64}

# How many export forwarders to follow before giving up. A real chain is one or
# two hops; the bound is what stops a cycle in a forged image from looping.
_MAX_FORWARDER_HOPS = 8


def _win32_code(exc):
    """The Win32/errno code carried by 'exc' or anything it was raised from."""
    seen = 0
    while exc is not None and seen < 8:
        code = getattr(exc, "winerror", None)
        if not code:
            code = getattr(exc, "errno", None)
        if code:
            return int(code)
        exc = exc.__cause__
        seen += 1
    return 0


def _code_detail(code):
    """The code half of an InjectionError message: "win32=N" or its absence."""
    return f"win32={code}" if code else "no Win32 code"


def _fail(stage, message, code=None):
    """Raise InjectionError for 'stage'.

    'code' is the Win32/errno number when Windows made the call and refused
    it. A failure that never reached Windows — a missing target, a DLL of the
    wrong bitness, a bad argument — has no code, and says so instead of
    printing `win32=0`, which reads like a successful call.
    """
    raise InjectionError(
        f"injection {stage} failed ({_code_detail(code)}): {message}")


def _translate(stage, exc):
    """Re-raise a lower-level failure as an InjectionError for 'stage'."""
    raise InjectionError(
        f"injection {stage} failed ({_code_detail(_win32_code(exc))}): "
        f"{exc}") from exc


def _session(dbg):
    """The target session behind 'dbg', or an InjectionError naming the problem."""
    session = getattr(dbg, "_session", None)
    if getattr(session, "process_handle", None) is None:
        _fail("target", "no target process handle; create_process() or "
                        "attach() first")
    if getattr(session, "pid", None) is None:
        _fail("target", "no target pid; create_process() or attach() first")
    return session


def _target_is_wow64(session):
    """True when the target is 32-bit, i.e. WOW64 on this 64-bit host.

    Everything that changes between the two paths hangs off this one question:
    which kernel32 resolves `LoadLibraryW`, and whether the remote addresses a
    target will dereference have to fit in 32 bits.
    """
    return getattr(session, "target_arch", None) == 32


def _alloc(dbg, session, size, protect):
    """Allocate 'size' bytes in the target; a WOW64 base stays below 4 GiB.

    A 64-bit target gets the historical arbitrary-placement allocation. A
    32-bit target cannot form an address at or above 4 GiB, so VirtualAllocEx
    is steered with `_WOW64_ALLOC_HINTS`: a refused hint is an ordinary "that
    base is taken" and the next candidate is tried, but a *successful* answer
    at or above the limit is fatal. Truncating it to 32 bits would make the
    target read from an unrelated address, and retrying would paper over an
    answer that must not have happened — so the block is released and the call
    fails.

    Raises:
        InjectionError: VirtualAllocEx refused every candidate (`alloc`), or
            answered with an address a 32-bit target cannot use; the message
            carries the Win32 code when there is one.
    """
    if not _target_is_wow64(session):
        try:
            return dbg.memory.alloc_remote(size, protect)
        except (MemError, OSError) as exc:
            _translate("alloc", exc)

    last = None
    last_hint = 0
    for hint in _WOW64_ALLOC_HINTS:
        last_hint = hint
        try:
            address = dbg.memory.alloc_remote(size, protect, hint)
        except (MemError, OSError) as exc:
            last = exc
            continue
        if not 0 < address < _WOW64_LIMIT:
            # Release what Windows handed out and then refuse it: the caller
            # never learns this address, so leaving it allocated would leak.
            if address:
                _free_quietly(dbg, address)
            _fail("alloc",
                  f"VirtualAllocEx returned 0x{address:X} for a 32-bit "
                  f"target; it cannot address anything at or above "
                  f"0x{_WOW64_LIMIT:X}, and truncating the answer would point "
                  f"the target at the wrong memory. Refusing it.")
        return address
    _fail("alloc",
          f"VirtualAllocEx refused every candidate base for {size} bytes "
          f"({len(_WOW64_ALLOC_HINTS)} tried, last 0x{last_hint:X}): {last}",
          _win32_code(last))


def _write(dbg, address, data):
    try:
        dbg.memory.write(address, data)
    except (MemError, OSError) as exc:
        _translate("write", exc)


def _free_quietly(dbg, address):
    try:
        dbg.memory.free_remote(address)
    except (MemError, OSError):
        pass


def _create_remote_thread(h_process, start, param=0):
    try:
        return _pydbg.create_remote_thread(h_process, start, param)
    except OSError as exc:
        _translate("thread", exc)


def _close_quietly(handle):
    try:
        _pydbg.close_handle(handle)
    except OSError:
        pass


def _image_arch(path):
    """32 or 64 from the DLL's own PE header; 0 when it is not a usable PE.

    A process loads only images of its own architecture, so the bitness of the
    file is what decides whether injecting it can work at all. Only the machine
    field is needed, which is why this reads the two headers rather than
    parsing the whole image: the answer is two bytes and the caller has not yet
    touched the target.
    """
    try:
        with open(path, "rb") as handle:
            dos = handle.read(0x40)
            if len(dos) < 0x40 or dos[:2] != b"MZ":
                return 0
            e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
            handle.seek(e_lfanew)
            nt = handle.read(6)
    except OSError as exc:
        _fail("path", f"cannot read {path}: {exc}", _win32_code(exc))
    if len(nt) < 6 or nt[:4] != b"PE\x00\x00":
        return 0
    return _MACHINE_ARCH.get(struct.unpack_from("<H", nt, 4)[0], 0)


def _target_module(dbg, module_name):
    """The target's entry for 'module_name' in its 32-bit module table.

    This is also where the loader-breakpoint boundary shows up. Before the
    loader has mapped the 32-bit image, Windows either refuses the table with
    ERROR_PARTIAL_COPY (the window module/resolver.py documents) or answers
    with an empty one; both are surfaced as an InjectionError naming the
    missing table, never as a fallback to a same-bitness address the target
    could not execute.
    """
    try:
        modules = dbg.enum_modules(arch=32)
    except MemError as exc:
        if _win32_code(exc) == _WIN32_PARTIAL_COPY:
            _fail("resolve",
                  "the target's 32-bit module table is not available yet "
                  "(the loader has not mapped the 32-bit image; wait past the "
                  "WX86 loader breakpoint): " + str(exc),
                  _WIN32_PARTIAL_COPY)
        _translate("resolve", exc)
    except PydbgError as exc:
        _translate("resolve", exc)

    wanted = module_name.lower()
    for module in modules:
        if os.path.basename(module.get("name") or "").lower() == wanted:
            return module
    _fail("resolve",
          f"the target has no 32-bit {module_name}: its 32-bit module table "
          f"does not contain one")


def _read_target_image(dbg, module_name):
    """(base, PE) for the target's own 32-bit 'module_name', read in place.

    The bytes come out of the target with `dbg.read_memory` after the module
    table supplied the base and the image's own SizeOfImage. Parsing them with
    LoadedView means an RVA is a direct offset into that buffer, and `va_base`
    anchors the addresses the image stores to where the module really loaded.

    The source is a ProcessSource over `dbg.read_memory`, not one bulk read of
    SizeOfImage: a loaded image legitimately has holes (the loader decommits
    discardable sections such as .reloc after applying them), so reading the
    whole image at once fails with ERROR_PARTIAL_COPY on the first such page —
    measured on a real 32-bit kernel32. ProcessSource asks for the bytes the
    directory walk actually needs and reports an unreadable page as "no data
    here", which is the answer the PE parser is built to stop on.
    """
    module = _target_module(dbg, module_name)
    base = module.get("base_address") or 0
    size = module.get("size") or 0
    if not base or not size:
        _fail("resolve",
              f"the target's {module_name} entry reports no base/size, so its "
              f"image cannot be read")
    source = ProcessSource(
        getattr(dbg, "_session", None), base, size=size, reader=dbg.read_memory)
    try:
        return base, PE.from_source(source, LoadedView(), va_base=base)
    except (ValueError, struct.error) as exc:
        _fail("resolve",
              f"cannot parse the target's {module_name} at 0x{base:X}: {exc}")


def _target_export(dbg, module_name, proc_name):
    """Address of 'proc_name' in the target's own 32-bit 'module_name'.

    The 64-bit host's kernel32 is a different image at a different base, so an
    address resolved here could not be executed by a WOW64 target (spec §13.2).
    The answer therefore has to come from the target's address space: find the
    module in its 32-bit table, read that mapped image, and take the export's
    RVA relative to the module's runtime base.

    A forwarded export is followed into the module it names, because a
    forwarder's RVA points at a name string inside the export directory rather
    than at code; returning it would hand the target a data address to execute.

    Raises:
        InjectionError: the 32-bit module table is missing, either module is
            not loaded, the export is not there, or an image cannot be read or
            parsed (`resolve`); the message names which.
    """
    name = proc_name
    for _ in range(_MAX_FORWARDER_HOPS):
        base, image = _read_target_image(dbg, module_name)
        entry = next(
            (export for export in image.exports if export.name == name), None)
        if entry is None:
            _fail("resolve",
                  f"{module_name} in the target has no export {name!r}")
        if entry.forwarder is None:
            return base + entry.rva
        module_name, _, name = entry.forwarder.partition(".")
        if not name:
            _fail("resolve",
                  f"malformed export forwarder {entry.forwarder!r}")
        if not module_name.lower().endswith(".dll"):
            module_name += ".dll"
    _fail("resolve",
          f"the export forwarders for {proc_name!r} did not terminate within "
          f"{_MAX_FORWARDER_HOPS} hops")


def inject_dll(dbg, path):
    """Inject a DLL into the target with `CreateRemoteThread(LoadLibraryW)`.

    The absolute path is written into a `PAGE_READWRITE` allocation in the
    target and `LoadLibraryW(path)` runs there. The returned report carries the
    remote thread and the allocation; both are the caller's:

    - wait with `_pydbg.wait_for_single_object(report.handle, timeout)` and read
      the thread exit code for the `HMODULE` (`0` means LoadLibrary failed);
    - close the thread handle with `_pydbg.close_handle(report.handle)`;
    - free the path buffer with `dbg.memory.free_remote(report.remote_base)`
      once the thread has finished.

    The function does not wait and does not free: a caller that only wants the
    DLL mapped and not the report can close and free after a successful wait.

    The DLL has to match the target's architecture: a 32-bit DLL goes to a
    WOW64 target (through that target's own 32-bit kernel32) and a 64-bit DLL
    to a 64-bit target (through this process's kernel32, the same-bitness
    assumption in the module docstring). A mismatch is refused before anything
    is allocated or executed.

    Raises:
        InjectionError: the path is unusable (`path`) or is not a PE image
            (`path`), the DLL's architecture does not match the target's
            (`arch`), kernel32/LoadLibraryW cannot be resolved (`resolve`),
            `VirtualAllocEx` refused or answered with a non-32-bit address for
            a WOW64 target (`alloc`), `WriteProcessMemory` refused (`write`),
            or `CreateRemoteThread` refused (`thread`); the message carries the
            Win32 code when there is one.
    """
    if not isinstance(path, (str, os.PathLike)):
        _fail("path", f"not a path: {path!r}", _WIN32_INVALID_PARAMETER)
    try:
        source = os.fspath(path)
    except TypeError:
        _fail("path", f"not a path: {path!r}", _WIN32_INVALID_PARAMETER)
    if not isinstance(source, str) or not source:
        _fail("path", f"not a usable path: {source!r}",
              _WIN32_INVALID_PARAMETER)

    absolute = os.path.abspath(source)
    if not os.path.isfile(absolute):
        _fail("path", f"no such file: {absolute}", _WIN32_FILE_NOT_FOUND)

    session = _session(dbg)
    target_arch = getattr(session, "target_arch", None)
    dll_arch = _image_arch(absolute)
    if not dll_arch:
        _fail("path", f"not a PE image: {absolute}", _WIN32_BAD_EXE_FORMAT)
    if dll_arch != target_arch:
        _fail("arch",
              f"refusing to inject a {dll_arch}-bit DLL into a "
              f"{target_arch}-bit target: a process can only load images of "
              f"its own architecture")

    if dll_arch == 32:
        # The target executes this address in its own 32-bit kernel32.
        load_library = _target_export(dbg, "kernel32.dll", "LoadLibraryW")
    else:
        try:
            kernel32 = _pydbg.get_module_handle("kernel32.dll")
            load_library = _pydbg.get_proc_address(kernel32, "LoadLibraryW")
        except OSError as exc:
            _translate("resolve", exc)

    # LoadLibraryW takes a wide string; the terminating pair is part of the
    # buffer, not of the Python string.
    payload = absolute.encode("utf-16-le") + b"\x00\x00"
    remote = _alloc(dbg, session, len(payload), _PAGE_READWRITE)
    try:
        _write(dbg, remote, payload)
        thread_id, handle = _create_remote_thread(
            session.process_handle, load_library, remote)
    except InjectionError:
        _free_quietly(dbg, remote)
        raise

    return InjectionReport(
        thread_id=thread_id, handle=handle, remote_base=remote)


def inject_shellcode(dbg, code):
    """Run 'code' in a new thread of the target (`CreateRemoteThread` direct).

    The bytes are written into a `PAGE_EXECUTE_READWRITE` allocation, and a new
    remote thread starts at its first byte with a NULL parameter. The returned
    report carries the thread and the allocation; neither is cleaned up:

    - wait with `_pydbg.wait_for_single_object(report.handle, timeout)`;
    - close the thread handle with `_pydbg.close_handle(report.handle)`;
    - free the code buffer with
      `dbg.memory.free_remote(report.remote_base)` once the thread exits.

    On a WOW64 target the code is 32-bit code, and the allocation is made below
    4 GiB so the thread can execute it at all; an allocation answer above that
    is refused (see `_alloc`).

    Raises:
        InjectionError: `code` is empty or not bytes (`code`), the allocation
            failed (`alloc`), the write failed (`write`), or the thread could
            not be created (`thread`); the message carries the Win32 code when
            there is one.
    """
    if not isinstance(code, (bytes, bytearray, memoryview)):
        _fail("code", f"shellcode must be bytes, not {type(code).__name__}",
              _WIN32_INVALID_PARAMETER)
    try:
        payload = bytes(code)
    except (TypeError, ValueError):
        _fail("code", "shellcode is not a bytes-like object",
              _WIN32_INVALID_PARAMETER)
    if not payload:
        _fail("code", "empty shellcode", _WIN32_INVALID_PARAMETER)

    session = _session(dbg)

    remote = _alloc(dbg, session, len(payload), _PAGE_EXECUTE_READWRITE)
    try:
        _write(dbg, remote, payload)
        thread_id, handle = _create_remote_thread(
            session.process_handle, remote)
    except InjectionError:
        _free_quietly(dbg, remote)
        raise

    return InjectionReport(
        thread_id=thread_id, handle=handle, remote_base=remote)


def queue_apc(dbg, thread_id, addr, data=b""):
    """Queue a user-mode APC to 'thread_id' at 'addr'.

    The target thread must enter an **alertable wait** before the APC runs:
    `SleepEx`, `WaitForSingleObjectEx(..., TRUE)`, or
    `MsgWaitForMultipleObjectsEx(..., MWMO_ALERTABLE)`. Queueing does not
    interrupt a non-alertable wait (an ordinary `Sleep`, `WaitForSingleObject`
    or `GetMessage`), so a thread parked the wrong way will simply not run the
    APC until it later waits alertably — or never.

    `addr` is the APC routine's address in the target; it receives `data` as
    its `ULONG_PTR` parameter. An empty `data` passes 0. A non-empty `data` is
    copied into a new `PAGE_READWRITE` allocation in the target and that
    address is what the routine receives.

    On a WOW64 target both `addr` and the parameter block have to be below
    4 GiB: that is the address space the 32-bit thread can form, and a high
    address is refused instead of being handed to it truncated. Note that
    Windows documents `QueueUserAPC` as unsupported across architectures
    ("addresses will be incorrect and the application will crash"): the APC is
    dispatched natively rather than through the 32-bit ntdll, so an address
    below 4 GiB is delivered, but the body there must not assume that the
    32-bit calling convention (a stack argument, `ret n`) is in effect.

    **A non-empty `data` leaks that allocation by design**: the address is
    neither returned nor freed, because the APC routine owns what it receives
    and this function cannot know when the APC ran. A caller that needs to
    reclaim the bytes must allocate and write them itself with
    `dbg.memory.alloc_remote`/`write` and pass an empty `data`; it then holds
    the address and can free it after the APC has run.

    Returns:
        The `QueueUserAPC` result: nonzero on success.

    Raises:
        InjectionError: the thread id or routine address is invalid (`apc`),
            the routine address is not a 32-bit address for a WOW64 target
            (`apc`), the thread cannot be opened (`apc`), the data
            allocation/write failed (`alloc`/`write`), or Windows refused the
            APC (`apc`); the message carries the Win32 code when there is one.
    """
    if not isinstance(thread_id, int) or isinstance(thread_id, bool) \
            or thread_id <= 0:
        _fail("apc", f"invalid thread id: {thread_id!r}",
              _WIN32_INVALID_PARAMETER)
    if not isinstance(addr, int) or isinstance(addr, bool) or addr <= 0:
        _fail("apc", f"invalid APC routine address: {addr!r}",
              _WIN32_INVALID_PARAMETER)

    session = _session(dbg)
    if _target_is_wow64(session) and addr >= _WOW64_LIMIT:
        _fail("apc",
              f"APC routine 0x{addr:X} is not a 32-bit address; a WOW64 target "
              f"cannot execute code at or above 0x{_WOW64_LIMIT:X}")

    parameter = 0
    if data:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            _fail("apc", f"APC data must be bytes, not {type(data).__name__}",
                  _WIN32_INVALID_PARAMETER)
        payload = bytes(data)
        parameter = _alloc(dbg, session, len(payload), _PAGE_READWRITE)
        try:
            _write(dbg, parameter, payload)
        except InjectionError:
            _free_quietly(dbg, parameter)
            raise

    try:
        try:
            handle = _pydbg.open_thread(thread_id, _THREAD_SET_CONTEXT)
        except OSError as exc:
            _translate("apc", exc)
        try:
            return int(_pydbg.queue_user_apc(handle, addr, parameter))
        except OSError as exc:
            _translate("apc", exc)
        finally:
            _close_quietly(handle)
    except InjectionError:
        # The APC that would have owned the parameter never ran, so the caller
        # has no way to reach the buffer: free it instead of leaking the one
        # allocation whose lifetime the success path deliberately leaves open.
        if parameter:
            _free_quietly(dbg, parameter)
        raise


def _thread_ids(session):
    try:
        return [thread["tid"] for thread in
                _pydbg.enumerate_threads(session.pid)]
    except OSError as exc:
        _translate("threads", exc)


def _distinct_thread_ids(session):
    """The target's thread ids with duplicates removed, in enumeration order.

    `enumerate_threads` is a raw snapshot of a live process and the same tid can
    be reported more than once. Suspending such a thread twice raises its
    suspend count twice, and the count would then describe attempts rather than
    threads. Counting each tid once keeps `suspend_process` and
    `resume_process` symmetric — both answer "distinct threads", so
    `resume_process` undoes exactly what `suspend_process` did.
    """
    seen = set()
    distinct = []
    for thread_id in _thread_ids(session):
        if thread_id not in seen:
            seen.add(thread_id)
            distinct.append(thread_id)
    return distinct


def suspend_process(dbg):
    """Suspend every thread of the target; returns how many were suspended.

    Opens each thread with `THREAD_SUSPEND_RESUME`, calls `SuspendThread` once,
    closes the handles, and returns the number of **distinct threads** that were
    suspended. A tid the enumeration reports more than once is suspended once
    and counted once, so the answer is comparable with `dbg.get_thread_ids()`
    after removing duplicates. Each thread's suspend count is raised by one, so
    `resume_process` is the matching undo. The target's threads stop executing
    immediately; its memory is still readable.

    If a thread cannot be suspended, the threads already suspended by this call
    are resumed before the error is raised, so a partial failure does not leave
    the target wedged; the threads resumed in the rollback are not counted.

    Raises:
        InjectionError: no target (`target`), thread enumeration failed or a
            thread could not be opened/suspended (`threads`); the message
            carries the Win32 code when there is one.
    """
    session = _session(dbg)
    thread_ids = _distinct_thread_ids(session)
    suspended = []
    try:
        for thread_id in thread_ids:
            handle = _pydbg.open_thread(thread_id, _THREAD_SUSPEND_RESUME)
            try:
                _pydbg.suspend_thread(handle)
            except OSError:
                _close_quietly(handle)
                raise
            suspended.append(handle)
    except OSError as exc:
        for handle in suspended:
            try:
                _pydbg.resume_thread(handle)
            except OSError:
                pass
        for handle in suspended:
            _close_quietly(handle)
        _translate("threads", exc)

    for handle in suspended:
        _close_quietly(handle)
    return len(suspended)


def resume_process(dbg):
    """Resume every thread of the target; returns how many were resumed.

    Opens each thread with `THREAD_SUSPEND_RESUME`, calls `ResumeThread` once,
    and closes the handles. A tid the enumeration reports more than once is
    resumed once and counted once, so the answer counts distinct threads and is
    symmetric with `suspend_process`. This is the undo for `suspend_process`;
    resuming a thread that was not suspended by this API lowers a count someone
    else raised, so pair the calls.

    Every thread is attempted even when one fails, and the first failure is
    raised as an `InjectionError` after the rest have been tried; only the
    successful resumes are counted.

    Raises:
        InjectionError: no target (`target`), or enumeration/open/resume failed
            (`threads`); the message carries the Win32 code when there is one.
    """
    session = _session(dbg)
    thread_ids = _distinct_thread_ids(session)
    resumed = 0
    failures = []
    for thread_id in thread_ids:
        try:
            handle = _pydbg.open_thread(thread_id, _THREAD_SUSPEND_RESUME)
        except OSError as exc:
            failures.append(exc)
            continue
        try:
            _pydbg.resume_thread(handle)
            resumed += 1
        except OSError as exc:
            failures.append(exc)
        finally:
            _close_quietly(handle)

    if failures:
        _translate("threads", failures[0])
    return resumed
