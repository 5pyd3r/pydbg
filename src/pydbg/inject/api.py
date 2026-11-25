"""The extension-backed half of `pydbg.inject`.

Every function here takes a `Debugger` (or anything with the same session
surface: `_session.process_handle`, `_session.pid`, `memory`). Remote memory is
allocated with `VirtualAllocEx` through `dbg.memory`, never freed on success,
and the address comes back in the `InjectionReport`; the caller owns both the
allocation and the thread handle. Failures raise `InjectionError` with the
stage and the Win32 code, because an injection that fails at `alloc` and one
that fails at `CreateRemoteThread` need different fixes.

The `LoadLibraryW` address is resolved in *this* process's kernel32. That is
valid only for a same-bitness target: Windows maps kernel32 at the same base in
every 64-bit process of a session, which is the same assumption
`demo/dll_injector.py` makes. Cross-architecture injection is out of scope
(spec §13.9), so a WOW64 target is refused instead of being handed a 64-bit
address.
"""

import os

from .. import _pydbg
from ..exceptions import InjectionError, MemError
from . import InjectionReport

_MEM_COMMIT_RESERVE = 0x3000     # MEM_COMMIT | MEM_RESERVE
_PAGE_READWRITE = 0x04
_PAGE_EXECUTE_READWRITE = 0x40
_THREAD_SET_CONTEXT = 0x0010     # what QueueUserAPC requires
_THREAD_SUSPEND_RESUME = 0x0002  # what SuspendThread/ResumeThread require

_WIN32_INVALID_PARAMETER = 87
_WIN32_FILE_NOT_FOUND = 2


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


def _fail(stage, message, code):
    raise InjectionError(
        f"injection {stage} failed (win32={code}): {message}")


def _translate(stage, exc):
    """Re-raise a lower-level failure as an InjectionError for 'stage'."""
    raise InjectionError(
        f"injection {stage} failed (win32={_win32_code(exc)}): {exc}") from exc


def _session(dbg):
    """The target session behind 'dbg', or an InjectionError naming the problem."""
    session = getattr(dbg, "_session", None)
    if getattr(session, "process_handle", None) is None:
        _fail("target", "no target process handle; create_process() or "
                        "attach() first", 0)
    if getattr(session, "pid", None) is None:
        _fail("target", "no target pid; create_process() or attach() first", 0)
    return session


def _require_native(session):
    """Refuse a WOW64 target: this injection path only has 64-bit addresses."""
    if getattr(session, "target_arch", None) == 32:
        _fail("arch", "cross-architecture injection is not supported "
                      "(WOW64 target, 64-bit host)", 0)


def _alloc(dbg, size, protect):
    try:
        return dbg.memory.alloc_remote(size, protect)
    except (MemError, OSError) as exc:
        _translate("alloc", exc)


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
    Same-bitness targets only (see the module docstring).

    Raises:
        InjectionError: the path is unusable (`path`), kernel32/LoadLibraryW
            cannot be resolved (`resolve`), `VirtualAllocEx` refused (`alloc`),
            `WriteProcessMemory` refused (`write`), or `CreateRemoteThread`
            refused (`thread`); the message carries the Win32 code.
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
    _require_native(session)

    try:
        kernel32 = _pydbg.get_module_handle("kernel32.dll")
        load_library = _pydbg.get_proc_address(kernel32, "LoadLibraryW")
    except OSError as exc:
        _translate("resolve", exc)

    # LoadLibraryW takes a wide string; the terminating pair is part of the
    # buffer, not of the Python string.
    payload = absolute.encode("utf-16-le") + b"\x00\x00"
    remote = _alloc(dbg, len(payload), _PAGE_READWRITE)
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

    Same-bitness targets only (see the module docstring).

    Raises:
        InjectionError: `code` is empty or not bytes (`code`), the allocation
            failed (`alloc`), the write failed (`write`), or the thread could
            not be created (`thread`); the message carries the Win32 code.
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
    _require_native(session)

    remote = _alloc(dbg, len(payload), _PAGE_EXECUTE_READWRITE)
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
    address is what the routine receives; this function does not return that
    address and does not free it, so a caller that needs to reclaim the bytes
    should write them itself with `dbg.memory.alloc_remote`/`write` and pass an
    empty `data` (its own address can then be baked into the routine or found
    another way).

    Returns:
        The `QueueUserAPC` result: nonzero on success.

    Raises:
        InjectionError: the thread id or routine address is invalid (`apc`), the
            thread cannot be opened (`apc`), the data allocation/write failed
            (`alloc`/`write`), or Windows refused the APC (`apc`); the message
            carries the Win32 code.
    """
    if not isinstance(thread_id, int) or isinstance(thread_id, bool) \
            or thread_id <= 0:
        _fail("apc", f"invalid thread id: {thread_id!r}",
              _WIN32_INVALID_PARAMETER)
    if not isinstance(addr, int) or isinstance(addr, bool) or addr <= 0:
        _fail("apc", f"invalid APC routine address: {addr!r}",
              _WIN32_INVALID_PARAMETER)

    session = _session(dbg)
    _require_native(session)

    parameter = 0
    if data:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            _fail("apc", f"APC data must be bytes, not {type(data).__name__}",
                  _WIN32_INVALID_PARAMETER)
        payload = bytes(data)
        parameter = _alloc(dbg, len(payload), _PAGE_READWRITE)
        try:
            _write(dbg, parameter, payload)
        except InjectionError:
            _free_quietly(dbg, parameter)
            raise

    try:
        handle = _pydbg.open_thread(thread_id, _THREAD_SET_CONTEXT)
    except OSError as exc:
        _translate("apc", exc)
    try:
        try:
            return int(_pydbg.queue_user_apc(handle, addr, parameter))
        except OSError as exc:
            _translate("apc", exc)
    finally:
        _close_quietly(handle)


def _thread_ids(session):
    try:
        return [thread["tid"] for thread in
                _pydbg.enumerate_threads(session.pid)]
    except OSError as exc:
        _translate("threads", exc)


def suspend_process(dbg):
    """Suspend every thread of the target; returns how many were suspended.

    Opens each thread with `THREAD_SUSPEND_RESUME`, calls `SuspendThread` once,
    closes the handles, and returns the count. Each thread's suspend count is
    raised by one, so `resume_process` is the matching undo. The target's
    threads stop executing immediately; its memory is still readable.

    If a thread cannot be suspended, the threads already suspended by this call
    are resumed before the error is raised, so a partial failure does not leave
    the target wedged.

    Raises:
        InjectionError: no target (`target`), thread enumeration failed or a
            thread could not be opened/suspended (`threads`); the message
            carries the Win32 code.
    """
    session = _session(dbg)
    thread_ids = _thread_ids(session)
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
    and closes the handles. This is the undo for `suspend_process`; resuming a
    thread that was not suspended by this API lowers a count someone else
    raised, so pair the calls.

    Every thread is attempted even when one fails, and the first failure is
    raised as an `InjectionError` after the rest have been tried.

    Raises:
        InjectionError: no target (`target`), or enumeration/open/resume failed
            (`threads`); the message carries the Win32 code.
    """
    session = _session(dbg)
    thread_ids = _thread_ids(session)
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
