# _process.pyx — Win32 process debugging API

from _win32types cimport (
    HANDLE, DWORD, BOOL, LPVOID, SIZE_T, LPCSTR, LPDWORD, HMODULE,
    DEBUG_EVENT, STARTUPINFOA, PROCESS_INFORMATION,
    CreateProcessA, WaitForDebugEvent, ContinueDebugEvent,
    DebugActiveProcess, DebugActiveProcessStop,
    GetExitCodeProcess, GetExitCodeThread, TerminateProcess, OpenProcess,
    CreateRemoteThread, GetProcAddress, GetModuleHandleA,
    WaitForSingleObject,
    CloseHandle, GetLastError,
    DEBUG_PROCESS, DEBUG_ONLY_THIS_PROCESS, CREATE_SUSPENDED, INFINITE,
    DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED,
    EXCEPTION_DEBUG_EVENT, CREATE_PROCESS_DEBUG_EVENT,
    CREATE_THREAD_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
    EXIT_THREAD_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT,
    UNLOAD_DLL_DEBUG_EVENT, EXCEPTION_ACCESS_VIOLATION,
    EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
)

from libc.string cimport memset

# Event code string mapping
_EVENT_NAMES = {
    EXCEPTION_DEBUG_EVENT: "EXCEPTION",
    CREATE_THREAD_DEBUG_EVENT: "CREATE_THREAD",
    CREATE_PROCESS_DEBUG_EVENT: "CREATE_PROCESS",
    EXIT_THREAD_DEBUG_EVENT: "EXIT_THREAD",
    EXIT_PROCESS_DEBUG_EVENT: "EXIT_PROCESS",
    LOAD_DLL_DEBUG_EVENT: "LOAD_DLL",
    UNLOAD_DLL_DEBUG_EVENT: "UNLOAD_DLL",
    # OUTPUT_DEBUG_STRING: "OUTPUT_DEBUG_STRING",
    # RIP_INFO: "RIP_INFO",
}

cpdef tuple create_process(str path, bint debug_children=False):
    """Create a process under debug control.

    Args:
        path: Path to executable.
        debug_children: If True, also debug child processes.

    Returns (pid, tid, h_process, h_thread).
    Raises OSError on failure.
    """
    cdef PROCESS_INFORMATION pi
    cdef STARTUPINFOA si
    cdef bytes path_bytes

    memset(&si, 0, sizeof(si))
    si.cb = sizeof(si)
    memset(&pi, 0, sizeof(pi))

    path_bytes = path.encode('utf-8')

    cdef DWORD flags = DEBUG_PROCESS
    if not debug_children:
        flags |= DEBUG_ONLY_THIS_PROCESS

    cdef BOOL result = CreateProcessA(
        <LPCSTR>NULL,
        <char*>path_bytes,
        NULL, NULL, 0,
        flags,
        NULL, <LPCSTR>NULL,
        &si, &pi)

    if result == 0:
        raise OSError(GetLastError(), "CreateProcessA failed")

    cdef DWORD pid = pi.dwProcessId
    cdef DWORD tid = pi.dwThreadId
    cdef unsigned long long h_proc = <unsigned long long>pi.hProcess
    cdef unsigned long long h_thr = <unsigned long long>pi.hThread

    return (pid, tid, h_proc, h_thr)


cpdef tuple create_process_suspended(str path):
    """Create a process in suspended state (no debug control).

    The main thread is created but does not execute. Caller is
    responsible for resuming the thread after injection.

    Returns (pid, tid, h_process, h_thread).
    Raises OSError on failure.
    """
    cdef PROCESS_INFORMATION pi
    cdef STARTUPINFOA si
    cdef bytes path_bytes

    memset(&si, 0, sizeof(si))
    si.cb = sizeof(si)
    memset(&pi, 0, sizeof(pi))

    path_bytes = path.encode('utf-8')

    cdef BOOL result = CreateProcessA(
        <LPCSTR>NULL,
        <char*>path_bytes,
        NULL, NULL, 0,
        CREATE_SUSPENDED,
        NULL, <LPCSTR>NULL,
        &si, &pi)

    if result == 0:
        raise OSError(GetLastError(), "CreateProcessA failed (suspended)")

    cdef DWORD pid = pi.dwProcessId
    cdef DWORD tid = pi.dwThreadId
    cdef unsigned long long h_proc = <unsigned long long>pi.hProcess
    cdef unsigned long long h_thr = <unsigned long long>pi.hThread

    return (pid, tid, h_proc, h_thr)


cpdef int debug_active_process(int pid) except? -1:
    """Attach to a running process for debugging.

    Raises OSError on failure.
    """
    cdef BOOL result = DebugActiveProcess(<DWORD>pid)
    if result == 0:
        raise OSError(GetLastError(), "DebugActiveProcess failed")
    return 0


cpdef object wait_for_debug_event(int timeout_ms=10000):
    """Wait for the next debug event.

    Returns a dict with event info, or None on timeout.
    """
    cdef DEBUG_EVENT de
    cdef BOOL result
    cdef DWORD err

    memset(&de, 0, sizeof(de))

    result = WaitForDebugEvent(&de, <DWORD>timeout_ms)
    if result == 0:
        err = GetLastError()
        if err == 1460 or err == 121:  # ERROR_TIMEOUT or ERROR_SEM_TIMEOUT
            return None
        raise OSError(err, "WaitForDebugEvent failed")

    cdef dict event = {
        'event_code': de.dwDebugEventCode,
        'event_name': _EVENT_NAMES.get(de.dwDebugEventCode, "UNKNOWN"),
        'pid': de.dwProcessId,
        'tid': de.dwThreadId,
    }

    cdef DWORD code = de.dwDebugEventCode

    if code == EXCEPTION_DEBUG_EVENT:
        event['exception_code'] = de.u.Exception.ExceptionRecord.ExceptionCode
        event['exception_addr'] = <unsigned long long>de.u.Exception.ExceptionRecord.ExceptionAddress
        event['first_chance'] = de.u.Exception.dwFirstChance
    elif code == CREATE_PROCESS_DEBUG_EVENT:
        event['base_of_image'] = <unsigned long long>de.u.CreateProcessInfo.lpBaseOfImage
        event['child_process_handle'] = <unsigned long long>de.u.CreateProcessInfo.hProcess
        event['child_thread_handle'] = <unsigned long long>de.u.CreateProcessInfo.hThread
    elif code == EXIT_PROCESS_DEBUG_EVENT:
        event['exit_code'] = de.u.ExitProcess.dwExitCode
    elif code == CREATE_THREAD_DEBUG_EVENT:
        event['thread_start_addr'] = <unsigned long long>de.u.CreateThread.lpStartAddress
    elif code == EXIT_THREAD_DEBUG_EVENT:
        event['thread_exit_code'] = de.u.ExitThread.dwExitCode
    elif code == LOAD_DLL_DEBUG_EVENT:
        event['dll_base'] = <unsigned long long>de.u.LoadDll.lpBaseOfDll

    return event


cpdef void continue_debug_event(int pid, int tid, int status=DBG_CONTINUE):
    """Continue a thread that was stopped for a debug event.

    Raises OSError on failure.
    """
    cdef BOOL result = ContinueDebugEvent(<DWORD>pid, <DWORD>tid, <DWORD>status)
    if result == 0:
        raise OSError(GetLastError(), f"ContinueDebugEvent failed, {pid}, {tid}")

cpdef int debug_active_process_stop(int pid) except? -1:
    """Detach debugger from a process.

    Raises OSError on failure.
    """
    cdef BOOL result = DebugActiveProcessStop(<DWORD>pid)
    if result == 0:
        raise OSError(GetLastError(), "DebugActiveProcessStop failed")
    return 0


cpdef int get_exit_code(unsigned long long h_process):
    """Get the exit code of a process.

    Raises OSError on failure.
    """
    cdef DWORD exit_code
    cdef BOOL result = GetExitCodeProcess(<HANDLE><LPVOID>h_process, &exit_code)
    if result == 0:
        raise OSError(GetLastError(), "GetExitCodeProcess failed")
    return exit_code


cpdef int get_exit_code_thread(unsigned long long h_thread):
    """Get the exit code of a thread.

    For threads created via CreateRemoteThread, this returns the
    return value of the thread function (e.g., LoadLibraryA result).
    Raises OSError on failure.
    """
    cdef DWORD exit_code
    cdef BOOL result = GetExitCodeThread(<HANDLE><LPVOID>h_thread, &exit_code)
    if result == 0:
        raise OSError(GetLastError(), "GetExitCodeThread failed")
    return exit_code


cpdef void terminate_process(unsigned long long h_process, int exit_code=1):
    """Terminate a process.

    Raises OSError on failure.
    """
    cdef BOOL result = TerminateProcess(<HANDLE><LPVOID>h_process, <unsigned int>exit_code)
    if result == 0:
        raise OSError(GetLastError(), "TerminateProcess failed")


cpdef unsigned long long open_process(int pid, int access=0x1F0FFF):
    """Open a process by PID.

    Default access: PROCESS_ALL_ACCESS (0x1F0FFF).
    Returns process handle. Raises OSError on failure.
    """
    cdef HANDLE h_proc = OpenProcess(<DWORD>access, 0, <DWORD>pid)
    if h_proc == NULL:
        raise OSError(GetLastError(), f"OpenProcess failed for pid {pid}")
    return <unsigned long long>h_proc


cpdef void close_handle(unsigned long long h_handle):
    """Close a Win32 handle.

    Raises OSError on failure.
    """
    cdef BOOL result = CloseHandle(<HANDLE><LPVOID>h_handle)
    if result == 0:
        raise OSError(GetLastError(), "CloseHandle failed")


cpdef tuple create_remote_thread(unsigned long long h_process,
                                  unsigned long long start_addr,
                                  unsigned long long param, int flags=0):
    """Create a thread in the remote process.

    Returns (tid, h_thread). Raises OSError on failure.
    """
    cdef DWORD tid = 0
    cdef HANDLE h_thread = CreateRemoteThread(
        <HANDLE><LPVOID>h_process,
        NULL,
        0,
        <LPVOID>start_addr,
        <LPVOID>param,
        <DWORD>flags,
        &tid)

    if h_thread == NULL:
        raise OSError(GetLastError(), "CreateRemoteThread failed")

    return (<int>tid, <unsigned long long>h_thread)


cpdef unsigned long long get_proc_address(unsigned long long h_module, str proc_name):
    """Get the address of an exported function.

    Returns the function address. Raises OSError on failure.
    """
    cdef bytes name_bytes = proc_name.encode('utf-8')
    cdef void* addr = GetProcAddress(<HMODULE><LPVOID>h_module, <LPCSTR>name_bytes)

    if addr == NULL:
        raise OSError(GetLastError(), f"GetProcAddress failed for '{proc_name}'")

    return <unsigned long long>addr


cpdef unsigned long long get_module_handle(str module_name):
    """Get the handle (base address) of a loaded module.

    Returns the module handle. Raises OSError on failure.
    """
    cdef bytes name_bytes = module_name.encode('utf-8')
    cdef HMODULE h_mod = GetModuleHandleA(<LPCSTR>name_bytes)

    if h_mod == NULL:
        raise OSError(GetLastError(), f"GetModuleHandleA failed for '{module_name}'")

    return <unsigned long long>h_mod


cpdef int wait_for_single_object(unsigned long long h_handle, int timeout_ms=10000):
    """Wait for an object (thread, process, etc.) to become signaled.

    Returns WAIT_OBJECT_0 (0) if signaled, WAIT_TIMEOUT (258) on timeout.
    Raises OSError on failure.
    """
    cdef DWORD result = WaitForSingleObject(<HANDLE><LPVOID>h_handle, <DWORD>timeout_ms)

    if result == <DWORD>0xFFFFFFFF:  # WAIT_FAILED
        raise OSError(GetLastError(), "WaitForSingleObject failed")

    return <int>result
