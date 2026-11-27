# _thread.pyx — Win32 thread and register operations

from libc.stdlib cimport malloc, free
from _win32types cimport (
    HANDLE, DWORD, BOOL, LPVOID, SIZE_T, ULONG_PTR,
    OpenThread, GetThreadContext, SetThreadContext,
    Wow64GetThreadContext, Wow64SetThreadContext, WOW64_CONTEXT_ALL,
    SuspendThread, ResumeThread, GetThreadId, GetLastError,
    CloseHandle, PAPCFUNC, QueueUserAPC,
    THREAD_ALL_ACCESS, CONTEXT_ALL,
    CONTEXT_DEBUG_REGISTERS, CONTEXT_INTEGER, CONTEXT_CONTROL,
    CreateToolhelp32Snapshot, Thread32First, Thread32Next,
    THREADENTRY32, TH32CS_SNAPTHREAD,
    pydbg_ctx_sizeof, pydbg_ctx_init,
    pydbg_ctx_arch_sizeof,
    pydbg_ctx_get_ip, pydbg_ctx_set_ip,
    pydbg_ctx_get_sp, pydbg_ctx_set_sp,
    pydbg_ctx_get_bp, pydbg_ctx_set_bp,
    pydbg_ctx_get_eflags, pydbg_ctx_set_eflags,
    pydbg_ctx_get_gp, pydbg_ctx_set_gp,
    pydbg_ctx_get_dr, pydbg_ctx_set_dr,
    pydbg_ctx_get_seg,
    pydbg_host_arch,
)

# Register name tables for x64 and x86
_GP_NAMES_X64 = [
    'rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
]
_GP_NAMES_X86 = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
_SEG_NAMES = ['cs', 'ds', 'es', 'fs', 'gs', 'ss']
_DR_SLOTS = [0, 1, 2, 3, 6, 7]


cpdef unsigned long long open_thread(int thread_id, int access=THREAD_ALL_ACCESS):
    """Open a thread by ID.

    Returns handle as integer. Raises OSError on failure.
    """
    cdef HANDLE h = OpenThread(<DWORD>access, 0, <DWORD>thread_id)
    if h == NULL:
        raise OSError(GetLastError(), "OpenThread failed")
    return <unsigned long long>h


cpdef int get_host_arch():
    """Return host architecture: 32 or 64."""
    return pydbg_host_arch()


cpdef unsigned long long get_thread_id(unsigned long long h_thread):
    """Return the thread ID for a thread handle. Raises OSError on failure."""
    cdef DWORD tid = GetThreadId(<HANDLE><LPVOID>h_thread)
    if tid == 0:
        raise OSError(GetLastError(), "GetThreadId failed")
    return <unsigned long long>tid


cpdef dict get_thread_context(unsigned long long h_thread, int machine=64):
    """Get thread register context.

    machine: 32 = WOW64 (x86) target, 64 = native x64 target (default).
    Returns dict of register name -> value with architecture-appropriate
    names (rax/rsp/rip on x64, eax/esp/eip on x86) plus 'arch'.
    Raises OSError on failure.
    """
    cdef int ctx_size = pydbg_ctx_sizeof()
    cdef void* ctx = malloc(ctx_size)
    if ctx == NULL:
        raise MemoryError("Failed to allocate CONTEXT")
    cdef BOOL result
    if machine == 32:
        pydbg_ctx_init(ctx, machine, WOW64_CONTEXT_ALL)
        result = Wow64GetThreadContext(<HANDLE><LPVOID>h_thread, ctx)
    else:
        pydbg_ctx_init(ctx, machine, CONTEXT_ALL)
        result = GetThreadContext(<HANDLE><LPVOID>h_thread, ctx)
    if result == 0:
        free(ctx)
        raise OSError(GetLastError(), "GetThreadContext failed")

    cdef list gp_names
    cdef str ip_name
    cdef str arch
    if machine == 32:
        gp_names = _GP_NAMES_X86
        ip_name = 'eip'
        arch = 'x86'
    else:
        gp_names = _GP_NAMES_X64
        ip_name = 'rip'
        arch = 'x64'

    cdef dict out = {}
    cdef int i
    for i in range(len(gp_names)):
        out[gp_names[i]] = pydbg_ctx_get_gp(ctx, machine, i)
    out[ip_name] = pydbg_ctx_get_ip(ctx, machine)
    out['eflags'] = pydbg_ctx_get_eflags(ctx, machine)
    for dr in _DR_SLOTS:
        out[f'dr{dr}'] = pydbg_ctx_get_dr(ctx, machine, dr)
    for i, name in enumerate(_SEG_NAMES):
        out[name] = pydbg_ctx_get_seg(ctx, machine, i)
    out['arch'] = arch
    free(ctx)
    return out


cpdef bytes get_thread_context_bytes(unsigned long long h_thread, int machine=64):
    """Capture a thread's raw CONTEXT bytes.

    machine: 32 = WOW64_CONTEXT (716 bytes), 64 = native x64 CONTEXT
    (1232 bytes). This is the buffer StackWalk64 consumes; the dict-shaped
    get_thread_context() above stays the register API. Raises OSError on
    failure.
    """
    cdef int ctx_size = pydbg_ctx_sizeof()
    cdef void* ctx = malloc(ctx_size)
    if ctx == NULL:
        raise MemoryError("Failed to allocate CONTEXT")
    cdef BOOL result
    if machine == 32:
        pydbg_ctx_init(ctx, machine, WOW64_CONTEXT_ALL)
        result = Wow64GetThreadContext(<HANDLE><LPVOID>h_thread, ctx)
    else:
        pydbg_ctx_init(ctx, machine, CONTEXT_ALL)
        result = GetThreadContext(<HANDLE><LPVOID>h_thread, ctx)
    if result == 0:
        free(ctx)
        raise OSError(GetLastError(), "GetThreadContext failed")
    cdef char* raw = <char*>ctx
    cdef bytes data = raw[:pydbg_ctx_arch_sizeof(machine)]
    free(ctx)
    return data


cpdef tuple context_frame_bytes(int machine, object context_bytes):
    """(ip, sp, fp) read from raw CONTEXT bytes, without touching a thread.

    StackWalker starts from the context it was handed rather than from
    whatever the thread's registers hold now. Raises ValueError when the
    buffer is shorter than the architecture's CONTEXT.
    """
    cdef bytes data = bytes(context_bytes)
    cdef int need = pydbg_ctx_arch_sizeof(machine)
    if len(data) < need:
        raise ValueError(
            "CONTEXT for machine %d is %d bytes, got %d"
            % (machine, need, len(data)))
    cdef char* raw = data
    return (pydbg_ctx_get_ip(<void*>raw, machine),
            pydbg_ctx_get_sp(<void*>raw, machine),
            pydbg_ctx_get_bp(<void*>raw, machine))


cpdef int set_thread_context(unsigned long long h_thread, dict context, int machine=64) except? -1:
    """Set thread register context.

    machine: 32 = WOW64 (x86) target, 64 = native x64 target (default).
    Accepts both x64 (rax/rip/...) and x86 (eax/eip/...) register names;
    only registers present in the dict are updated.
    Raises OSError on failure.
    """
    cdef int ctx_size = pydbg_ctx_sizeof()
    cdef void* ctx = malloc(ctx_size)
    if ctx == NULL:
        raise MemoryError("Failed to allocate CONTEXT")
    cdef BOOL result
    if machine == 32:
        pydbg_ctx_init(ctx, machine, WOW64_CONTEXT_ALL)
        result = Wow64GetThreadContext(<HANDLE><LPVOID>h_thread, ctx)
    else:
        pydbg_ctx_init(ctx, machine, CONTEXT_ALL)
        result = GetThreadContext(<HANDLE><LPVOID>h_thread, ctx)
    if result == 0:
        free(ctx)
        raise OSError(GetLastError(), "GetThreadContext failed (before set)")

    cdef list gp_names
    if machine == 32:
        gp_names = _GP_NAMES_X86
    else:
        gp_names = _GP_NAMES_X64

    # IP / SP / BP / GP by machine
    if machine == 32:
        if 'eip' in context: pydbg_ctx_set_ip(ctx, machine, context['eip'])
        if 'esp' in context: pydbg_ctx_set_sp(ctx, machine, context['esp'])
        if 'ebp' in context: pydbg_ctx_set_bp(ctx, machine, context['ebp'])
    else:
        if 'rip' in context: pydbg_ctx_set_ip(ctx, machine, context['rip'])
        if 'rsp' in context: pydbg_ctx_set_sp(ctx, machine, context['rsp'])
        if 'rbp' in context: pydbg_ctx_set_bp(ctx, machine, context['rbp'])

    for i, name in enumerate(gp_names):
        if name in context:
            pydbg_ctx_set_gp(ctx, machine, i, context[name])

    if 'eflags' in context:
        pydbg_ctx_set_eflags(ctx, machine, context['eflags'])

    for dr in _DR_SLOTS:
        key = f'dr{dr}'
        if key in context:
            pydbg_ctx_set_dr(ctx, machine, dr, context[key])

    if machine == 32:
        result = Wow64SetThreadContext(<HANDLE><LPVOID>h_thread, ctx)
    else:
        result = SetThreadContext(<HANDLE><LPVOID>h_thread, ctx)
    free(ctx)
    if result == 0:
        raise OSError(GetLastError(), "SetThreadContext failed")
    return 0


cpdef int suspend_thread(unsigned long long h_thread):
    """Suspend a thread. Returns previous suspend count.

    Raises OSError on failure.
    """
    cdef DWORD result = SuspendThread(<HANDLE><LPVOID>h_thread)
    if result == <DWORD>-1:
        raise OSError(GetLastError(), "SuspendThread failed")
    return <int>result


cpdef int resume_thread(unsigned long long h_thread):
    """Resume a thread. Returns previous suspend count.

    Raises OSError on failure.
    """
    cdef DWORD result = ResumeThread(<HANDLE><LPVOID>h_thread)
    if result == <DWORD>-1:
        raise OSError(GetLastError(), "ResumeThread failed")
    return <int>result


cpdef int queue_user_apc(unsigned long long h_thread, unsigned long long addr,
                         unsigned long long data=0):
    """Queue a user-mode APC to 'h_thread' at 'addr', with 'data' as parameter.

    The target thread must enter an alertable wait before the routine runs
    (SleepEx / WaitForSingleObjectEx(..., TRUE) / MsgWaitForMultipleObjectsEx
    with MWMO_ALERTABLE); queueing does not interrupt a non-alertable wait.

    Returns 1 on success. Raises OSError on failure.
    """
    cdef DWORD result = QueueUserAPC(
        <PAPCFUNC>addr,
        <HANDLE><LPVOID>h_thread,
        <ULONG_PTR>data)
    if result == 0:
        raise OSError(GetLastError(), "QueueUserAPC failed")
    return 1


cpdef int close_thread(unsigned long long h_handle):
    """Close a Win32 handle. Raises OSError on failure."""
    cdef BOOL result = CloseHandle(<HANDLE><LPVOID>h_handle)
    if result == 0:
        raise OSError(GetLastError(), "CloseHandle failed")
    return 0


cpdef list enumerate_threads(int pid):
    """Enumerate thread IDs for a given process.

    Uses CreateToolhelp32Snapshot + Thread32First/Thread32Next.

    Args:
        pid: Process ID.

    Returns:
        list of thread ID dicts with keys: 'tid', 'owner_pid', 'base_priority'.

    Raises:
        OSError: On snapshot failure.
    """
    cdef HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, <DWORD>pid)
    if snap == <HANDLE><unsigned long long>-1:
        raise OSError(GetLastError(), "CreateToolhelp32Snapshot failed")

    cdef THREADENTRY32 te
    te.dwSize = sizeof(THREADENTRY32)
    cdef list threads = []

    cdef BOOL ok = Thread32First(snap, &te)
    # List building can raise; the snapshot handle must also go back on that
    # path, not just when the walk runs to completion.
    try:
        while ok:
            if te.th32OwnerProcessID == <DWORD>pid:
                threads.append({
                    'tid': te.th32ThreadID,
                    'owner_pid': te.th32OwnerProcessID,
                    'base_priority': te.tpBasePri,
                })
            ok = Thread32Next(snap, &te)
    finally:
        CloseHandle(snap)
    return threads
