# _thread.pyx — Win32 thread and register operations

from _win32types cimport (
    HANDLE, DWORD, BOOL, LPVOID, CONTEXT,
    OpenThread, GetThreadContext, SetThreadContext,
    SuspendThread, ResumeThread, GetLastError,
    CloseHandle,
    THREAD_ALL_ACCESS, CONTEXT_ALL,
    CONTEXT_DEBUG_REGISTERS, CONTEXT_INTEGER, CONTEXT_CONTROL,
    CreateToolhelp32Snapshot, Thread32First, Thread32Next,
    THREADENTRY32, TH32CS_SNAPTHREAD,
)

from libc.string cimport memset

cpdef unsigned long long open_thread(int thread_id, int access=THREAD_ALL_ACCESS):
    """Open a thread by ID.

    Returns handle as integer. Raises OSError on failure.
    """
    cdef HANDLE h = OpenThread(<DWORD>access, 0, <DWORD>thread_id)
    if h == NULL:
        raise OSError(GetLastError(), "OpenThread failed")
    return <unsigned long long>h


cpdef dict get_thread_context(unsigned long long h_thread):
    """Get thread register context (x64).

    Returns dict of register name -> value.
    Raises OSError on failure.
    """
    cdef CONTEXT ctx
    memset(&ctx, 0, sizeof(ctx))
    ctx.ContextFlags = CONTEXT_ALL

    cdef BOOL result = GetThreadContext(<HANDLE><LPVOID>h_thread, &ctx)
    if result == 0:
        raise OSError(GetLastError(), "GetThreadContext failed")

    return {
        'rax': ctx.Rax, 'rcx': ctx.Rcx, 'rdx': ctx.Rdx, 'rbx': ctx.Rbx,
        'rsp': ctx.Rsp, 'rbp': ctx.Rbp, 'rsi': ctx.Rsi, 'rdi': ctx.Rdi,
        'r8': ctx.R8, 'r9': ctx.R9, 'r10': ctx.R10, 'r11': ctx.R11,
        'r12': ctx.R12, 'r13': ctx.R13, 'r14': ctx.R14, 'r15': ctx.R15,
        'rip': ctx.Rip,
        'eflags': ctx.EFlags,
        'dr0': ctx.Dr0, 'dr1': ctx.Dr1, 'dr2': ctx.Dr2, 'dr3': ctx.Dr3,
        'dr6': ctx.Dr6, 'dr7': ctx.Dr7,
        'cs': ctx.SegCs, 'ds': ctx.SegDs, 'es': ctx.SegEs,
        'fs': ctx.SegFs, 'gs': ctx.SegGs, 'ss': ctx.SegSs,
    }


cpdef int set_thread_context(unsigned long long h_thread, dict context) except? -1:
    """Set thread register context (x64).

    Only registers present in the dict are updated.
    Raises OSError on failure.
    """
    cdef CONTEXT ctx
    memset(&ctx, 0, sizeof(ctx))
    ctx.ContextFlags = CONTEXT_ALL

    # First get current context
    cdef BOOL result = GetThreadContext(<HANDLE><LPVOID>h_thread, &ctx)
    if result == 0:
        raise OSError(GetLastError(), "GetThreadContext failed (before set)")

    # Update fields present in dict
    if 'rax' in context: ctx.Rax = context['rax']
    if 'rcx' in context: ctx.Rcx = context['rcx']
    if 'rdx' in context: ctx.Rdx = context['rdx']
    if 'rbx' in context: ctx.Rbx = context['rbx']
    if 'rsp' in context: ctx.Rsp = context['rsp']
    if 'rbp' in context: ctx.Rbp = context['rbp']
    if 'rsi' in context: ctx.Rsi = context['rsi']
    if 'rdi' in context: ctx.Rdi = context['rdi']
    if 'r8' in context: ctx.R8 = context['r8']
    if 'r9' in context: ctx.R9 = context['r9']
    if 'r10' in context: ctx.R10 = context['r10']
    if 'r11' in context: ctx.R11 = context['r11']
    if 'r12' in context: ctx.R12 = context['r12']
    if 'r13' in context: ctx.R13 = context['r13']
    if 'r14' in context: ctx.R14 = context['r14']
    if 'r15' in context: ctx.R15 = context['r15']
    if 'rip' in context: ctx.Rip = context['rip']
    if 'dr0' in context: ctx.Dr0 = context['dr0']
    if 'dr1' in context: ctx.Dr1 = context['dr1']
    if 'dr2' in context: ctx.Dr2 = context['dr2']
    if 'dr3' in context: ctx.Dr3 = context['dr3']
    if 'dr7' in context: ctx.Dr7 = context['dr7']
    if 'eflags' in context: ctx.EFlags = context['eflags']

    result = SetThreadContext(<HANDLE><LPVOID>h_thread, &ctx)
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
    while ok:
        if te.th32OwnerProcessID == <DWORD>pid:
            threads.append({
                'tid': te.th32ThreadID,
                'owner_pid': te.th32OwnerProcessID,
                'base_priority': te.tpBasePri,
            })
        ok = Thread32Next(snap, &te)

    CloseHandle(snap)
    return threads
