# _thread.pyx — Win32 thread and register operations

from libc.stdlib cimport malloc, free
from _win32types cimport (
    HANDLE, DWORD, BOOL, LPVOID,
    OpenThread, GetThreadContext, SetThreadContext,
    SuspendThread, ResumeThread, GetLastError,
    CloseHandle,
    THREAD_ALL_ACCESS, CONTEXT_ALL,
    CONTEXT_DEBUG_REGISTERS, CONTEXT_INTEGER, CONTEXT_CONTROL,
    CreateToolhelp32Snapshot, Thread32First, Thread32Next,
    THREADENTRY32, TH32CS_SNAPTHREAD,
    pydbg_ctx_sizeof, pydbg_ctx_init,
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


cpdef dict get_thread_context(unsigned long long h_thread):
    """Get thread register context.

    Returns dict of register name -> value, with architecture-appropriate
    register names (rax/rsp/rip on x64, eax/esp/eip on x86).
    Also includes 'arch' key ('x64' or 'x86').
    Raises OSError on failure.
    """
    cdef int ctx_size = pydbg_ctx_sizeof()
    cdef void* ctx = malloc(ctx_size)
    if ctx == NULL:
        raise MemoryError("Failed to allocate CONTEXT")
    pydbg_ctx_init(ctx, CONTEXT_ALL)

    cdef BOOL result = GetThreadContext(<HANDLE><LPVOID>h_thread, ctx)
    if result == 0:
        free(ctx)
        raise OSError(GetLastError(), "GetThreadContext failed")

    cdef int arch = pydbg_host_arch()
    cdef dict out = {}

    # GP registers
    if arch == 64:
        for i in range(16):
            out[_GP_NAMES_X64[i]] = pydbg_ctx_get_gp(ctx, i)
        out['rip'] = pydbg_ctx_get_ip(ctx)
    else:
        for i in range(8):
            out[_GP_NAMES_X86[i]] = pydbg_ctx_get_gp(ctx, i)
        out['eip'] = pydbg_ctx_get_ip(ctx)

    out['eflags'] = pydbg_ctx_get_eflags(ctx)

    # Debug registers
    for dr in _DR_SLOTS:
        out[f'dr{dr}'] = pydbg_ctx_get_dr(ctx, dr)

    # Segment registers
    for i, name in enumerate(_SEG_NAMES):
        out[name] = pydbg_ctx_get_seg(ctx, i)

    out['arch'] = 'x64' if arch == 64 else 'x86'
    free(ctx)
    return out


cpdef int set_thread_context(unsigned long long h_thread, dict context) except? -1:
    """Set thread register context.

    Accepts both x64 (rax/rip/...) and x86 (eax/eip/...) register names.
    Only registers present in the dict are updated.
    Raises OSError on failure.
    """
    cdef int ctx_size = pydbg_ctx_sizeof()
    cdef void* ctx = malloc(ctx_size)
    if ctx == NULL:
        raise MemoryError("Failed to allocate CONTEXT")
    pydbg_ctx_init(ctx, CONTEXT_ALL)

    # First get current context
    cdef BOOL result = GetThreadContext(<HANDLE><LPVOID>h_thread, ctx)
    if result == 0:
        free(ctx)
        raise OSError(GetLastError(), "GetThreadContext failed (before set)")

    cdef int arch = pydbg_host_arch()

    # IP register
    if arch == 64:
        if 'rip' in context: pydbg_ctx_set_ip(ctx, context['rip'])
    else:
        if 'eip' in context: pydbg_ctx_set_ip(ctx, context['eip'])

    # SP register
    if arch == 64:
        if 'rsp' in context: pydbg_ctx_set_sp(ctx, context['rsp'])
    else:
        if 'esp' in context: pydbg_ctx_set_sp(ctx, context['esp'])

    # BP register
    if arch == 64:
        if 'rbp' in context: pydbg_ctx_set_bp(ctx, context['rbp'])
    else:
        if 'ebp' in context: pydbg_ctx_set_bp(ctx, context['ebp'])

    # GP registers
    gp_names = _GP_NAMES_X64 if arch == 64 else _GP_NAMES_X86
    for i, name in enumerate(gp_names):
        if name in context:
            pydbg_ctx_set_gp(ctx, i, context[name])

    # EFLAGS
    if 'eflags' in context:
        pydbg_ctx_set_eflags(ctx, context['eflags'])

    # Debug registers
    for dr in _DR_SLOTS:
        key = f'dr{dr}'
        if key in context:
            pydbg_ctx_set_dr(ctx, dr, context[key])

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
