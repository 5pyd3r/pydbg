# _bp.pyx — Hardware breakpoint management via debug registers

from libc.stdlib cimport malloc, free

from _win32types cimport (
    HANDLE, DWORD, BOOL, LPVOID,
    GetThreadContext, SetThreadContext, GetLastError,
    Wow64GetThreadContext, Wow64SetThreadContext, WOW64_CONTEXT_ALL,
    CONTEXT_DEBUG_REGISTERS,
    pydbg_ctx_sizeof, pydbg_ctx_init,
    pydbg_ctx_get_dr, pydbg_ctx_set_dr,
    pydbg_ctx_set_flags,
)

# Condition encoding for Dr7
HW_BREAKPOINT_EXECUTE = 0
HW_BREAKPOINT_WRITE = 1
HW_BREAKPOINT_READWRITE = 3

# Length encoding for Dr7
HW_BREAKPOINT_1_BYTE = 0
HW_BREAKPOINT_2_BYTE = 1
HW_BREAKPOINT_4_BYTE = 3
HW_BREAKPOINT_8_BYTE = 2

# Dr7 bit layout per slot:
#   RW bits at positions 16, 20, 24, 28
#   LEN bits at positions 18, 22, 26, 30
#   Local enable at bits 0, 2, 4, 6


cdef void* _get_context(HANDLE h_thread, int machine):
    """Get thread CONTEXT with debug registers. Caller must free()."""
    cdef int ctx_size = pydbg_ctx_sizeof()
    cdef void* ctx = malloc(ctx_size)
    if ctx == NULL:
        raise MemoryError("Failed to allocate CONTEXT")
    if machine == 32:
        pydbg_ctx_init(ctx, machine, WOW64_CONTEXT_ALL)
        if Wow64GetThreadContext(h_thread, ctx) == 0:
            free(ctx)
            raise OSError(GetLastError(), "Wow64GetThreadContext failed")
    else:
        pydbg_ctx_init(ctx, machine, CONTEXT_DEBUG_REGISTERS)
        if GetThreadContext(h_thread, ctx) == 0:
            free(ctx)
            raise OSError(GetLastError(), "GetThreadContext failed")
    return ctx

cpdef int set_hw_breakpoint(unsigned long long h_thread, int slot, unsigned long long addr,
                             int condition, int length, int machine=64) except? -1:
    """Set a hardware breakpoint.

    Args:
        h_thread: Thread handle.
        slot: Debug register slot (0-3).
        addr: Breakpoint address.
        condition: 0=execute, 1=write, 3=read/write.
        length: 0=1 byte, 1=2 bytes, 3=4 bytes, 2=8 bytes.
        machine: 32 = WOW64 (x86) target, 64 = native x64 target (default).

    Returns:
        0 on success.

    Raises:
        ValueError: Invalid slot/condition/length.
        OSError: Win32 API failure.
    """
    if slot < 0 or slot > 3:
        raise ValueError(f"slot must be 0-3, got {slot}")
    if condition not in (0, 1, 3):
        raise ValueError(f"condition must be 0, 1, or 3, got {condition}")
    if length not in (0, 1, 2, 3):
        raise ValueError(f"length must be 0, 1, 2, or 3, got {length}")
    if condition == 0 and length != 0:
        raise ValueError("execute breakpoints must be 1 byte")
    if machine == 32 and length == 2:
        raise ValueError("8-byte breakpoints not supported on x86/WOW64")

    cdef void* ctx = _get_context(<HANDLE><LPVOID>h_thread, machine)

    pydbg_ctx_set_dr(ctx, machine, slot, addr)

    cdef unsigned long long dr7 = pydbg_ctx_get_dr(ctx, machine, 7)
    cdef unsigned long long mask = <unsigned long long>(0xF << (16 + slot * 4))
    dr7 &= ~mask
    dr7 |= <unsigned long long>(condition << (16 + slot * 4))
    dr7 |= <unsigned long long>(length << (18 + slot * 4))
    dr7 |= <unsigned long long>(1 << (slot * 2))

    pydbg_ctx_set_dr(ctx, machine, 7, dr7)
    pydbg_ctx_set_dr(ctx, machine, 6, 0)

    cdef int set_result
    if machine == 32:
        pydbg_ctx_set_flags(ctx, machine, WOW64_CONTEXT_ALL)
        set_result = Wow64SetThreadContext(<HANDLE><LPVOID>h_thread, ctx)
    else:
        pydbg_ctx_set_flags(ctx, machine, CONTEXT_DEBUG_REGISTERS)
        set_result = SetThreadContext(<HANDLE><LPVOID>h_thread, ctx)
    free(ctx)
    if set_result == 0:
        raise OSError(GetLastError(), "SetThreadContext failed")
    return 0


cpdef int clear_hw_breakpoint(unsigned long long h_thread, int slot, int machine=64) except? -1:
    """Clear a hardware breakpoint.

    Args:
        h_thread: Thread handle.
        slot: Debug register slot (0-3).
        machine: 32 = WOW64 (x86) target, 64 = native x64 target (default).

    Returns:
        0 on success.

    Raises:
        ValueError: Invalid slot.
        OSError: Win32 API failure.
    """
    if slot < 0 or slot > 3:
        raise ValueError(f"slot must be 0-3, got {slot}")

    cdef void* ctx = _get_context(<HANDLE><LPVOID>h_thread, machine)

    pydbg_ctx_set_dr(ctx, machine, slot, 0)

    cdef unsigned long long dr7 = pydbg_ctx_get_dr(ctx, machine, 7)
    cdef unsigned long long mask = <unsigned long long>(0xF << (16 + slot * 4))
    dr7 &= ~mask
    dr7 &= ~<unsigned long long>(1 << (slot * 2))
    pydbg_ctx_set_dr(ctx, machine, 7, dr7)

    cdef int set_result
    if machine == 32:
        pydbg_ctx_set_flags(ctx, machine, WOW64_CONTEXT_ALL)
        set_result = Wow64SetThreadContext(<HANDLE><LPVOID>h_thread, ctx)
    else:
        pydbg_ctx_set_flags(ctx, machine, CONTEXT_DEBUG_REGISTERS)
        set_result = SetThreadContext(<HANDLE><LPVOID>h_thread, ctx)
    free(ctx)
    if set_result == 0:
        raise OSError(GetLastError(), "SetThreadContext failed")
    return 0
