# _bp.pyx — Hardware breakpoint management via debug registers

from libc.stdlib cimport malloc, free

from _win32types cimport (
    HANDLE, DWORD, BOOL, LPVOID,
    GetThreadContext, SetThreadContext, GetLastError,
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


cdef void* _get_context(HANDLE h_thread):
    """Get thread CONTEXT with debug registers. Caller must free()."""
    cdef int ctx_size = pydbg_ctx_sizeof()
    cdef void* ctx = malloc(ctx_size)
    if ctx == NULL:
        raise MemoryError("Failed to allocate CONTEXT")
    pydbg_ctx_init(ctx, CONTEXT_DEBUG_REGISTERS)
    if GetThreadContext(h_thread, ctx) == 0:
        free(ctx)
        raise OSError(GetLastError(), "GetThreadContext failed")
    return ctx

cpdef int set_hw_breakpoint(unsigned long long h_thread, int slot, unsigned long long addr,
                             int condition, int length) except? -1:
    """Set a hardware breakpoint.

    Args:
        h_thread: Thread handle.
        slot: Debug register slot (0-3).
        addr: Breakpoint address.
        condition: 0=execute, 1=write, 3=read/write.
        length: 0=1 byte, 1=2 bytes, 3=4 bytes, 2=8 bytes.

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

    cdef void* ctx = _get_context(<HANDLE><LPVOID>h_thread)

    # Set address register
    pydbg_ctx_set_dr(ctx, slot, addr)

    # Read current Dr7, modify, write back
    cdef unsigned long long dr7 = pydbg_ctx_get_dr(ctx, 7)

    # Clear existing condition/length for this slot
    cdef unsigned long long mask = <unsigned long long>(0xF << (16 + slot * 4))
    dr7 &= ~mask

    # Set condition (bits 16-17, 20-21, 24-25, 28-29)
    dr7 |= <unsigned long long>(condition << (16 + slot * 4))
    # Set length (bits 18-19, 22-23, 26-27, 30-31)
    dr7 |= <unsigned long long>(length << (18 + slot * 4))

    # Enable local breakpoint (bit 0, 2, 4, 6)
    dr7 |= <unsigned long long>(1 << (slot * 2))

    pydbg_ctx_set_dr(ctx, 7, dr7)

    # Clear DR6 status bits (they're write-1-to-clear)
    pydbg_ctx_set_dr(ctx, 6, 0)

    pydbg_ctx_set_flags(ctx, CONTEXT_DEBUG_REGISTERS)
    if SetThreadContext(<HANDLE><LPVOID>h_thread, ctx) == 0:
        free(ctx)
        raise OSError(GetLastError(), "SetThreadContext failed")

    free(ctx)
    return 0


cpdef int clear_hw_breakpoint(unsigned long long h_thread, int slot) except? -1:
    """Clear a hardware breakpoint.

    Args:
        h_thread: Thread handle.
        slot: Debug register slot (0-3).

    Returns:
        0 on success.

    Raises:
        ValueError: Invalid slot.
        OSError: Win32 API failure.
    """
    if slot < 0 or slot > 3:
        raise ValueError(f"slot must be 0-3, got {slot}")

    cdef void* ctx = _get_context(<HANDLE><LPVOID>h_thread)

    # Clear address register
    pydbg_ctx_set_dr(ctx, slot, 0)

    # Read current Dr7, modify, write back
    cdef unsigned long long dr7 = pydbg_ctx_get_dr(ctx, 7)

    # Clear condition/length for this slot
    cdef unsigned long long mask = <unsigned long long>(0xF << (16 + slot * 4))
    dr7 &= ~mask

    # Disable local breakpoint
    dr7 &= ~<unsigned long long>(1 << (slot * 2))

    pydbg_ctx_set_dr(ctx, 7, dr7)

    pydbg_ctx_set_flags(ctx, CONTEXT_DEBUG_REGISTERS)
    if SetThreadContext(<HANDLE><LPVOID>h_thread, ctx) == 0:
        free(ctx)
        raise OSError(GetLastError(), "SetThreadContext failed")

    free(ctx)
    return 0
