# _bp.pyx — Hardware breakpoint management via x64 debug registers

from libc.stdint cimport uint64_t

from _win32types cimport (
    HANDLE, DWORD, BOOL, LPVOID, DWORD64, WORD, CONTEXT,
    GetThreadContext, SetThreadContext, GetLastError,
    CONTEXT_DEBUG_REGISTERS,
)

from libc.string cimport memset

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


cdef CONTEXT _get_context(HANDLE h_thread):
    """Get thread CONTEXT with debug registers."""
    cdef CONTEXT ctx
    memset(&ctx, 0, sizeof(ctx))
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
    if GetThreadContext(h_thread, &ctx) == 0:
        raise OSError(GetLastError(), "GetThreadContext failed")
    return ctx

cpdef int set_hw_breakpoint(unsigned long long h_thread, int slot, uint64_t addr,
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

    cdef CONTEXT ctx = _get_context(<HANDLE><LPVOID>h_thread)

    # Set address register
    if slot == 0:
        ctx.Dr0 = addr
    elif slot == 1:
        ctx.Dr1 = addr
    elif slot == 2:
        ctx.Dr2 = addr
    else:
        ctx.Dr3 = addr

    # Clear existing condition/length for this slot
    cdef uint64_t mask
    mask = <uint64_t>(0xF << (16 + slot * 4))
    ctx.Dr7 &= ~mask

    # Set condition (bits 16-17, 20-21, 24-25, 28-29)
    ctx.Dr7 |= <uint64_t>(condition << (16 + slot * 4))
    # Set length (bits 18-19, 22-23, 26-27, 30-31)
    ctx.Dr7 |= <uint64_t>(length << (18 + slot * 4))

    # Enable local breakpoint (bit 0, 2, 4, 6)
    ctx.Dr7 |= <uint64_t>(1 << (slot * 2))

    # Clear DR6 status bits (they're write-1-to-clear)
    ctx.Dr6 = 0

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
    if SetThreadContext(<HANDLE><LPVOID>h_thread, &ctx) == 0:
        raise OSError(GetLastError(), "SetThreadContext failed")

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

    cdef CONTEXT ctx = _get_context(<HANDLE><LPVOID>h_thread)

    # Clear address register
    if slot == 0:
        ctx.Dr0 = 0
    elif slot == 1:
        ctx.Dr1 = 0
    elif slot == 2:
        ctx.Dr2 = 0
    else:
        ctx.Dr3 = 0

    # Clear condition/length for this slot
    cdef uint64_t mask
    mask = <uint64_t>(0xF << (16 + slot * 4))
    ctx.Dr7 &= ~mask

    # Disable local breakpoint
    ctx.Dr7 &= ~<uint64_t>(1 << (slot * 2))

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
    if SetThreadContext(<HANDLE><LPVOID>h_thread, &ctx) == 0:
        raise OSError(GetLastError(), "SetThreadContext failed")

    return 0
