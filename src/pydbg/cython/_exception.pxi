# src/cython/_exception.pyx
"""Exception code constants and parsing helpers."""

from _win32types cimport (
    DWORD, ULONG_PTR, LPVOID,
)

# Exception codes
EXCEPTION_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
EXCEPTION_GUARD_PAGE = 0x80000001
EXCEPTION_ARRAY_BOUNDS_EXCEEDED = 0xC000008C
EXCEPTION_FLT_DENORMAL_OPERAND = 0xC000008D
EXCEPTION_FLT_DIVIDE_BY_ZERO = 0xC000008E
EXCEPTION_FLT_INEXACT_RESULT = 0xC000008F
EXCEPTION_FLT_INVALID_OPERATION = 0xC0000090
EXCEPTION_FLT_OVERFLOW = 0xC0000091
EXCEPTION_FLT_STACK_CHECK = 0xC0000092
EXCEPTION_FLT_UNDERFLOW = 0xC0000093
EXCEPTION_INT_DIVIDE_BY_ZERO = 0xC0000094
EXCEPTION_INT_OVERFLOW = 0xC0000095
EXCEPTION_PRIV_INSTRUCTION = 0xC0000096
EXCEPTION_IN_PAGE_ERROR = 0xC0000006
EXCEPTION_ILLEGAL_INSTRUCTION = 0xC000001D
EXCEPTION_NONCONTINUABLE_EXCEPTION = 0xC0000025
EXCEPTION_STACK_OVERFLOW = 0xC00000FD
EXCEPTION_INVALID_DISPOSITION = 0xC0000026
EXCEPTION_INVALID_HANDLE = 0xC0000008
# WOW64 (32-bit target on 64-bit host): breakpoint/single-step events are
# reported by the WoW64 layer with these WX86 codes instead of the native ones.
STATUS_WX86_BREAKPOINT = 0x4000001F
STATUS_WX86_SINGLE_STEP = 0x4000001E

# Access violation types
EXCEPTION_READ_FAULT = 0
EXCEPTION_WRITE_FAULT = 1
EXCEPTION_EXECUTE_FAULT = 8

_EXCEPTION_NAMES = {
    0xC0000005: "EXCEPTION_ACCESS_VIOLATION",
    0x80000003: "EXCEPTION_BREAKPOINT",
    0x80000004: "EXCEPTION_SINGLE_STEP",
    0x80000001: "EXCEPTION_GUARD_PAGE",
    0xC000008C: "EXCEPTION_ARRAY_BOUNDS_EXCEEDED",
    0xC000008D: "EXCEPTION_FLT_DENORMAL_OPERAND",
    0xC000008E: "EXCEPTION_FLT_DIVIDE_BY_ZERO",
    0xC000008F: "EXCEPTION_FLT_INEXACT_RESULT",
    0xC0000090: "EXCEPTION_FLT_INVALID_OPERATION",
    0xC0000091: "EXCEPTION_FLT_OVERFLOW",
    0xC0000092: "EXCEPTION_FLT_STACK_CHECK",
    0xC0000093: "EXCEPTION_FLT_UNDERFLOW",
    0xC0000094: "EXCEPTION_INT_DIVIDE_BY_ZERO",
    0xC0000095: "EXCEPTION_INT_OVERFLOW",
    0xC0000096: "EXCEPTION_PRIV_INSTRUCTION",
    0xC0000006: "EXCEPTION_IN_PAGE_ERROR",
    0xC000001D: "EXCEPTION_ILLEGAL_INSTRUCTION",
    0xC0000025: "EXCEPTION_NONCONTINUABLE_EXCEPTION",
    0xC00000FD: "EXCEPTION_STACK_OVERFLOW",
    0xC0000026: "EXCEPTION_INVALID_DISPOSITION",
    0xC0000008: "EXCEPTION_INVALID_HANDLE",
    0x4000001F: "STATUS_WX86_BREAKPOINT",
    0x4000001E: "STATUS_WX86_SINGLE_STEP",
}

cpdef str exception_code_to_str(unsigned int code):
    """Convert exception code to human-readable name."""
    cdef str name = _EXCEPTION_NAMES.get(code)
    if name is not None:
        return name
    return f"UNKNOWN_EXCEPTION(0x{code:08X})"

cpdef dict get_exception_info(unsigned int code, unsigned long long addr,
                              unsigned int first_chance,
                              list exception_params):
    """Parse exception data into a structured dict.

    Args:
        code: Exception code.
        addr: Exception address.
        first_chance: 1 if first-chance, 0 if second-chance.
        exception_params: List of exception parameters (ULONG_PTR values).

    Returns:
        dict with parsed exception info.
    """
    cdef dict info = {
        'code': code,
        'name': exception_code_to_str(code),
        'addr': addr,
        'first_chance': bool(first_chance),
    }

    if code == EXCEPTION_ACCESS_VIOLATION and len(exception_params) >= 2:
        access_type = exception_params[0]
        access_addr = exception_params[1]
        if access_type == EXCEPTION_READ_FAULT:
            info['access_type'] = 'read'
        elif access_type == EXCEPTION_WRITE_FAULT:
            info['access_type'] = 'write'
        elif access_type == EXCEPTION_EXECUTE_FAULT:
            info['access_type'] = 'execute'
        else:
            info['access_type'] = f'unknown({access_type})'
        info['access_addr'] = access_addr

    if code == EXCEPTION_IN_PAGE_ERROR and len(exception_params) >= 3:
        info['access_type'] = exception_params[0]
        info['access_addr'] = exception_params[1]
        info['ntstatus'] = exception_params[2]

    return info
