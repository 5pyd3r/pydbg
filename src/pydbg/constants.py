"""Win32 constants as plain values, so importing them needs no extension.

They used to come from `_pydbg` (the Cython module), which meant that even
`from pydbg import EXCEPTION_BREAKPOINT` required a compiled Windows extension.
These are stable ABI numbers from <winnt.h>; the extension defines the same
ones, and the debugger code still reads them from here so both halves agree.
"""

EXCEPTION_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
EXCEPTION_GUARD_PAGE = 0x80000001
# ExceptionInformation[0] for an access violation.
EXCEPTION_READ_FAULT = 0x0
EXCEPTION_WRITE_FAULT = 0x1
EXCEPTION_EXECUTE_FAULT = 0x8
# WOW64 reports 32-bit breakpoints and single-steps under these codes.
STATUS_WX86_BREAKPOINT = 0x4000001F
STATUS_WX86_SINGLE_STEP = 0x4000001E
