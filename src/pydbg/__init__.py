"""pydbg — Windows binary analysis toolbox.

This module imports almost nothing on purpose. `import pydbg.analysis` used to
execute `from ._pydbg import ...` before anything else, which made the whole
static-analysis half of the package require a compiled Windows extension — even
the part that only reads a file (ADR-0001).

Everything that needs the extension is resolved on first use through
`__getattr__`, so:

    import pydbg                       # no extension needed
    from pydbg.analysis import analyze_file     # no extension needed
    from pydbg import Debugger         # extension needed, imported here
"""

import struct as _struct

from .constants import (
    EXCEPTION_ACCESS_VIOLATION,
    EXCEPTION_BREAKPOINT,
    EXCEPTION_EXECUTE_FAULT,
    EXCEPTION_GUARD_PAGE,
    EXCEPTION_READ_FAULT,
    EXCEPTION_SINGLE_STEP,
    EXCEPTION_WRITE_FAULT,
    STATUS_WX86_BREAKPOINT,
    STATUS_WX86_SINGLE_STEP,
)
from .exceptions import (
    BreakpointError,
    MemError,
    ProcessError,
    PydbgError,
    TeardownError,
    ThreadError,
    TimeoutError,
)

# The analysis half is pure Python (capstone at most), so it is safe to import
# here; keeping it eager is also what proves the boundary below.
from .analysis import StaticAnalyzer, analyze_bytes, analyze_file, analyze_pe

__version__ = "0.1.0"
HOST_ARCH = _struct.calcsize("P") * 8  # 64 under the x64-only build policy

# name -> module that defines it. Importing any of these pulls in `_pydbg`
# (directly or through the managers), which is exactly what must not happen at
# package import time.
_LAZY = {
    "Debugger": ".core.debugger",
    "DebugEvent": ".core.event",
    "ChildProcessInfo": ".core.session",
    "ExitReason": ".core.status",
    "ExitStatus": ".core.status",
    "enumerate_processes": ".core.process",
    "Windows": ".core.windows",
    "MessageLoopState": ".core.window_probe",
    "WindowInfo": ".core.window_probe",
    "WindowProbe": ".core.window_probe",
    "WindowProbeQuery": ".core.window_probe",
    "MemoryRead": ".memory.manager",
    "DisasmEngine": ".disasm.engine",
    "Instruction": ".disasm.engine",
    "Assembler": ".patch.assembler",
    "SymbolResolver": ".symbol.resolver",
    "IATHook": ".hook.iat",
    "InlineHook": ".hook.inline",
    "Trampoline": ".hook.inline",
    "StepTracer": ".trace.step",
    "CallTree": ".trace.calltree",
    "CallNode": ".trace.calltree",
    "MinidumpReader": ".dump.minidump",
    "StackWalker": ".dump.stackwalk",
    "Instrumenter": ".instrument",
    "InstrumentInfo": ".instrument",
    "InstrumentTemplates": ".instrument",
}


def __getattr__(name):
    """Import a lazily-held name on first use (see _LAZY and ADR-0001)."""
    module_name = _LAZY.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    value = getattr(importlib.import_module(module_name, __name__), name)
    globals()[name] = value          # resolve once; later lookups skip __getattr__
    return value


def __dir__():
    return sorted(set(globals()) | set(_LAZY))


__all__ = [
    "Debugger",
    "HOST_ARCH",
    "ChildProcessInfo",
    "enumerate_processes",
    "ExitReason",
    "ExitStatus",
    "Windows",
    "DebugEvent",
    "MessageLoopState",
    "WindowInfo",
    "WindowProbe",
    "WindowProbeQuery",
    "MemoryRead",
    "StaticAnalyzer",
    "analyze_file",
    "analyze_bytes",
    "analyze_pe",
    "PydbgError",
    "ProcessError",
    "MemError",
    "ThreadError",
    "BreakpointError",
    "TimeoutError",
    "TeardownError",
    "EXCEPTION_ACCESS_VIOLATION",
    "EXCEPTION_BREAKPOINT",
    "EXCEPTION_SINGLE_STEP",
    "EXCEPTION_GUARD_PAGE",
    "EXCEPTION_READ_FAULT",
    "EXCEPTION_WRITE_FAULT",
    "EXCEPTION_EXECUTE_FAULT",
    "STATUS_WX86_BREAKPOINT",
    "STATUS_WX86_SINGLE_STEP",
    "DisasmEngine",
    "Instruction",
    "Assembler",
    "SymbolResolver",
    "IATHook",
    "InlineHook",
    "Trampoline",
    "StepTracer",
    "CallTree",
    "CallNode",
    "MinidumpReader",
    "StackWalker",
    "Instrumenter",
    "InstrumentInfo",
    "InstrumentTemplates",
]
