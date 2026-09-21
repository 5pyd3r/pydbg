import struct as _struct

from ._pydbg import (
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
from .core.debugger import Debugger
from .disasm.engine import DisasmEngine, Instruction
from .dump.minidump import MinidumpReader
from .dump.stackwalk import StackWalker
from .hook.iat import IATHook
from .hook.inline import InlineHook, Trampoline
from .instrument import Instrumenter, InstrumentInfo, InstrumentTemplates
from .trace.step import StepTracer
from .symbol.resolver import SymbolResolver
from .trace.calltree import CallTree, CallNode
from .patch.assembler import Assembler
from .core.session import ChildProcessInfo
from .core.event import DebugEvent
from .core.window_probe import (
    MessageLoopState, WindowInfo, WindowProbe, WindowProbeQuery,
)
from .memory.manager import MemoryRead
from .analysis import StaticAnalyzer, analyze_bytes, analyze_file, analyze_pe
from .exceptions import (
    BreakpointError,
    MemError,
    ProcessError,
    PydbgError,
    ThreadError,
    TimeoutError,
)

__version__ = "0.1.0"
HOST_ARCH = _struct.calcsize("P") * 8  # 64 under the x64-only build policy

__all__ = [
    "Debugger",
    "HOST_ARCH",
    "ChildProcessInfo",
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
