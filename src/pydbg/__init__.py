import struct as _struct

from ._pydbg import (
    EXCEPTION_ACCESS_VIOLATION,
    EXCEPTION_BREAKPOINT,
    EXCEPTION_EXECUTE_FAULT,
    EXCEPTION_GUARD_PAGE,
    EXCEPTION_READ_FAULT,
    EXCEPTION_SINGLE_STEP,
    EXCEPTION_WRITE_FAULT,
)
from .core.debugger import Debugger
from .disasm.analysis import BasicBlock, CFGEdge, ControlFlowGraph, build_blocks, build_cfg
from .disasm.engine import DisasmEngine, Instruction
from .dump.minidump import MinidumpReader
from .dump.stackwalk import StackWalker
from .hook.iat import IATHook
from .hook.inline import InlineHook, Trampoline
from .trace.step import StepTracer
from .symbol.resolver import SymbolResolver
from .trace.calltree import CallTree, CallNode
from .patch.assembler import Assembler
from .core.session import ChildProcessInfo
from .core.event import DebugEvent
from .stealth.anti_aware import AntiAware
from .intercept.api_hook import APIInterceptor, APICall
from .intercept.call_graph import CallGraphBuilder, CallEdge
from .intercept.presets import load_preset as load_api_preset
from .intercept.presets.ddraw import DDRAW_VTABLE_METHODS, decode_hresult
from .resource.pe_resource import PEResourceParser, ResourceEntry
from .resource.recognizer import ResourceRecognizer
from .trace.execution import ExecutionTracer, TraceEvent
from .trace.dataflow import DataFlowTracker
from .analysis.workbench import AnalysisWorkbench
from .analysis.game_analyzer import GameAnalyzer
from .exceptions import (
    BreakpointError,
    MemError,
    ProcessError,
    PydbgError,
    ThreadError,
    TimeoutError,
)

__version__ = "0.1.0"
HOST_ARCH = _struct.calcsize("P") * 8  # 32 or 64

__all__ = [
    "Debugger",
    "HOST_ARCH",
    "ChildProcessInfo",
    "DebugEvent",
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
    "DisasmEngine",
    "Instruction",
    "BasicBlock",
    "ControlFlowGraph",
    "CFGEdge",
    "build_blocks",
    "build_cfg",
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
    "AntiAware",
    "APIInterceptor", "APICall",
    "CallGraphBuilder", "CallEdge",
    "load_api_preset",
    "DDRAW_VTABLE_METHODS", "decode_hresult",
    "PEResourceParser", "ResourceEntry",
    "ResourceRecognizer",
    "ExecutionTracer", "TraceEvent",
    "DataFlowTracker",
    "AnalysisWorkbench", "GameAnalyzer",
]
