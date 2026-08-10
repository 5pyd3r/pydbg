"""pydbg instrumentation module — hardcoded stubs + LLVM dynamic codegen."""

from .instrumenter import Instrumenter, InstrumentInfo
from .templates import InstrumentTemplates

__all__ = ['Instrumenter', 'InstrumentInfo', 'InstrumentTemplates']
