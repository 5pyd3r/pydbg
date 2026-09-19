"""Instruction decoding.

Control flow is not here. This package decodes one instruction at a time;
building a graph out of the results is analysis, and lives in pydbg.analysis —
see analysis/cfg.py for why there is only one answer to "what does this
function's control flow look like" rather than two that disagree.
"""

from .engine import DisasmEngine, Instruction

__all__ = [
    'DisasmEngine',
    'Instruction',
]
