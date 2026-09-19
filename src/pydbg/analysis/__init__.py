"""Static analysis — functions and cross-references, with no process.

pydbg's other layers want a target running: the debugger obviously, and the
disassembler needs someone to hand it bytes. This package is the one that works
from an image on disk, which is what makes bulk analysis possible at all.

    from pydbg.analysis import analyze_file
    result = analyze_file("target.exe")
    result.stats.func_starts
    result.callers_of(0x401000)

Coverage is reported with its overlap, because the two together are the only
honest form: the count of decoded bytes alone reads high whenever the decode
has drifted out of alignment, which is exactly when it should read low.
"""

from .attribution import (
    CoverageAttribution, UncoveredBreakdown, attribute_coverage, deltas,
    span_summary,
)
from .cfg import CFGBlock, FunctionCFG, build_function_cfg, cfg_to_dot
from .consts import ConstantTracker
from .engine import (
    StaticAnalyzer, analyze_bytes, analyze_file, analyze_pe, analyze_process,
)
from .functions import FunctionTable
from .image import AnalyzedImage, SectionInfo
from .model import (
    AnalysisResult, AnalysisStats, CoverageReport, Function, IndirectSite,
    RefKind, SeedConfig, Xref,
)
from .process_source import ProcessSource
from .refs import branch_target, classify_refs, is_indirect_branch, memory_address
from .seeds import SeedProvider, SeedSet, looks_like_entry

__all__ = [
    'StaticAnalyzer', 'analyze_file', 'analyze_bytes', 'analyze_pe',
    'analyze_process',
    'AnalyzedImage', 'SectionInfo', 'ProcessSource',
    'FunctionTable', 'SeedProvider', 'SeedSet', 'looks_like_entry',
    'AnalysisResult', 'AnalysisStats', 'CoverageReport', 'Function',
    'IndirectSite', 'RefKind', 'SeedConfig', 'Xref',
    'FunctionCFG', 'CFGBlock', 'build_function_cfg', 'cfg_to_dot',
    'ConstantTracker',
    'CoverageAttribution', 'UncoveredBreakdown', 'attribute_coverage',
    'deltas', 'span_summary',
    'branch_target', 'classify_refs', 'is_indirect_branch', 'memory_address',
]
