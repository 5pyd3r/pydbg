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

from .access import (
    STACK_REGISTERS, Access, FieldUse, StructureProfile,
    collect_accesses, profiles,
)
from .attribution import (
    CoverageAttribution, UncoveredBreakdown, attribute_coverage, deltas,
    span_summary,
)
from .cfg import CFGBlock, FunctionCFG, build_function_cfg, cfg_to_dot
from .consts import ConstantTracker
from .engine import (
    StaticAnalyzer, analyze_bytes, analyze_file, analyze_pe, analyze_process,
)
from .functions import OWNER_KINDS, FunctionTable
from .image import AnalyzedImage, SectionInfo
from .model import (
    AnalysisResult, AnalysisStats, CoverageReport, Function, IndirectSite,
    RefKind, SeedConfig, SlotTable, Xref,
)
from .owners import (
    DETERMINED_FACTS, BOUNDARY_KINDS, RECEIVER_FACTS, Boundary,
    ReceiverNote, RegionOwnership, boundary_of, classify_range,
    memory_base_registers, receiver_of,
)
from .names import Name, NameTable, auto_names, import_names
from .workspace import Workspace, WorkspaceError, image_fingerprint
from .process_source import ProcessSource
from .refs import branch_target, classify_refs, is_indirect_branch, memory_address
from .scan import (
    LinearScan, Resync, Undecodable, linear_scan, scan_executable, scan_section,
)
from .seeds import SeedProvider, SeedSet, looks_like_entry
from .values import (
    DECIDED, UNDECIDED, Bound, ValueSet, narrow_by_guards,
    unresolved_write_count, value_set_of, writes_to,
)

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
    'Name', 'NameTable', 'auto_names', 'import_names',
    'Access', 'FieldUse', 'StructureProfile', 'collect_accesses',
    'profiles', 'STACK_REGISTERS',
    'Workspace', 'WorkspaceError', 'image_fingerprint',
    'branch_target', 'classify_refs', 'is_indirect_branch', 'memory_address',
    'LinearScan', 'Resync', 'Undecodable', 'linear_scan', 'scan_executable',
    'scan_section',
    'SlotTable', 'OWNER_KINDS',
    'Boundary', 'BOUNDARY_KINDS', 'boundary_of',
    'RegionOwnership', 'classify_range',
    'ReceiverNote', 'RECEIVER_FACTS', 'DETERMINED_FACTS', 'receiver_of',
    'memory_base_registers',
    'Bound', 'ValueSet', 'DECIDED', 'UNDECIDED', 'writes_to', 'value_set_of',
    'narrow_by_guards', 'unresolved_write_count',
]
