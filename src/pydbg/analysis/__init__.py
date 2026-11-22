"""Static analysis — functions and cross-references, with no process.

pydbg's other layers want a target running: the debugger obviously, and the
disassembler needs someone to hand it bytes. This package is the one that works
from an image on disk, which is what makes bulk analysis possible at all —
and it must stay importable without the Windows extension (ADR-0001).

    from pydbg.analysis import analyze_file
    result = analyze_file("target.exe")
    result.stats.func_starts
    result.callers_of(0x401000)

`analyze_process` is the one entry point that wants a live session; it reaches
the debugger through ProcessSource, whose MemoryManager import is lazy, so the
rest of the package never touches it.

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
from .cfg import (
    CFGBlock, FunctionCFG, build_function_cfg, cfg_of, cfg_to_dot,
)
from .consts import ConstantTracker
from .engine import (
    StaticAnalyzer, analyze_bytes, analyze_file, analyze_pe, analyze_process,
)
from .functions import FunctionTable
from .image import AnalyzedImage
from .model import (
    AnalysisResult, AnalysisStats, CoverageReport, Function, IndirectSite,
    OWNER_KINDS, OWNED_KINDS, RefKind, SeedConfig, SlotTable, Xref,
)
from .owners import (
    DETERMINED_FACTS, BOUNDARY_KINDS, RECEIVER_FACTS, Boundary,
    ReceiverNote, RegionOwnership, boundary_of, classify_range, container_of,
    function_of, memory_base_registers, receiver_of,
)
from .names import (
    SOURCE_PDB, Name, NameTable, auto_names, import_names, resolve_for,
)
from .types import (
    Field, FieldReport, StructLayout, field_report, layout_of, structs,
)
from .workspace import Workspace, WorkspaceError, image_fingerprint
from .process_source import ProcessSource
from .refs import (
    branch_target, call_graph_is_complete, classify_refs, indirect_call_sites,
    is_indirect_branch, memory_address, ref_kinds, xrefs_are_complete,
)
from .scan import (
    LinearScan, Resync, Undecodable, linear_scan, scan_executable, scan_section,
)
from .seeds import SeedProvider, SeedSet, looks_like_entry
from .strings import (
    FoundString, PackingHints, SectionEntropy, extract_strings, packing_hints,
    section_entropy, strings_in_bytes,
)
from .values import (
    DECIDED, UNDECIDED, Bound, ValueSet, narrow_by_guards,
    unresolved_write_count, value_set_of, writes_to,
)
from .decompile import DecompiledFunction, decompile_function

__all__ = [
    'StaticAnalyzer', 'analyze_file', 'analyze_bytes', 'analyze_pe',
    'analyze_process',
    'AnalyzedImage', 'ProcessSource',
    'FunctionTable', 'SeedProvider', 'SeedSet', 'looks_like_entry',
    'AnalysisResult', 'AnalysisStats', 'CoverageReport', 'Function',
    'IndirectSite', 'RefKind', 'SeedConfig', 'Xref',
    'FunctionCFG', 'CFGBlock', 'build_function_cfg', 'cfg_of', 'cfg_to_dot',
    'ConstantTracker',
    'CoverageAttribution', 'UncoveredBreakdown', 'attribute_coverage',
    'deltas', 'span_summary',
    'Name', 'NameTable', 'SOURCE_PDB', 'auto_names', 'import_names',
    'resolve_for',
    'Access', 'FieldUse', 'StructureProfile', 'collect_accesses',
    'profiles', 'STACK_REGISTERS',
    'Workspace', 'WorkspaceError', 'image_fingerprint',
    'branch_target', 'classify_refs', 'is_indirect_branch', 'memory_address',
    'call_graph_is_complete', 'indirect_call_sites', 'ref_kinds',
    'xrefs_are_complete',
    'LinearScan', 'Resync', 'Undecodable', 'linear_scan', 'scan_executable',
    'scan_section',
    'FoundString', 'SectionEntropy', 'PackingHints', 'strings_in_bytes',
    'section_entropy', 'packing_hints', 'extract_strings',
    'SlotTable', 'OWNER_KINDS', 'OWNED_KINDS',
    'Boundary', 'BOUNDARY_KINDS', 'boundary_of',
    'RegionOwnership', 'classify_range', 'container_of', 'function_of',
    'ReceiverNote', 'RECEIVER_FACTS', 'DETERMINED_FACTS', 'receiver_of',
    'memory_base_registers',
    'Bound', 'ValueSet', 'DECIDED', 'UNDECIDED', 'writes_to', 'value_set_of',
    'narrow_by_guards', 'unresolved_write_count',
    'DecompiledFunction', 'decompile_function',
    'Field', 'FieldReport', 'StructLayout', 'field_report', 'layout_of',
    'structs',
]
