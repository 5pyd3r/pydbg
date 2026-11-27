"""Rebuild a DumpedImage into a file-layout PE, or say why it cannot be one.

`dump/memory.py` collects an RVA-indexed image plus a gap table; `pe/writer.py`
turns a loaded-layout PE into file-layout bytes. This module joins the two: it
parses the dump the way a loaded module must be parsed, refuses the gaps that
would corrupt structure, and assembles the report a caller needs before handing
the bytes to a loader.

Failure semantics (spec §11.4): structural problems raise `RebuildError` and
produce nothing — there is no half-written PE. Degradations that leave the
image parseable only reach `RebuildReport.warnings` and `gaps`. A hole in a
section needs no repair here because `DumpedImage`'s own contract already
zero-filled it; what this module adds is the name of the section it damaged.

The result keeps the source ImageBase. A module that was loaded away from its
preferred base is recorded as `load_delta` and nothing is rewritten:
relocation rewriting is explicitly out of scope (§11.7), so a non-zero delta is
a fact handed to the caller, not something this module repairs.
"""

from dataclasses import dataclass

from ..exceptions import PydbgError
from ..pe import BytesSource, LoadedView, PE, write_pe
from ..pe.parser import DIR_IMPORT
from ..pe.writer import file_layout

# The size of one IMAGE_IMPORT_DESCRIPTOR, for the directory-size fallback.
_IMPORT_DESCRIPTOR_SIZE = 20


class RebuildError(PydbgError):
    """A dump cannot become a PE that this package would parse back.

    Raised for the structural failures: the dumped bytes are not a PE image, a
    gap covers the header that the writer copies verbatim, the writer cannot
    lay the image out, or the `validate=True` read-back fails. Degraded but
    usable images are returned with warnings instead.
    """


@dataclass(frozen=True)
class RebuildReport:
    """What the rebuild kept, recomputed, degraded, or could not resolve.

    'sections_rebuilt' is how many section records were written, and
    'imports' is how many import entries were copied through unchanged (one
    per thunk slot; the report has no descriptor-level count because the read
    model parses descriptors into entries). 'unresolved_imports' holds the IAT
    slot RVAs whose thunk named neither an imported function nor an ordinal.
    'gaps' is the dump's side table, unchanged, so a consumer can tell which
    zero bytes are real and which are holes.
    """

    sections_rebuilt: int
    size_of_image: int
    entry_point: int
    load_delta: int
    imports: int
    unresolved_imports: tuple
    gaps: tuple
    warnings: tuple


@dataclass(frozen=True)
class RebuiltImage:
    """File-layout PE bytes plus the report that qualifies them.

    Nothing is written to disk: the caller decides whether and where the bytes
    become a file, and `PE(data)` is the documented self-check.
    """

    data: bytes
    report: RebuildReport


def rebuild_pe(dumped, *, entry_point=None, validate=True):
    """Rebuild 'dumped' into a file-layout PE, or raise RebuildError.

    'dumped' is a `DumpedImage` whose bytes are RVA-indexed from the module base
    — the shape `dump_module` produces. 'entry_point' overrides the image's own
    AddressOfEntryPoint when given (an OEP candidate, typically).

    'validate=True' re-parses the result with `PE(data)` and turns a failure
    into `RebuildError`, whose message carries the parser's reason; with
    validate=False the bytes are returned even when the read-back fails, the
    report says so in its warnings, and its `size_of_image` still describes the
    file that was written (the shared `file_layout`), not the dump's header.
    """
    try:
        pe = PE.from_source(BytesSource(dumped.data), LoadedView(),
                            va_base=dumped.image_base)
    except (ValueError, OSError) as e:
        raise RebuildError(f"not a PE image: {e}") from e

    size_of_headers = pe.optional_header.size_of_headers
    header_gap = next(
        (gap for gap in dumped.gaps if _overlaps(gap, 0, size_of_headers)),
        None)
    if header_gap is not None:
        raise RebuildError(
            f"gap in header: rva=0x{header_gap.rva:X}, "
            f"size=0x{header_gap.size:X} ({header_gap.reason}); a PE header "
            f"cannot be rebuilt from zero-filled bytes")

    imports = list(pe.imports)
    try:
        # The report's size_of_image and the gap warnings below read the same
        # layout the writer uses, so there is one source for the copy window.
        layout = file_layout(pe)
        warnings = _section_gap_warnings(pe, layout, dumped.gaps)
        import_range = _import_directory_range(pe)
        if import_range is not None and any(
                _overlaps(gap, *import_range) for gap in dumped.gaps):
            warnings.append('imports_unreadable')
        data = write_pe(pe, dumped.data, entry_point=entry_point)
    except ValueError as e:
        raise RebuildError(f"cannot lay out the image: {e}") from e

    rebuilt, parse_error = _parse_file(data)
    if rebuilt is None:
        if validate:
            raise RebuildError(
                f"rebuilt image does not parse back: {parse_error}")
        warnings.append('rebuilt image does not parse back')

    report = RebuildReport(
        sections_rebuilt=len(pe.sections),
        # What was written, from the same calculation the writer used — never
        # the dump's stale header value, which describes the loaded image.
        size_of_image=layout.size_of_image,
        entry_point=(pe.optional_header.entry_point_rva
                     if entry_point is None else int(entry_point)),
        # Already computed against the runtime base by dump_module (P25).
        load_delta=dumped.load_delta,
        imports=len(imports),
        unresolved_imports=tuple(
            imp.rva for imp in imports
            if imp.ordinal is None and not imp.name),
        gaps=tuple(dumped.gaps),
        warnings=tuple(warnings),
    )
    return RebuiltImage(data=data, report=report)


def _parse_file(data):
    """Parse 'data' as a file-layout PE.

    Returns (PE, None) on success and (None, exception) otherwise, so the
    reason the read-back failed can be reported instead of being discarded.
    """
    try:
        return PE(data), None
    except (ValueError, OSError) as exc:
        return None, exc


def _overlaps(gap, start, end):
    """True when 'gap' covers any byte of [start, end)."""
    return gap.size > 0 and gap.rva < end and gap.rva + gap.size > start


def _import_directory_range(pe):
    """The import directory's RVA span, or None when the image has none.

    The descriptor array is what a gap can damage; a directory with size 0
    still names one descriptor slot, which is the smallest range worth
    checking.
    """
    directory = pe.optional_header.data_directories.get(DIR_IMPORT)
    if directory is None or directory.virtual_address == 0:
        return None
    start = directory.virtual_address
    return start, start + (directory.size or _IMPORT_DESCRIPTOR_SIZE)


def _section_gap_warnings(pe, layout, gaps):
    """One "gap in <section>" per section whose copied data has a hole.

    The extent is the layout's: `SectionLayout.size` bytes starting at its
    `virtual_address` are what the writer copies, so a hole outside that
    window is not section corruption and does not get named here. The names
    come from the headers because a layout carries the destination, not the
    identity.
    """
    warnings = []
    for header, section in zip(pe.sections, layout.sections):
        start = section.virtual_address
        if any(_overlaps(gap, start, start + section.size) for gap in gaps):
            warnings.append(f"gap in {header.name}")
    return warnings
