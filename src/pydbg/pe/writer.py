"""PE writer — file-layout bytes from an image that was read in loaded layout.

Only one direction is offered, and it is not a re-serialiser. The read model
keeps what analysis needs, not what a linker-emitter needs: DllCharacteristics,
the stack/heap sizes and SizeOfOptionalHeader never reach `OptionalHeader`, so
rebuilding a header from the dataclasses silently zeroes them. This module
therefore copies the image's own header bytes and patches the handful of fields
that relocating the sections actually changes. See docs/analysis-coverage.md
§11.3 for the rule set.

The input is a PE parsed with LoadedView (RVA-indexed image bytes, e.g. a live
module read from process memory). A PE parsed with FileView is already in the
layout this module produces, so passing one is a caller error and is rejected.

`file_layout()` is the one calculation of SizeOfImage, SizeOfHeaders and each
section's file offset; `write_pe()` patches the header with it, and
`dump.rebuild_pe()` reports the same values instead of copying the dump's
header, which describes the loaded image rather than the file just written.
"""

import struct
from dataclasses import dataclass

from .view import LoadedView

# Offsets inside IMAGE_OPTIONAL_HEADER32 *and* IMAGE_OPTIONAL_HEADER64. The two
# layouts diverge at ImageBase, but the four fields patched here sit at the same
# offset in both — which is why one constant set is enough.
_OH_ADDRESS_OF_ENTRY_POINT = 16
_OH_SIZE_OF_IMAGE = 56
_OH_SIZE_OF_HEADERS = 60
_OH_CHECKSUM = 64

# IMAGE_SECTION_HEADER field offsets (the struct is 40 bytes).
_SH_SIZE_OF_RAW_DATA = 16
_SH_POINTER_TO_RAW_DATA = 20
_SH_SIZE = 40

# IMAGE_FILE_HEADER: 20 bytes, SizeOfOptionalHeader 16 bytes in.
_FH_SIZE = 20
_FH_SIZE_OF_OPTIONAL_HEADER = 16


def _align(value, alignment):
    """Round 'value' up to the next multiple of 'alignment'."""
    return (value + alignment - 1) // alignment * alignment


@dataclass(frozen=True)
class SectionLayout:
    """Where one section's bytes go in the file-layout image.

    'size' is how many bytes are copied out of the loaded image; 'raw_size' is
    that rounded up to FileAlignment, and 'raw_pointer' is where they land.
    """

    raw_pointer: int
    raw_size: int
    virtual_address: int
    size: int


@dataclass(frozen=True)
class FileLayout:
    """The file-layout decisions for one loaded image.

    'sections' holds one `SectionLayout` per section, in section-table order.
    'sections_offset' is where the section table sits inside the header copy,
    which the writer needs in order to patch each section's raw fields.
    """

    size_of_image: int
    size_of_headers: int
    sections: tuple[SectionLayout, ...]
    sections_offset: int


def file_layout(pe):
    """Compute the file layout for a loaded-layout 'pe'.

    Every size here is derived from the image's own section table: SizeOfImage
    is the SectionAlignment boundary covering the mapped sections, SizeOfHeaders
    is FileAlignment-aligned and never smaller than the section table, and raw
    offsets start just past the headers and grow by each aligned section size.
    `virtual_size` is the trustworthy extent of a loaded image — its
    `size_of_raw_data` describes the file it came from, not the memory image.

    Raises:
        ValueError: 'pe' was not parsed with LoadedView, or its alignments or
            header are unusable.
    """
    if not isinstance(pe.view, LoadedView):
        raise ValueError(
            "file_layout needs a PE parsed with LoadedView (RVA-indexed image "
            f"bytes), not {type(pe.view).__name__}")

    optional = pe.optional_header
    file_align = optional.file_alignment
    section_align = optional.section_alignment
    if file_align <= 0 or section_align <= 0:
        raise ValueError(
            f"invalid alignment: FileAlignment={file_align:#x}, "
            f"SectionAlignment={section_align:#x}")

    # The fixed part of the file header locates the section table:
    # SizeOfOptionalHeader lives there, not in the parsed model.
    e_lfanew = pe.dos_header.e_lfanew
    optional_offset = e_lfanew + 4 + _FH_SIZE
    file_header_bytes = pe.source.try_read(0, optional_offset)
    if file_header_bytes is None:
        raise ValueError("PE header is unreadable")
    size_of_optional_header = struct.unpack_from(
        "<H", file_header_bytes,
        e_lfanew + 4 + _FH_SIZE_OF_OPTIONAL_HEADER)[0]
    sections_offset = optional_offset + size_of_optional_header

    # SizeOfHeaders has to cover the section table and stay FileAlignment
    # aligned; never shrink it, because the original header bytes live there.
    table_end = sections_offset + pe.file_header.number_of_sections * _SH_SIZE
    size_of_headers = max(optional.size_of_headers,
                          _align(table_end, file_align))

    # SizeOfImage covers every section's *virtual* extent plus the headers;
    # rebuilding can drop it below the source's hard-coded value.
    image_end = max([section.virtual_address + section.span
                     for section in pe.sections] + [size_of_headers])
    size_of_image = _align(image_end, section_align)

    # Lay the sections out at file offsets, aligned and strictly increasing.
    sections = []
    raw_pointer = _align(size_of_headers, file_align)
    for section in pe.sections:
        size = section.virtual_size or section.span
        raw_size = _align(size, file_align)
        sections.append(SectionLayout(
            raw_pointer=raw_pointer,
            raw_size=raw_size,
            virtual_address=section.virtual_address,
            size=size))
        raw_pointer += raw_size or file_align

    return FileLayout(
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
        sections=tuple(sections),
        sections_offset=sections_offset,
    )


def write_pe(pe, image_bytes, *, entry_point=None):
    """Write 'pe' and its image bytes out as a file-layout PE.

    'pe' must be a PE parsed with LoadedView over 'image_bytes' (or an
    identical buffer); its header supplies everything that is not recomputed.
    'image_bytes' is indexed by RVA and must cover the image's sections — a
    short buffer is zero-filled rather than rejected, because a dump of a
    partially unreadable module is still worth rebuilding. 'entry_point'
    overrides AddressOfEntryPoint when given.

    Returns the new image; the 'pe' object is not modified.
    """
    layout = file_layout(pe)

    e_lfanew = pe.dos_header.e_lfanew
    optional_offset = e_lfanew + 4 + _FH_SIZE

    # A header that under-declares SizeOfHeaders is still parseable (the
    # section table is read past it), so fall back to the table extent rather
    # than zeroing every section's name and characteristics.
    table_end = layout.sections_offset + pe.file_header.number_of_sections * _SH_SIZE
    raw_header = pe.source.try_read(0, layout.size_of_headers)
    if raw_header is None:
        raw_header = pe.source.try_read(0, table_end)
    if raw_header is None:
        raise ValueError("PE header is unreadable")

    header = bytearray(raw_header.ljust(layout.size_of_headers, b"\x00"))
    struct.pack_into("<I", header, optional_offset + _OH_SIZE_OF_IMAGE,
                     layout.size_of_image)
    struct.pack_into("<I", header, optional_offset + _OH_SIZE_OF_HEADERS,
                     layout.size_of_headers)
    # The source checksum describes bytes this rewrite invalidates, and the spec
    # scopes checksum *computation* out: zero says "not verified", which is
    # honest, while a stale value is a lie.
    struct.pack_into("<I", header, optional_offset + _OH_CHECKSUM, 0)
    if entry_point is not None:
        struct.pack_into("<I", header,
                         optional_offset + _OH_ADDRESS_OF_ENTRY_POINT,
                         entry_point)

    for index, section in enumerate(layout.sections):
        struct.pack_into(
            "<II", header,
            layout.sections_offset + index * _SH_SIZE + _SH_SIZE_OF_RAW_DATA,
            section.raw_size, section.raw_pointer)

    output = bytearray(header)
    for section in layout.sections:
        if len(output) < section.raw_pointer:
            output.extend(b"\x00" * (section.raw_pointer - len(output)))
        output.extend(image_bytes[
            section.virtual_address:section.virtual_address + section.size])
        output.extend(b"\x00" * (
            section.raw_pointer + section.raw_size - len(output)))
    return bytes(output)
