"""PE format dataclass types."""

from dataclasses import dataclass


@dataclass
class DosHeader:
    e_magic: int        # 0x5A4D = "MZ"
    e_lfanew: int       # Offset to PE signature


@dataclass
class FileHeader:
    machine: int              # 0x14C = i386, 0x8664 = AMD64
    time_date_stamp: int
    number_of_sections: int
    characteristics: int


@dataclass
class OptionalHeader:
    magic: int               # 0x10B = PE32, 0x20B = PE32+
    major_linker_version: int
    minor_linker_version: int
    size_of_code: int
    entry_point_rva: int
    base_of_code: int
    image_base: int
    section_alignment: int
    file_alignment: int
    size_of_image: int
    size_of_headers: int
    checksum: int
    subsystem: int
    number_of_rva_and_sizes: int
    data_directories: dict     # index -> DataDirectory


@dataclass
class DataDirectory:
    virtual_address: int
    size: int


@dataclass
class SectionHeader:
    name: str
    virtual_size: int
    virtual_address: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    characteristics: int


@dataclass
class ExportEntry:
    name: str | None     # None if exported by ordinal only
    ordinal: int
    rva: int
    forwarder: str | None  # DLLName.ProcName if forwarded, None otherwise


@dataclass
class ImportEntry:
    dll_name: str
    name: str | None     # None if imported by ordinal only
    ordinal: int | None  # None if imported by name
    rva: int             # RVA of the IAT entry (thunk)


@dataclass
class RelocationEntry:
    """One IMAGE_REL_BASED_* fixup within a relocation block."""

    kind: int            # high nibble of the word: 3 = HIGHLOW, 10 = DIR64
    offset: int          # low 12 bits: offset within the page


@dataclass
class RelocationBlock:
    """A 4KB page's worth of fixups.

    Deliberately structure only — the parser does not dereference the slots.
    Reading a slot's value needs the image's pointer width and the base the
    VAs are relative to, both of which belong to whoever is interpreting the
    relocations, not to the format parser. Keeping that split is what makes
    the 32-bit HIGHLOW / 64-bit DIR64 difference a single decision in one
    place instead of two.
    """

    page_rva: int
    block_size: int
    entries: list        # list[RelocationEntry]


@dataclass
class TLSDirectory:
    """IMAGE_TLS_DIRECTORY. Addresses are VAs as stored in the image."""

    start_address_of_raw_data: int
    end_address_of_raw_data: int
    address_of_index: int
    address_of_callbacks: int
    size_of_zero_fill: int
    characteristics: int
    callbacks: list      # list[int], raw VAs; empty when there is no array


@dataclass
class DebugEntry:
    """One IMAGE_DEBUG_DIRECTORY record (data directory 6)."""

    characteristics: int
    time_date_stamp: int
    major_version: int
    minor_version: int
    type: int            # 2 = IMAGE_DEBUG_TYPE_CODEVIEW (holds the PDB path)
    size_of_data: int
    address_of_raw_data: int
    pointer_to_raw_data: int


@dataclass
class ExceptionEntry:
    """One RUNTIME_FUNCTION from the exception directory (data directory 3).

    On x64 this is the loader's own function table: an authoritative
    [begin, end) range per function, which no prologue heuristic matches.
    """

    begin_rva: int
    end_rva: int
    unwind_info_rva: int


@dataclass
class RichHeaderEntry:
    """One (tool, build) pair from the Rich header."""

    comp_id: int
    count: int


@dataclass
class RichHeader:
    """Decoded Rich header — the toolchain fingerprint MSVC leaves behind."""

    xor_key: int
    entries: list        # list[RichHeaderEntry]
