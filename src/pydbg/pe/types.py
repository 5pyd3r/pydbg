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
