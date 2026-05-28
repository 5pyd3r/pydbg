"""PE (Portable Executable) format parser.

Parses PE32 and PE32+ binaries from raw bytes. No external dependencies.
"""

import struct
from dataclasses import dataclass


@dataclass
class DosHeader:
    e_magic: int  # 0x5A4D = "MZ"
    e_lfanew: int  # Offset to PE signature


@dataclass
class FileHeader:
    machine: int  # 0x14C = i386, 0x8664 = AMD64
    time_date_stamp: int
    number_of_sections: int
    characteristics: int


@dataclass
class OptionalHeader:
    magic: int  # 0x10B = PE32, 0x20B = PE32+
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
    data_directories: dict  # index -> DataDirectory


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
    name: str | None  # None if exported by ordinal only
    ordinal: int
    rva: int
    forwarder: str | None  # DLLName.ProcName if forwarded, None otherwise


@dataclass
class ImportEntry:
    dll_name: str
    name: str | None  # None if imported by ordinal only
    ordinal: int | None  # None if imported by name
    rva: int  # RVA of the IAT entry (thunk)


class PE:
    """PE format parser. Takes raw bytes and parses headers, sections, exports, imports."""

    def __init__(self, data: bytes):
        self._data = data
        self.dos_header = None
        self.file_header = None
        self.optional_header = None
        self.sections = []
        self.exports = []
        self.imports = []
        self._parse()

    def _parse(self):
        self._parse_dos_header()
        self._parse_nt_headers()
        self._parse_exports()
        self._parse_imports()

    def _parse_dos_header(self):
        if len(self._data) < 64:
            raise ValueError("Data too short for DOS header")
        magic = struct.unpack_from("<2s", self._data, 0)[0]
        if magic != b"MZ":
            raise ValueError(f"Invalid DOS signature: {magic!r}")
        e_lfanew = struct.unpack_from("<I", self._data, 0x3C)[0]
        self.dos_header = DosHeader(e_magic=0x5A4D, e_lfanew=e_lfanew)

    def _parse_nt_headers(self):
        e_lfanew = self.dos_header.e_lfanew
        if e_lfanew + 24 > len(self._data):
            raise ValueError("Data too short for NT headers")

        # PE signature
        sig = struct.unpack_from("<I", self._data, e_lfanew)[0]
        if sig != 0x00004550:
            raise ValueError(f"Invalid PE signature: 0x{sig:08X}")

        # IMAGE_FILE_HEADER (20 bytes after signature)
        offset = e_lfanew + 4
        machine, num_sections, ts, _, _, opt_hdr_size, chars = struct.unpack_from(
            "<HHIIIHH", self._data, offset
        )
        self.file_header = FileHeader(
            machine=machine,
            time_date_stamp=ts,
            number_of_sections=num_sections,
            characteristics=chars,
        )

        # IMAGE_OPTIONAL_HEADER
        offset += 20
        self._opt_hdr_size = opt_hdr_size
        magic = struct.unpack_from("<H", self._data, offset)[0]

        if magic == 0x20B:  # PE32+
            self._parse_optional_header_64(offset, num_sections, opt_hdr_size)
        elif magic == 0x10B:  # PE32
            self._parse_optional_header_32(offset, num_sections, opt_hdr_size)
        else:
            raise ValueError(f"Unknown optional header magic: 0x{magic:04X}")

    def _parse_optional_header_64(self, offset, num_sections, opt_hdr_size):
        # PE32+ static fields end at offset 112 (108 + 4 for NumberOfRvaAndSizes)
        # offset 108 = NumberOfRvaAndSizes, offset 112 = data directories start
        static_end = offset + 112
        if static_end > len(self._data):
            raise ValueError("Data too short for PE32+ optional header")

        fields = struct.unpack_from(
            "<HBBIIIIIQIIHHHHHHI III HH QQQQ II", self._data, offset
        )
        num_rva = struct.unpack_from("<I", self._data, offset + 108)[0]

        # Data directories
        data_dirs_offset = offset + 112  # PE32+ static fields = 112 bytes
        data_dirs = {}
        for i in range(min(num_rva, 16)):
            dd_offset = data_dirs_offset + i * 8
            if dd_offset + 8 > len(self._data):
                break
            rva, size = struct.unpack_from("<II", self._data, dd_offset)
            data_dirs[i] = DataDirectory(virtual_address=rva, size=size)

        self.optional_header = OptionalHeader(
            magic=fields[0],
            major_linker_version=fields[1],
            minor_linker_version=fields[2],
            size_of_code=fields[3],
            entry_point_rva=fields[6],
            base_of_code=fields[7],
            image_base=fields[8],
            section_alignment=fields[9],
            file_alignment=fields[10],
            size_of_image=fields[18],
            size_of_headers=fields[19],
            checksum=fields[20],
            subsystem=fields[21],
            number_of_rva_and_sizes=num_rva,
            data_directories=data_dirs,
        )

        # Parse sections
        sections_offset = data_dirs_offset + num_rva * 8
        self._parse_sections(sections_offset, num_sections)

    def _parse_optional_header_32(self, offset, num_sections, opt_hdr_size):
        if offset + 96 > len(self._data):
            raise ValueError("Data too short for PE32 optional header")

        # PE32 optional header: 96 bytes
        # 0:H 2:B 3:B 4:I 8:I 12:I 16:I 20:I 24:I 28:I 32:I 36:I
        # 40:H 42:H 44:H 46:H 48:H 50:H
        # 52:I 56:I 60:I 64:I 68:H 70:H 72:I 76:I 80:I 84:I 88:I 92:I
        fields = struct.unpack_from(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII", self._data, offset
        )
        num_rva = struct.unpack_from("<I", self._data, offset + 92)[0]

        # Data directories
        data_dirs_offset = offset + 96
        data_dirs = {}
        for i in range(min(num_rva, 16)):
            dd_offset = data_dirs_offset + i * 8
            if dd_offset + 8 > len(self._data):
                break
            rva, size = struct.unpack_from("<II", self._data, dd_offset)
            data_dirs[i] = DataDirectory(virtual_address=rva, size=size)

        self.optional_header = OptionalHeader(
            magic=fields[0],
            major_linker_version=fields[1],
            minor_linker_version=fields[2],
            size_of_code=fields[3],
            entry_point_rva=fields[6],
            base_of_code=fields[7],
            image_base=fields[9],
            section_alignment=fields[10],
            file_alignment=fields[11],
            size_of_image=struct.unpack_from("<I", self._data, offset + 56)[0],
            size_of_headers=struct.unpack_from("<I", self._data, offset + 60)[0],
            checksum=struct.unpack_from("<I", self._data, offset + 64)[0],
            subsystem=struct.unpack_from("<H", self._data, offset + 68)[0],
            number_of_rva_and_sizes=num_rva,
            data_directories=data_dirs,
        )

        # Parse sections
        sections_offset = data_dirs_offset + num_rva * 8
        self._parse_sections(sections_offset, num_sections)

    def _parse_sections(self, offset, count):
        self.sections = []
        for i in range(count):
            sec_offset = offset + i * 40
            if sec_offset + 40 > len(self._data):
                raise ValueError(f"Data too short for section header {i}")
            raw_name = struct.unpack_from("<8s", self._data, sec_offset)[0]
            name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace")
            vs, va, rs, rp, _, _, _, _, chars = struct.unpack_from(
                "<IIIIIIHHI", self._data, sec_offset + 8
            )
            self.sections.append(
                SectionHeader(
                    name=name,
                    virtual_size=vs,
                    virtual_address=va,
                    size_of_raw_data=rs,
                    pointer_to_raw_data=rp,
                    characteristics=chars,
                )
            )

    def rva_to_offset(self, rva):
        """Convert RVA to file offset using section headers.

        Returns file offset (int), or None if RVA is outside all sections.
        """
        for section in self.sections:
            if (
                section.virtual_address
                <= rva
                < section.virtual_address + section.virtual_size
            ):
                return rva - section.virtual_address + section.pointer_to_raw_data
        return None

    def _read_string_at_offset(self, offset):
        """Read a null-terminated ASCII string from _data at the given offset."""
        end = self._data.find(b"\x00", offset)
        if end == -1:
            end = len(self._data)
        return self._data[offset:end].decode("ascii", errors="replace")

    def _parse_exports(self):
        self.exports = []
        if 0 not in self.optional_header.data_directories:
            return
        dd = self.optional_header.data_directories[0]
        if dd.virtual_address == 0 or dd.size == 0:
            return

        offset = self.rva_to_offset(dd.virtual_address)
        if offset is None or offset + 40 > len(self._data):
            return

        fields = struct.unpack_from("<IIHHIIIIIII", self._data, offset)
        base = fields[5]
        num_funcs = fields[6]
        num_names = fields[7]
        func_table_rva = fields[8]
        name_table_rva = fields[9]
        ordinal_table_rva = fields[10]

        # Read function addresses
        func_offsets = []
        func_table_offset = self.rva_to_offset(func_table_rva)
        if func_table_offset is None:
            return
        for i in range(num_funcs):
            off = func_table_offset + i * 4
            if off + 4 > len(self._data):
                break
            func_offsets.append(struct.unpack_from("<I", self._data, off)[0])

        # Read name-to-ordinal mapping
        name_to_ordinal = {}
        name_table_offset = self.rva_to_offset(name_table_rva)
        ordinal_table_offset = self.rva_to_offset(ordinal_table_rva)
        if name_table_offset is not None and ordinal_table_offset is not None:
            for i in range(num_names):
                name_off = name_table_offset + i * 4
                ord_off = ordinal_table_offset + i * 2
                if name_off + 4 > len(self._data) or ord_off + 2 > len(self._data):
                    break
                name_rva = struct.unpack_from("<I", self._data, name_off)[0]
                ordinal = struct.unpack_from("<H", self._data, ord_off)[0]
                name_offset = self.rva_to_offset(name_rva)
                if name_offset is not None:
                    name = self._read_string_at_offset(name_offset)
                    name_to_ordinal[ordinal] = name

        # Determine export directory range for forwarder detection
        export_dir_rva = dd.virtual_address
        export_dir_end = export_dir_rva + dd.size

        # Build export entries
        for i in range(len(func_offsets)):
            func_rva = func_offsets[i]
            name = name_to_ordinal.get(i)
            forwarder = None
            if export_dir_rva <= func_rva < export_dir_end:
                # Forwarder: RVA points to a string inside the export directory
                fwd_offset = self.rva_to_offset(func_rva)
                if fwd_offset is not None:
                    forwarder = self._read_string_at_offset(fwd_offset)
            self.exports.append(
                ExportEntry(
                    name=name,
                    ordinal=i + base,
                    rva=func_rva,
                    forwarder=forwarder,
                )
            )

    def _parse_imports(self):
        self.imports = []
        if 1 not in self.optional_header.data_directories:
            return
        dd = self.optional_header.data_directories[1]
        if dd.virtual_address == 0 or dd.size == 0:
            return

        offset = self.rva_to_offset(dd.virtual_address)
        if offset is None:
            return

        # Read IMAGE_IMPORT_DESCRIPTOR entries (20 bytes each, null-terminated)
        while offset + 20 <= len(self._data):
            ilt_rva, _, _, name_rva, iat_rva = struct.unpack_from(
                "<IIIII", self._data, offset
            )
            if ilt_rva == 0 and name_rva == 0 and iat_rva == 0:
                break  # null terminator

            # Read DLL name
            name_offset = self.rva_to_offset(name_rva)
            dll_name = ""
            if name_offset is not None:
                dll_name = self._read_string_at_offset(name_offset)

            # Read ILT entries (thunks)
            thunk_rva = ilt_rva  # OriginalFirstThunk
            if thunk_rva == 0:
                thunk_rva = iat_rva  # fallback to FirstThunk

            thunk_offset = self.rva_to_offset(thunk_rva)
            if thunk_offset is not None:
                is_pe32plus = self.optional_header.magic == 0x20B
                thunk_size = 8 if is_pe32plus else 4
                ordinal_flag = 0x8000000000000000 if is_pe32plus else 0x80000000

                while thunk_offset + thunk_size <= len(self._data):
                    if is_pe32plus:
                        thunk = struct.unpack_from("<Q", self._data, thunk_offset)[0]
                    else:
                        thunk = struct.unpack_from("<I", self._data, thunk_offset)[0]

                    if thunk == 0:
                        break

                    if thunk & ordinal_flag:
                        # Import by ordinal
                        ordinal = thunk & 0xFFFF
                        self.imports.append(
                            ImportEntry(
                                dll_name=dll_name,
                                name=None,
                                ordinal=ordinal,
                                rva=iat_rva
                                + (thunk_offset - self.rva_to_offset(thunk_rva)),
                            )
                        )
                    else:
                        # Import by name: thunk is RVA to IMAGE_IMPORT_BY_NAME
                        ibn_offset = self.rva_to_offset(thunk)
                        func_name = None
                        if ibn_offset is not None and ibn_offset + 2 < len(self._data):
                            func_name = self._read_string_at_offset(ibn_offset + 2)
                        thunk_index = (
                            thunk_offset - self.rva_to_offset(thunk_rva)
                        ) // thunk_size
                        self.imports.append(
                            ImportEntry(
                                dll_name=dll_name,
                                name=func_name,
                                ordinal=None,
                                rva=iat_rva + thunk_index * thunk_size,
                            )
                        )

                    thunk_offset += thunk_size

            offset += 20

    @staticmethod
    def from_file(path):
        """Parse PE from a file on disk.

        Args:
            path: Path to PE file.

        Returns:
            PE object.
        """
        with open(path, "rb") as f:
            return PE(f.read())
