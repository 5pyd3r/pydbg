"""Tests for PE format parser."""

import os
import struct
import tempfile
import unittest


def _write_temp(data, suffix=".bin"):
    """Write bytes to a temp file and return its path (caller removes it)."""
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as handle:
        handle.write(data)
        return handle.name


def build_minimal_pe32plus():
    """Build minimal synthetic PE32+ bytes for testing."""
    # DOS header: 64 bytes
    dos_header = struct.pack(
        "<2s58xI",
        b"MZ",  # e_magic
        0x80,  # e_lfanew -> offset 128
    )
    # Pad to 128 bytes (dos header + padding)
    dos_header += b"\x00" * (0x80 - len(dos_header))

    # PE signature
    pe_sig = struct.pack("<I", 0x00004550)  # "PE\0\0"

    # IMAGE_FILE_HEADER (20 bytes)
    file_header = struct.pack(
        "<HHIIIHH",
        0x8664,  # machine: AMD64
        2,  # number_of_sections
        0x5A000000,  # time_date_stamp
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        0xF0,  # SizeOfOptionalHeader (PE32+)
        0x22,
    )  # characteristics

    # IMAGE_OPTIONAL_HEADER64 (PE32+ static fields: 112 bytes before data dirs)
    opt_header = struct.pack(
        "<HBB",
        0x20B,  # magic: PE32+
        14,  # major linker version
        0,  # minor linker version
    )
    opt_header += struct.pack(
        "<III",
        0x1000,  # SizeOfCode
        0,  # SizeOfInitializedData
        0,  # SizeOfUninitializedData
    )
    opt_header += struct.pack(
        "<II",
        0x1000,  # AddressOfEntryPoint
        0x1000,  # BaseOfCode
    )
    opt_header += struct.pack(
        "<Q",
        0x140000000,  # ImageBase
    )
    opt_header += struct.pack(
        "<II",
        0x1000,  # SectionAlignment
        0x200,  # FileAlignment
    )
    # Version fields + Win32Version: offset 40-55 (16 bytes)
    opt_header += struct.pack("<HHHHHHI", 4, 0, 0, 0, 4, 0, 0)
    # SizeOfImage, SizeOfHeaders, CheckSum: offset 56-67 (12 bytes)
    opt_header += struct.pack("<III", 0x4000, 0x400, 0)
    # Subsystem, DllCharacteristics: offset 68-71 (4 bytes)
    opt_header += struct.pack("<HH", 2, 0)
    # Stack/Heap: offset 72-103 (32 bytes)
    opt_header += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)
    # LoaderFlags, NumberOfRvaAndSizes: offset 104-111 (8 bytes)
    opt_header += struct.pack("<II", 0, 2)

    # Data directories: 2 entries * 8 bytes = 16 bytes
    # Entry 0 (Export): RVA=0x3000, Size=0x100
    # Entry 1 (Import): RVA=0x4000, Size=0x100
    data_dirs = struct.pack(
        "<IIII",
        0x3000,
        0x100,  # Export
        0x4000,
        0x100,  # Import
    )

    # Section headers: 2 * 40 bytes
    # .text section
    text_section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",  # Name
        0xE00,  # VirtualSize
        0x1000,  # VirtualAddress
        0x1000,  # SizeOfRawData
        0x400,  # PointerToRawData
        0,
        0,
        0,
        0,
        0x60000020,  # Characteristics: CODE|EXECUTE|READ
    )
    # .rdata section
    rdata_section = struct.pack(
        "<8sIIIIIIHHI",
        b".rdata\x00\x00",  # Name
        0xA00,  # VirtualSize
        0x2000,  # VirtualAddress
        0xC00,  # SizeOfRawData
        0x1400,  # PointerToRawData
        0,
        0,
        0,
        0,
        0x40000040,  # Characteristics: DATA|READ
    )

    data = (
        dos_header
        + pe_sig
        + file_header
        + opt_header
        + data_dirs
        + text_section
        + rdata_section
    )

    # Pad to at least 0x4200 bytes so export/import RVAs are within file
    if len(data) < 0x4200:
        data += b"\x00" * (0x4200 - len(data))

    return data


def build_pe_with_exports():
    """Build PE32+ bytes with a synthetic export directory."""
    dos_header = struct.pack("<2s58xI", b"MZ", 0x80)
    dos_header += b"\x00" * (0x80 - len(dos_header))
    pe_sig = struct.pack("<I", 0x00004550)
    file_header = struct.pack("<HHIIIHH", 0x8664, 2, 0x5A000000, 0, 0, 0xF0, 0x22)

    # Optional header (PE32+)
    oh = struct.pack("<HBB", 0x20B, 14, 0)
    oh += struct.pack("<III", 0x1000, 0, 0)
    oh += struct.pack("<II", 0x1000, 0x1000)
    oh += struct.pack("<Q", 0x140000000)
    oh += struct.pack("<II", 0x1000, 0x200)
    oh += struct.pack("<HHHHHHI", 4, 0, 0, 0, 4, 0, 0)
    oh += struct.pack("<III", 0x4000, 0x400, 0)
    oh += struct.pack("<HH", 2, 0)
    oh += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)
    oh += struct.pack("<II", 0, 2)

    # Export dir: RVA=0x3000, Size=0x200
    # Import dir: RVA=0x4000, Size=0x100
    data_dirs = struct.pack("<IIII", 0x3000, 0x200, 0x4000, 0x100)

    # .text: RVA=0x1000, file=0x400, size=0x1000
    text = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0xE00,
        0x1000,
        0x1000,
        0x400,
        0,
        0,
        0,
        0,
        0x60000020,
    )

    # .rdata: RVA=0x2000, file=0x1400, size=0x3000 (big enough for exports)
    rdata = struct.pack(
        "<8sIIIIIIHHI",
        b".rdata\x00\x00",
        0x3000,
        0x2000,
        0x3000,
        0x1400,
        0,
        0,
        0,
        0,
        0x40000040,
    )

    data = dos_header + pe_sig + file_header + oh + data_dirs + text + rdata
    # Pad to 0x4400
    if len(data) < 0x4400:
        data += b"\x00" * (0x4400 - len(data))

    # Now build export directory at file offset 0x2400 (RVA 0x3000)
    export_dir_offset = 0x2400
    # Name string "test.dll" at RVA 0x3100 -> file offset 0x2500
    name_rva = 0x3100
    data = bytearray(data)
    name_str = b"test.dll\x00"
    data[0x2500: 0x2500 + len(name_str)] = name_str

    # AddressOfFunctions at RVA 0x3200 -> file offset 0x2600 (1 function)
    # AddressOfNames at RVA 0x3204 -> file offset 0x2604 (1 name)
    # AddressOfNameOrdinals at RVA 0x3208 -> file offset 0x2608 (1 ordinal)
    # Function RVA: 0x1000 (points to .text)
    # Name RVA: 0x3300 -> file offset 0x2700 (function name "MyExport")
    # Ordinal: 0

    func_rva = 0x3200
    names_rva = 0x3204
    ordinals_rva = 0x3208
    func_name_rva = 0x3300

    export_dir = struct.pack(
        "<IIHHIIIIIII",
        0,  # Characteristics
        0,  # TimeDateStamp
        0,
        0,  # Version
        name_rva,  # Name
        1,  # Base (ordinal base = 1)
        1,  # NumberOfFunctions
        1,  # NumberOfNames
        func_rva,  # AddressOfFunctions
        names_rva,  # AddressOfNames
        ordinals_rva,
    )  # AddressOfNameOrdinals

    data[export_dir_offset: export_dir_offset + 40] = export_dir

    # Function address table: 1 entry = 0x1000 (RVA of the function)
    struct.pack_into("<I", data, 0x2600, 0x1000)
    # Name pointer table: 1 entry = func_name_rva
    struct.pack_into("<I", data, 0x2604, func_name_rva)
    # Ordinal table: 1 entry = 0
    struct.pack_into("<H", data, 0x2608, 0)
    # Function name: "MyExport\x00"
    func_name = b"MyExport\x00"
    data[0x2700: 0x2700 + len(func_name)] = func_name

    return bytes(data)


def build_pe_with_imports():
    """Build PE32+ bytes with a synthetic import directory."""
    dos_header = struct.pack("<2s58xI", b"MZ", 0x80)
    dos_header += b"\x00" * (0x80 - len(dos_header))
    pe_sig = struct.pack("<I", 0x00004550)
    file_header = struct.pack("<HHIIIHH", 0x8664, 2, 0x5A000000, 0, 0, 0xF0, 0x22)

    oh = struct.pack("<HBB", 0x20B, 14, 0)
    oh += struct.pack("<III", 0x1000, 0, 0)
    oh += struct.pack("<II", 0x1000, 0x1000)
    oh += struct.pack("<Q", 0x140000000)
    oh += struct.pack("<II", 0x1000, 0x200)
    oh += struct.pack("<HHHHHHI", 4, 0, 0, 0, 4, 0, 0)
    oh += struct.pack("<III", 0x4000, 0x400, 0)
    oh += struct.pack("<HH", 2, 0)
    oh += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)
    oh += struct.pack("<II", 0, 2)

    # Export: RVA=0, Size=0 (none)
    # Import: RVA=0x5000, Size=0x200
    data_dirs = struct.pack("<IIII", 0, 0, 0x5000, 0x200)

    text = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0xE00,
        0x1000,
        0x1000,
        0x400,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    rdata = struct.pack(
        "<8sIIIIIIHHI",
        b".rdata\x00\x00",
        0x5000,
        0x2000,
        0x5000,
        0x1400,
        0,
        0,
        0,
        0,
        0x40000040,
    )

    data = dos_header + pe_sig + file_header + oh + data_dirs + text + rdata
    if len(data) < 0x6400:
        data += b"\x00" * (0x6400 - len(data))

    # Import directory at RVA 0x5000 -> file offset 0x1400 + (0x5000 - 0x2000) = 0x4400
    import_dir_offset = 0x4400

    data = bytearray(data)

    # ILT at RVA 0x5100 -> file offset 0x4500 (1 entry: points to import by name)
    # Import by name at RVA 0x5200 -> file offset 0x4600 (hint=1, name="MessageBoxA")
    # DLL name at RVA 0x5300 -> file offset 0x4700 ("user32.dll\x00")
    # IAT at RVA 0x5400 -> file offset 0x4800

    ilt_rva = 0x5100
    import_by_name_rva = 0x5200
    dll_name_rva = 0x5300
    iat_rva = 0x5400

    # IMAGE_IMPORT_DESCRIPTOR (20 bytes):
    # OriginalFirstThunk(4), TimeDateStamp(4), ForwarderChain(4), Name(4), FirstThunk(4)
    import_desc = struct.pack(
        "<IIIII",
        ilt_rva,  # OriginalFirstThunk (ILT)
        0,  # TimeDateStamp
        0,  # ForwarderChain
        dll_name_rva,  # Name
        iat_rva,
    )  # FirstThunk (IAT)
    data[import_dir_offset: import_dir_offset + 20] = import_desc
    # Null terminator (next 20 bytes are already zero)

    # ILT: 1 entry pointing to import by name RVA, then null
    struct.pack_into("<Q", data, 0x4500, import_by_name_rva)

    # IMAGE_IMPORT_BY_NAME: Hint(2) + Name string
    struct.pack_into("<H", data, 0x4600, 1)  # hint = 1
    func_name = b"MessageBoxA\x00"
    data[0x4602: 0x4602 + len(func_name)] = func_name

    # DLL name
    dll_name = b"user32.dll\x00"
    data[0x4700: 0x4700 + len(dll_name)] = dll_name

    return bytes(data)


def build_minimal_pe32():
    """Build minimal synthetic PE32 bytes for testing."""
    # DOS header
    dos_header = struct.pack("<2s58xI", b"MZ", 0x80)
    dos_header += b"\x00" * (0x80 - len(dos_header))

    # PE signature
    pe_sig = struct.pack("<I", 0x00004550)

    # IMAGE_FILE_HEADER (20 bytes)
    file_header = struct.pack(
        "<HHIIIHH",
        0x14C,  # machine: i386
        2,  # number_of_sections
        0x5A000000,  # time_date_stamp
        0,
        0,  # PointerToSymbolTable, NumberOfSymbols
        0xE0,  # SizeOfOptionalHeader (PE32)
        0x22,  # characteristics
    )

    # PE32 optional header: 96 bytes static fields
    # Magic(2) + Linker(1+1) + Code/I0/I1/Entry/Base/BaseOfData(6*4) + ImageBase(4)
    # + SectionAlign(4) + FileAlign(4) + 6*H(12) + Win32(4)
    # + SizeOfImage/Headers/CheckSum(3*4) + Subsystem/DllChar(2+2)
    # + StackReserve/Commit/HeapReserve/Commit(4*4) + LoaderFlags(4) + NumRva(4)
    opt_header = struct.pack(
        "<HBB",
        0x10B,  # magic: PE32
        14,
        0,  # linker version
    )
    opt_header += struct.pack(
        "<IIIIII",
        0x1000,  # SizeOfCode
        0,  # SizeOfInitializedData
        0,  # SizeOfUninitializedData
        0x1000,  # AddressOfEntryPoint
        0x1000,  # BaseOfCode
        0,  # BaseOfData (PE32 only)
    )
    opt_header += struct.pack("<I", 0x400000)  # ImageBase
    opt_header += struct.pack(
        "<II",
        0x1000,  # SectionAlignment
        0x200,  # FileAlignment
    )
    opt_header += struct.pack(
        "<HHHHHH",
        4,
        0,  # OS version
        0,
        0,  # Image version
        4,
        0,  # Subsystem version
    )
    opt_header += struct.pack("<I", 0)  # Win32VersionValue
    opt_header += struct.pack(
        "<III",
        0x4000,  # SizeOfImage
        0x400,  # SizeOfHeaders
        0,  # CheckSum
    )
    opt_header += struct.pack(
        "<HH",
        2,  # Subsystem (GUI)
        0,  # DllCharacteristics
    )
    opt_header += struct.pack(
        "<IIII",
        0x100000,  # SizeOfStackReserve
        0x1000,  # SizeOfStackCommit
        0x100000,  # SizeOfHeapReserve
        0x1000,  # SizeOfHeapCommit
    )
    opt_header += struct.pack("<II", 0, 2)  # LoaderFlags, NumberOfRvaAndSizes

    # Data directories: 2 entries
    data_dirs = struct.pack(
        "<IIII",
        0x3000,
        0x100,  # Export
        0x4000,
        0x100,  # Import
    )

    # Section headers: 2 * 40 bytes
    text_section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0xE00,
        0x1000,
        0x1000,
        0x400,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    rdata_section = struct.pack(
        "<8sIIIIIIHHI",
        b".rdata\x00\x00",
        0xA00,
        0x2000,
        0xC00,
        0x1400,
        0,
        0,
        0,
        0,
        0x40000040,
    )

    data = (
        dos_header
        + pe_sig
        + file_header
        + opt_header
        + data_dirs
        + text_section
        + rdata_section
    )
    if len(data) < 0x4200:
        data += b"\x00" * (0x4200 - len(data))
    return data


class TestSyntheticPE32(unittest.TestCase):
    """Tests for PE32 parser with synthetic data."""

    def test_parse_magic_pe32(self):
        from pydbg.pe import PE

        data = build_minimal_pe32()
        pe = PE(data)
        self.assertEqual(pe.optional_header.magic, 0x10B)

    def test_parse_dos_header_pe32(self):
        from pydbg.pe import PE

        data = build_minimal_pe32()
        pe = PE(data)
        self.assertEqual(pe.dos_header.e_magic, 0x5A4D)
        self.assertEqual(pe.dos_header.e_lfanew, 0x80)

    def test_parse_file_header_pe32(self):
        from pydbg.pe import PE

        data = build_minimal_pe32()
        pe = PE(data)
        self.assertEqual(pe.file_header.machine, 0x14C)
        self.assertEqual(pe.file_header.number_of_sections, 2)

    def test_parse_optional_header_pe32(self):
        from pydbg.pe import PE

        data = build_minimal_pe32()
        pe = PE(data)
        self.assertEqual(pe.optional_header.image_base, 0x400000)
        self.assertEqual(pe.optional_header.entry_point_rva, 0x1000)
        self.assertEqual(pe.optional_header.number_of_rva_and_sizes, 2)

    def test_parse_sections_pe32(self):
        from pydbg.pe import PE

        data = build_minimal_pe32()
        pe = PE(data)
        self.assertEqual(len(pe.sections), 2)
        self.assertEqual(pe.sections[0].name, ".text")
        self.assertEqual(pe.sections[0].virtual_address, 0x1000)
        self.assertEqual(pe.sections[1].name, ".rdata")

    def test_rva_to_offset_pe32(self):
        from pydbg.pe import PE

        data = build_minimal_pe32()
        pe = PE(data)
        offset = pe.rva_to_offset(0x1050)
        self.assertEqual(offset, 0x450)

    def test_parse_dos_header(self):
        from pydbg.pe import PE

        data = build_minimal_pe32plus()
        pe = PE(data)
        self.assertEqual(pe.dos_header.e_magic, 0x5A4D)
        self.assertEqual(pe.dos_header.e_lfanew, 0x80)

    def test_parse_file_header(self):
        from pydbg.pe import PE

        data = build_minimal_pe32plus()
        pe = PE(data)
        self.assertEqual(pe.file_header.machine, 0x8664)
        self.assertEqual(pe.file_header.number_of_sections, 2)
        self.assertEqual(pe.file_header.characteristics, 0x22)

    def test_parse_optional_header_pe32plus(self):
        from pydbg.pe import PE

        data = build_minimal_pe32plus()
        pe = PE(data)
        self.assertEqual(pe.optional_header.magic, 0x20B)
        self.assertEqual(pe.optional_header.entry_point_rva, 0x1000)
        self.assertEqual(pe.optional_header.image_base, 0x140000000)
        self.assertEqual(pe.optional_header.number_of_rva_and_sizes, 2)
        self.assertIn(0, pe.optional_header.data_directories)
        self.assertIn(1, pe.optional_header.data_directories)
        self.assertEqual(pe.optional_header.data_directories[0].virtual_address, 0x3000)
        self.assertEqual(pe.optional_header.data_directories[1].virtual_address, 0x4000)

    def test_parse_sections(self):
        from pydbg.pe import PE

        data = build_minimal_pe32plus()
        pe = PE(data)
        self.assertEqual(len(pe.sections), 2)
        self.assertEqual(pe.sections[0].name, ".text")
        self.assertEqual(pe.sections[0].virtual_address, 0x1000)
        self.assertEqual(pe.sections[0].pointer_to_raw_data, 0x400)
        self.assertEqual(pe.sections[1].name, ".rdata")


class TestRvaConversion(unittest.TestCase):
    """Tests for RVA to file offset conversion."""

    def test_rva_to_offset(self):
        from pydbg.pe import PE

        data = build_minimal_pe32plus()
        pe = PE(data)
        # .text section: VirtualAddress=0x1000, PointerToRawData=0x400
        # RVA 0x1050 -> file offset 0x450
        offset = pe.rva_to_offset(0x1050)
        self.assertEqual(offset, 0x450)

    def test_rva_outside_sections(self):
        from pydbg.pe import PE

        data = build_minimal_pe32plus()
        pe = PE(data)
        offset = pe.rva_to_offset(0x99999)
        self.assertIsNone(offset)


class TestFileViewRawSizeGuard(unittest.TestCase):
    """A section's in-memory extent can exceed what the file stores.

    FileView must refuse those RVAs instead of resolving them into the next
    section's raw data. Packed images make this routine rather than exotic: a
    UPX0-style section declares virtual_size with size_of_raw_data == 0, so
    every RVA inside it used to return a plausible offset into whatever
    followed — bytes from the wrong place, which is worse than no answer.
    """

    @staticmethod
    def _sections():
        from pydbg.pe.types import SectionHeader

        def section(name, va, vsize, rawptr, rawsize):
            return SectionHeader(
                name=name, virtual_address=va, virtual_size=vsize,
                pointer_to_raw_data=rawptr, size_of_raw_data=rawsize,
                characteristics=0x60000020)

        return [
            section(".text", 0x1000, 0x1000, 0x400, 0x1000),   # fully backed
            section(".data", 0x2000, 0x2000, 0x1400, 0x400),   # zero-fill tail
            section("UPX0", 0x4000, 0x2000, 0x0000, 0x0000),   # mapped, not stored
            section("UPX1", 0x6000, 0x1000, 0x1800, 0x600),
        ]

    def view(self):
        from pydbg.pe.view import FileView
        return FileView(self._sections())

    def test_fully_backed_section_resolves(self):
        self.assertEqual(self.view().rva_to_source_offset(0x1000), 0x400)
        self.assertEqual(self.view().rva_to_source_offset(0x1FFF), 0x13FF)

    def test_zero_raw_size_section_is_not_file_backed(self):
        # Used to return 0 for the first RVA — i.e. the DOS header — and
        # 0x1800 (UPX1's raw data) for the last.
        self.assertIsNone(self.view().rva_to_source_offset(0x4000))
        self.assertIsNone(self.view().rva_to_source_offset(0x5FFF))

    def test_zero_fill_tail_is_not_file_backed(self):
        # .data maps 0x2000..0x4000 but stores only the first 0x400 bytes.
        self.assertEqual(self.view().rva_to_source_offset(0x2000), 0x1400)
        self.assertEqual(self.view().rva_to_source_offset(0x23FF), 0x17FF)
        # These used to resolve into UPX1's raw data at 0x1800.
        self.assertIsNone(self.view().rva_to_source_offset(0x2400))
        self.assertIsNone(self.view().rva_to_source_offset(0x3FFF))

    def test_rva_outside_every_section_is_none(self):
        self.assertIsNone(self.view().rva_to_source_offset(0x9000))

    def test_loaded_view_does_not_inherit_the_guard(self):
        """The zero-fill tail IS readable in a live process.

        That asymmetry is the whole reason two views exist, so LoadedView must
        keep mapping every RVA rather than inheriting FileView's filtering.
        """
        from pydbg.pe.view import LoadedView

        loaded = LoadedView()
        for rva in (0x1000, 0x23FF, 0x2400, 0x4000, 0x5FFF):
            self.assertEqual(loaded.rva_to_source_offset(rva), rva)


class TestSourceTryRead(unittest.TestCase):
    """try_read is the one place "cannot read" becomes None.

    The sources disagree by default — BytesSource raises past the end,
    FileSource returns a short slice — and every directory walk depends on
    both meaning the same thing. Without this, a truncated directory aborts
    the whole parse instead of ending one table.
    """

    def test_bytes_source_out_of_bounds_is_none(self):
        from pydbg.pe.source import BytesSource

        src = BytesSource(b"0123456789")
        self.assertEqual(src.try_read(0, 4), b"0123")
        self.assertIsNone(src.try_read(8, 4))     # straddles the end
        self.assertIsNone(src.try_read(20, 1))    # starts past it
        # read() is unchanged: try_read is additive, not a replacement.
        with self.assertRaises(ValueError):
            src.read(20, 1)

    def test_file_source_short_read_is_none(self):
        from pydbg.pe.source import FileSource

        path = _write_temp(b"0123456789")
        try:
            src = FileSource(path)
            try:
                self.assertEqual(src.try_read(0, 4), b"0123")
                self.assertIsNone(src.try_read(8, 4))
                self.assertIsNone(src.try_read(20, 1))
            finally:
                src.close()
        finally:
            os.remove(path)

    def test_raising_source_becomes_none(self):
        """A live-process source signals an unreadable page with OSError."""
        from pydbg.pe.source import Source

        class Broken(Source):
            def read(self, offset, size):
                raise OSError(299, "ERROR_PARTIAL_COPY")

        self.assertIsNone(Broken().try_read(0, 16))


class TestPEConstructionIsUnified(unittest.TestCase):
    """PE(data) and PE.from_file(path) must produce the same object.

    They used to be two independent copies of the same parse sequence, so a
    new directory had to be wired into both — and would eventually be wired
    into only one.
    """

    def test_from_file_matches_from_bytes(self):
        from pydbg.pe import PE

        data = build_minimal_pe32plus()
        path = _write_temp(data, ".exe")
        try:
            from_bytes = PE(data)
            from_file = PE.from_file(path)
        finally:
            os.remove(path)

        self.assertEqual(from_file.dos_header, from_bytes.dos_header)
        self.assertEqual(from_file.file_header, from_bytes.file_header)
        self.assertEqual(from_file.optional_header, from_bytes.optional_header)
        self.assertEqual(from_file.sections, from_bytes.sections)
        self.assertEqual(from_file.exports, from_bytes.exports)
        self.assertEqual(from_file.imports, from_bytes.imports)
        self.assertEqual(from_file.image_base, from_bytes.image_base)

    def test_from_file_closes_its_handle(self):
        """Reading the file in is what lets the handle close early.

        Removing the file before asserting would fail on Windows if anything
        still held it open.
        """
        from pydbg.pe import PE
        from pydbg.pe.source import BytesSource

        data = build_minimal_pe32plus()
        path = _write_temp(data, ".exe")
        try:
            pe = PE.from_file(path)
        finally:
            os.remove(path)

        self.assertIsInstance(pe.source, BytesSource)
        # ...and the bytes are still there to parse, with the file gone.
        self.assertEqual(pe.read_rva(0x1000, 2), data[0x400:0x402])

    def test_lazy_keeps_the_file_open(self):
        from pydbg.pe import PE
        from pydbg.pe.source import FileSource

        data = build_minimal_pe32plus()
        path = _write_temp(data, ".exe")
        pe = PE.from_file(path, lazy=True)
        try:
            self.assertIsInstance(pe.source, FileSource)
            self.assertEqual(pe.read_rva(0x1000, 2), data[0x400:0x402])
        finally:
            pe.source.close()
            os.remove(path)


class TestReadRva(unittest.TestCase):
    """read_rva is the accessor every directory parser will go through."""

    def test_reads_a_file_backed_rva(self):
        from pydbg.pe import PE

        data = build_minimal_pe32plus()
        pe = PE(data)
        # .text holds RVA 0x1000 at file offset 0x400.
        self.assertEqual(pe.read_rva(0x1000, 4), data[0x400:0x404])

    def test_unmapped_rva_is_none(self):
        from pydbg.pe import PE

        pe = PE(build_minimal_pe32plus())
        self.assertIsNone(pe.read_rva(0x99999, 4))

    def test_size_that_overruns_the_file_is_none(self):
        """A lying size field must end a walk, not raise."""
        from pydbg.pe import PE

        data = build_minimal_pe32plus()
        pe = PE(data)
        self.assertIsNone(pe.read_rva(0x1000, len(data) * 2))

    def test_from_source_honours_an_explicit_view(self):
        """The seam a live-process parse uses: with LoadedView the source
        offset IS the RVA, so headers at RVA 0.. parse while the body is read
        relative to the module base."""
        from pydbg.pe import PE
        from pydbg.pe.source import BytesSource
        from pydbg.pe.view import LoadedView

        data = build_minimal_pe32plus()
        pe = PE.from_source(BytesSource(data), LoadedView())
        self.assertEqual(pe.read_rva(0x50, 4), data[0x50:0x54])
        self.assertIsNone(pe.read_rva(0x99999, 4))
        # The headers really did parse through the loaded view.
        self.assertEqual(pe.dos_header.e_lfanew, 0x80)


class TestExportParsing(unittest.TestCase):
    """Tests for export directory parsing."""

    def test_parse_exports(self):
        from pydbg.pe import PE

        data = build_pe_with_exports()
        pe = PE(data)
        self.assertEqual(len(pe.exports), 1)
        self.assertEqual(pe.exports[0].name, "MyExport")
        self.assertEqual(pe.exports[0].ordinal, 1)
        self.assertEqual(pe.exports[0].rva, 0x1000)
        self.assertIsNone(pe.exports[0].forwarder)

    def test_no_exports(self):
        from pydbg.pe import PE

        data = build_minimal_pe32plus()
        pe = PE(data)
        self.assertEqual(pe.exports, [])


class TestImportParsing(unittest.TestCase):
    """Tests for import directory parsing."""

    def test_parse_imports(self):
        from pydbg.pe import PE

        data = build_pe_with_imports()
        pe = PE(data)
        self.assertEqual(len(pe.imports), 1)
        self.assertEqual(pe.imports[0].dll_name, "user32.dll")
        self.assertEqual(pe.imports[0].name, "MessageBoxA")
        self.assertIsNone(pe.imports[0].ordinal)
        self.assertEqual(pe.imports[0].rva, 0x5400)

    def test_no_imports(self):
        from pydbg.pe import PE

        data = build_minimal_pe32plus()
        pe = PE(data)
        self.assertEqual(pe.imports, [])


class TestValidation(unittest.TestCase):
    """Tests for PE parser error handling."""

    def test_invalid_dos_signature(self):
        from pydbg.pe import PE

        data = b"XX" + b"\x00" * 100
        with self.assertRaises(ValueError) as cm:
            PE(data)
        self.assertIn("DOS signature", str(cm.exception))

    def test_invalid_pe_signature(self):
        from pydbg.pe import PE

        data = struct.pack("<2s58xI", b"MZ", 0x40)
        data += b"\x00" * (0x44 - len(data))
        data += b"BADS"  # bad PE sig
        data += b"\x00" * 100
        with self.assertRaises(ValueError) as cm:
            PE(data)
        self.assertIn("PE signature", str(cm.exception))

    def test_truncated_data(self):
        from pydbg.pe import PE

        data = b"MZ" + b"\x00" * 10
        with self.assertRaises(ValueError):
            PE(data)


class TestRealDLL(unittest.TestCase):
    """Integration tests with real DLL files."""

    def test_parse_kernel32(self):
        """Parse kernel32.dll from System32."""
        from pydbg.pe import PE

        path = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"), "System32", "kernel32.dll"
        )
        pe = PE.from_file(path)
        self.assertEqual(pe.dos_header.e_magic, 0x5A4D)
        self.assertIn(pe.file_header.machine, (0x14C, 0x8664))
        self.assertIn(pe.optional_header.magic, (0x10B, 0x20B))
        self.assertGreater(len(pe.sections), 0)
        # kernel32.dll definitely has exports
        self.assertGreater(len(pe.exports), 0)
        # Check some well-known exports exist
        export_names = [e.name for e in pe.exports if e.name is not None]
        self.assertIn("GetProcAddress", export_names)
        self.assertIn("LoadLibraryA", export_names)


if __name__ == "__main__":
    unittest.main()
