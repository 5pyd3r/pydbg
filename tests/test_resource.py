"""Tests for PE resource directory parser."""

import struct
import unittest


def build_pe_with_resources():
    """Build a synthetic PE32+ with a .rsrc section containing one RT_RCDATA resource.

    The .rsrc section contains:
    - Type-level directory: 1 ID entry (type_id=10, RT_RCDATA)
    - Name-level directory: 1 ID entry (name_id=100)
    - Language-level directory: 1 ID entry (language_id=1033 = 0x0409)
    - Data entry pointing to 16 bytes at the end of .rsrc section

    Layout within .rsrc section (base at pointer_to_raw_data):
        0x0000: Type-level directory (16 + 1*8 = 24 bytes)
        0x0018: Name-level directory (16 + 1*8 = 24 bytes)
        0x0030: Language-level directory (16 + 1*8 = 24 bytes)
        0x0048: IMAGE_RESOURCE_DATA_ENTRY (16 bytes)
        0x0058: Resource data (16 bytes)

    The .rsrc section will be at RVA 0x3000, file offset 0x600.
    """
    # --- DOS header: 64 bytes, e_lfanew at 0x3C -> 0x80 ---
    dos_header = struct.pack("<2s58xI", b"MZ", 0x80)
    dos_header += b"\x00" * (0x80 - len(dos_header))

    # PE signature
    pe_sig = struct.pack("<I", 0x00004550)  # "PE\0\0"

    # IMAGE_FILE_HEADER (20 bytes)
    file_header = struct.pack(
        "<HHIIIHH",
        0x8664,  # machine: AMD64
        3,       # number_of_sections (.text, .rdata, .rsrc)
        0x5A000000,  # time_date_stamp
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        0xF0,  # SizeOfOptionalHeader (PE32+)
        0x22,  # characteristics
    )

    # IMAGE_OPTIONAL_HEADER64 (PE32+)
    opt_header = struct.pack("<HBB", 0x20B, 14, 0)  # magic, linker
    opt_header += struct.pack("<III", 0x1000, 0, 0)  # code sizes
    opt_header += struct.pack("<II", 0x1000, 0x1000)  # entry, base of code
    opt_header += struct.pack("<Q", 0x140000000)  # image base
    opt_header += struct.pack("<II", 0x1000, 0x200)  # section/file align
    opt_header += struct.pack("<HHHHHHI", 4, 0, 0, 0, 4, 0, 0)  # versions
    opt_header += struct.pack("<III", 0x5000, 0x400, 0)  # image/headers size, checksum
    opt_header += struct.pack("<HH", 2, 0)  # subsystem, dll chars
    opt_header += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)  # stack/heap
    opt_header += struct.pack("<II", 0, 16)  # LoaderFlags, NumberOfRvaAndSizes

    # Data directories: 16 entries * 8 bytes = 128 bytes
    # Entry 0 (Export): none
    # Entry 1 (Import): none
    # Entry 2 (Resource): RVA=0x3000, Size=0x100
    data_dirs = struct.pack("<II", 0, 0)   # Export
    data_dirs += struct.pack("<II", 0, 0)  # Import
    data_dirs += struct.pack("<II", 0x3000, 0x100)  # Resource
    # Pad to 16 entries (remaining 13 entries = 104 bytes of zeros)
    data_dirs += b"\x00" * (13 * 8)

    # Section headers: 3 * 40 bytes
    # .text section
    text_section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",  # Name
        0xE00,   # VirtualSize
        0x1000,  # VirtualAddress
        0x1000,  # SizeOfRawData
        0x400,   # PointerToRawData
        0, 0, 0, 0,
        0x60000020,  # CODE|EXECUTE|READ
    )
    # .rdata section
    rdata_section = struct.pack(
        "<8sIIIIIIHHI",
        b".rdata\x00\x00",  # Name
        0xA00,   # VirtualSize
        0x2000,  # VirtualAddress
        0x200,   # SizeOfRawData
        0x1400,  # PointerToRawData
        0, 0, 0, 0,
        0x40000040,  # DATA|READ
    )
    # .rsrc section: starts at file offset 0x1600, RVA 0x3000
    # Size needs to hold all resource directory structures + data
    # Directory structures: 3 dirs * 24 bytes + 1 data entry (16) + 16 bytes data = 104
    # Round up to 0x200 for file alignment
    rsrc_section = struct.pack(
        "<8sIIIIIIHHI",
        b".rsrc\x00\x00\x00",  # Name
        0x200,   # VirtualSize
        0x3000,  # VirtualAddress
        0x200,   # SizeOfRawData (aligned to 0x200)
        0x1600,  # PointerToRawData
        0, 0, 0, 0,
        0x40000040,  # DATA|READ
    )

    # Build the PE header portion
    header = dos_header + pe_sig + file_header + opt_header + data_dirs
    header += text_section + rdata_section + rsrc_section

    # Pad header to at least 0x1600 bytes (start of .rsrc raw data)
    if len(header) < 0x1600:
        header += b"\x00" * (0x1600 - len(header))

    # Now build the .rsrc section content
    # All offsets within .rsrc are relative to the section start
    # .rsrc file offset = 0x1600, .rsrc RVA = 0x3000

    resource_data = b"\xDE\xAD\xBE\xEF" * 4  # 16 bytes of test data

    # Type-level directory at .rsrc offset 0x0000
    # 1 ID entry (RT_RCDATA = 10)
    type_dir = struct.pack('<IIHHHH',
                           0,  # Characteristics
                           0,  # TimeDateStamp
                           0,  # MajorVersion
                           0,  # MinorVersion
                           0,  # NumberOfNamedEntries
                           1)  # NumberOfIdEntries
    # Entry: Id=10, Subdir at offset 0x0018
    type_dir += struct.pack('<II', 10, 0x80000000 | 0x0018)

    # Name-level directory at .rsrc offset 0x0018
    # 1 ID entry (name_id = 100)
    name_dir = struct.pack('<IIHHHH',
                           0, 0, 0, 0,
                           0,  # NumberOfNamedEntries
                           1)  # NumberOfIdEntries
    # Entry: Id=100, Subdir at offset 0x0030
    name_dir += struct.pack('<II', 100, 0x80000000 | 0x0030)

    # Language-level directory at .rsrc offset 0x0030
    # 1 ID entry (language = 0x0409 = 1033 English US)
    lang_dir = struct.pack('<IIHHHH',
                           0, 0, 0, 0,
                           0,  # NumberOfNamedEntries
                           1)  # NumberOfIdEntries
    # Entry: Id=0x0409, DataEntry at offset 0x0048
    lang_dir += struct.pack('<II', 0x0409, 0x0048)

    # IMAGE_RESOURCE_DATA_ENTRY at .rsrc offset 0x0048
    # OffsetToData = RVA of the actual resource data
    # Data is at .rsrc offset 0x0058 -> RVA = 0x3000 + 0x0058 = 0x3058
    data_rva = 0x3058
    data_entry = struct.pack('<IIII',
                             data_rva,      # OffsetToData (RVA)
                             16,            # Size
                             0,             # CodePage
                             0)             # Reserved

    # Assemble .rsrc section content
    rsrc_content = type_dir + name_dir + lang_dir + data_entry + resource_data

    # Pad .rsrc to 0x200 bytes (SizeOfRawData)
    if len(rsrc_content) < 0x200:
        rsrc_content += b"\x00" * (0x200 - len(rsrc_content))

    # Full PE
    pe_data = header + rsrc_content
    # Ensure total is big enough
    if len(pe_data) < 0x1800:
        pe_data += b"\x00" * (0x1800 - len(pe_data))

    return pe_data, resource_data


def build_pe_without_resources():
    """Build a minimal PE32+ without a .rsrc section."""
    dos_header = struct.pack("<2s58xI", b"MZ", 0x80)
    dos_header += b"\x00" * (0x80 - len(dos_header))
    pe_sig = struct.pack("<I", 0x00004550)
    file_header = struct.pack("<HHIIIHH", 0x8664, 1, 0x5A000000, 0, 0, 0xF0, 0x22)

    opt_header = struct.pack("<HBB", 0x20B, 14, 0)
    opt_header += struct.pack("<III", 0x1000, 0, 0)
    opt_header += struct.pack("<II", 0x1000, 0x1000)
    opt_header += struct.pack("<Q", 0x140000000)
    opt_header += struct.pack("<II", 0x1000, 0x200)
    opt_header += struct.pack("<HHHHHHI", 4, 0, 0, 0, 4, 0, 0)
    opt_header += struct.pack("<III", 0x2000, 0x400, 0)
    opt_header += struct.pack("<HH", 2, 0)
    opt_header += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)
    opt_header += struct.pack("<II", 0, 16)
    data_dirs = b"\x00" * (16 * 8)

    text_section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0xE00, 0x1000, 0x1000, 0x400,
        0, 0, 0, 0,
        0x60000020,
    )

    data = dos_header + pe_sig + file_header + opt_header + data_dirs + text_section
    if len(data) < 0x400:
        data += b"\x00" * (0x400 - len(data))
    return data


class TestResourceEntry(unittest.TestCase):
    """Tests for the ResourceEntry dataclass."""

    def test_dataclass_fields(self):
        from pydbg.resource.pe_resource import ResourceEntry
        entry = ResourceEntry(
            type_id=10, type_name="RT_RCDATA", name_id=1,
            name_str="", language_id=1033,
            data_rva=0x133100, data_size=4096, data_offset=0xF200,
        )
        self.assertEqual(entry.type_id, 10)
        self.assertEqual(entry.type_name, "RT_RCDATA")
        self.assertEqual(entry.name_id, 1)
        self.assertEqual(entry.name_str, "")
        self.assertEqual(entry.language_id, 1033)
        self.assertEqual(entry.data_rva, 0x133100)
        self.assertEqual(entry.data_size, 4096)
        self.assertEqual(entry.data_offset, 0xF200)

    def test_dataclass_equality(self):
        from pydbg.resource.pe_resource import ResourceEntry
        entry1 = ResourceEntry(
            type_id=10, type_name="RT_RCDATA", name_id=100,
            name_str="", language_id=1033,
            data_rva=0x3058, data_size=16, data_offset=0x1658,
        )
        entry2 = ResourceEntry(
            type_id=10, type_name="RT_RCDATA", name_id=100,
            name_str="", language_id=1033,
            data_rva=0x3058, data_size=16, data_offset=0x1658,
        )
        self.assertEqual(entry1, entry2)


class TestResourceTypes(unittest.TestCase):
    """Tests for the RESOURCE_TYPES constant."""

    def test_standard_types_present(self):
        from pydbg.resource.pe_resource import RESOURCE_TYPES
        self.assertEqual(RESOURCE_TYPES[1], "RT_CURSOR")
        self.assertEqual(RESOURCE_TYPES[2], "RT_BITMAP")
        self.assertEqual(RESOURCE_TYPES[10], "RT_RCDATA")
        self.assertEqual(RESOURCE_TYPES[24], "RT_MANIFEST")


class TestPEResourceParser(unittest.TestCase):
    """Tests for PEResourceParser with synthetic PE data."""

    def test_parse_resources(self):
        """Parse finds 1 resource with correct type/name/size."""
        from pydbg.pe import PE
        from pydbg.resource.pe_resource import PEResourceParser

        pe_data, _ = build_pe_with_resources()
        pe = PE(pe_data)
        parser = PEResourceParser(pe)
        entries = parser.parse()

        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry.type_id, 10)
        self.assertEqual(entry.type_name, "RT_RCDATA")
        self.assertEqual(entry.name_id, 100)
        self.assertEqual(entry.language_id, 1033)  # 0x0409
        self.assertEqual(entry.data_size, 16)
        self.assertEqual(entry.data_rva, 0x3058)

    def test_extract_resource_data(self):
        """Extract returns correct 16 bytes."""
        from pydbg.pe import PE
        from pydbg.resource.pe_resource import PEResourceParser

        pe_data, expected_data = build_pe_with_resources()
        pe = PE(pe_data)
        parser = PEResourceParser(pe)
        entries = parser.parse()

        self.assertEqual(len(entries), 1)
        extracted = parser.extract(entries[0])
        self.assertEqual(extracted, expected_data)
        self.assertEqual(len(extracted), 16)

    def test_get_by_type(self):
        """Filter by type 10 returns 1, type 2 returns 0."""
        from pydbg.pe import PE
        from pydbg.resource.pe_resource import PEResourceParser

        pe_data, _ = build_pe_with_resources()
        pe = PE(pe_data)
        parser = PEResourceParser(pe)

        rcdata = parser.get_by_type(10)
        self.assertEqual(len(rcdata), 1)
        self.assertEqual(rcdata[0].type_name, "RT_RCDATA")

        bitmap = parser.get_by_type(2)
        self.assertEqual(len(bitmap), 0)

    def test_get_by_name(self):
        """Filter by type name works correctly."""
        from pydbg.pe import PE
        from pydbg.resource.pe_resource import PEResourceParser

        pe_data, _ = build_pe_with_resources()
        pe = PE(pe_data)
        parser = PEResourceParser(pe)

        rcdata = parser.get_by_name("RT_RCDATA")
        self.assertEqual(len(rcdata), 1)

        icon = parser.get_by_name("RT_ICON")
        self.assertEqual(len(icon), 0)

    def test_empty_resources(self):
        """PE without .rsrc returns empty list."""
        from pydbg.pe import PE
        from pydbg.resource.pe_resource import PEResourceParser

        pe_data = build_pe_without_resources()
        pe = PE(pe_data)
        parser = PEResourceParser(pe)
        entries = parser.parse()

        self.assertEqual(entries, [])

    def test_parse_is_idempotent(self):
        """Calling parse() twice returns the same result."""
        from pydbg.pe import PE
        from pydbg.resource.pe_resource import PEResourceParser

        pe_data, _ = build_pe_with_resources()
        pe = PE(pe_data)
        parser = PEResourceParser(pe)

        entries1 = parser.parse()
        entries2 = parser.parse()
        self.assertEqual(len(entries1), len(entries2))
        self.assertEqual(entries1[0].type_id, entries2[0].type_id)

    def test_data_offset_conversion(self):
        """data_offset is correctly converted from RVA to file offset."""
        from pydbg.pe import PE
        from pydbg.resource.pe_resource import PEResourceParser

        pe_data, _ = build_pe_with_resources()
        pe = PE(pe_data)
        parser = PEResourceParser(pe)
        entries = parser.parse()

        # .rsrc: RVA=0x3000, file offset=0x1600
        # Data RVA=0x3058 -> file offset = 0x3058 - 0x3000 + 0x1600 = 0x1658
        self.assertEqual(entries[0].data_offset, 0x1658)


class TestGuessExtension(unittest.TestCase):
    """Tests for the _guess_extension static method."""

    def test_riff_wav(self):
        from pydbg.resource.pe_resource import PEResourceParser
        self.assertEqual(PEResourceParser._guess_extension(b"RIFF\x00\x00\x00\x00"), ".wav")

    def test_bmp(self):
        from pydbg.resource.pe_resource import PEResourceParser
        self.assertEqual(PEResourceParser._guess_extension(b"BM\x00\x00"), ".bmp")

    def test_unknown_bin(self):
        from pydbg.resource.pe_resource import PEResourceParser
        self.assertEqual(PEResourceParser._guess_extension(b"\x00\x00\x00\x00"), ".bin")

    def test_short_data(self):
        from pydbg.resource.pe_resource import PEResourceParser
        self.assertEqual(PEResourceParser._guess_extension(b"\x00"), ".bin")
        self.assertEqual(PEResourceParser._guess_extension(b""), ".bin")


class TestResourceRecognizer(unittest.TestCase):
    """Tests for ResourceRecognizer format detection."""

    def _make_bmp(self, width=4, height=4, bpp=24):
        """Build a minimal BMP with the given dimensions."""
        row_size = (width * bpp + 31) // 32 * 4  # rows are 4-byte aligned
        pixel_data_size = row_size * height
        dib_header = struct.pack(
            '<IiiHHIIiiII',
            40,          # biSize
            width,       # biWidth
            height,      # biHeight
            1,           # biPlanes
            bpp,         # biBitCount
            0,           # biCompression
            pixel_data_size,
            0, 0,        # biXPelsPerMeter, biYPelsPerMeter
            0, 0,        # biClrUsed, biClrImportant
        )
        file_header = struct.pack('<2sIHHI', b'BM',
                                  14 + 40 + pixel_data_size,
                                  0, 0, 14 + 40)
        return file_header + dib_header + b'\x00' * pixel_data_size

    def test_recognize_wav(self):
        from pydbg.resource.recognizer import ResourceRecognizer
        rec = ResourceRecognizer()
        data = b'RIFF\x00\x00\x00\x00WAVE'
        result = rec.recognize(data)
        self.assertEqual(result['format'], 'wav')

    def test_recognize_bmp(self):
        from pydbg.resource.recognizer import ResourceRecognizer
        rec = ResourceRecognizer()
        bmp = self._make_bmp(width=8, height=6, bpp=24)
        result = rec.recognize(bmp)
        self.assertEqual(result['format'], 'bmp')
        self.assertEqual(result['width'], 8)
        self.assertEqual(result['height'], 6)
        self.assertEqual(result['bpp'], 24)

    def test_recognize_unknown(self):
        from pydbg.resource.recognizer import ResourceRecognizer
        rec = ResourceRecognizer()
        result = rec.recognize(b'\x00\x01\x02\x03')
        self.assertEqual(result['format'], 'unknown')
        self.assertIsNone(result['width'])

    def test_recognize_palette_rgb(self):
        from pydbg.resource.recognizer import ResourceRecognizer
        rec = ResourceRecognizer()
        data = b'\x00' * 768
        result = rec.recognize(data)
        self.assertEqual(result['format'], 'palette')
        self.assertEqual(result['extra']['entries'], 256)
        self.assertEqual(result['extra']['bpp'], 24)
        self.assertEqual(result['extra']['bytes_per_entry'], 3)

    def test_recognize_palette_rgba(self):
        from pydbg.resource.recognizer import ResourceRecognizer
        rec = ResourceRecognizer()
        data = b'\x00' * 1024
        result = rec.recognize(data)
        self.assertEqual(result['format'], 'palette')
        self.assertEqual(result['extra']['entries'], 256)
        self.assertEqual(result['extra']['bpp'], 32)
        self.assertEqual(result['extra']['bytes_per_entry'], 4)

    def test_palette_wrong_size(self):
        from pydbg.resource.recognizer import ResourceRecognizer
        rec = ResourceRecognizer()
        data = b'\x00' * 512
        result = rec.recognize_palette(data)
        self.assertIsNone(result)


class TestExtractAll(unittest.TestCase):
    """Tests for PEResourceParser.extract_all()."""

    def test_extract_all_creates_files(self):
        """extract_all creates files in the output directory."""
        import tempfile
        import os
        from pydbg.pe import PE
        from pydbg.resource.pe_resource import PEResourceParser

        pe_data, expected_data = build_pe_with_resources()
        pe = PE(pe_data)
        parser = PEResourceParser(pe)

        with tempfile.TemporaryDirectory() as tmpdir:
            paths = parser.extract_all(tmpdir)
            self.assertEqual(len(paths), 1)
            self.assertTrue(os.path.exists(paths[0]))
            with open(paths[0], 'rb') as f:
                self.assertEqual(f.read(), expected_data)

    def test_extract_all_naming(self):
        """Files are named using type_name, name_id, language_id."""
        import tempfile
        import os
        from pydbg.pe import PE
        from pydbg.resource.pe_resource import PEResourceParser

        pe_data, _ = build_pe_with_resources()
        pe = PE(pe_data)
        parser = PEResourceParser(pe)

        with tempfile.TemporaryDirectory() as tmpdir:
            paths = parser.extract_all(tmpdir)
            filename = os.path.basename(paths[0])
            self.assertIn("RT_RCDATA", filename)
            self.assertIn("100", filename)

    def test_extract_all_empty_resources(self):
        """extract_all on PE without resources returns empty list."""
        import tempfile
        from pydbg.pe import PE
        from pydbg.resource.pe_resource import PEResourceParser

        pe_data = build_pe_without_resources()
        pe = PE(pe_data)
        parser = PEResourceParser(pe)

        with tempfile.TemporaryDirectory() as tmpdir:
            paths = parser.extract_all(tmpdir)
            self.assertEqual(len(paths), 0)

    def test_extract_all_default_dir(self):
        """extract_all with default output_dir writes to current directory."""
        import tempfile
        import os
        from pydbg.pe import PE
        from pydbg.resource.pe_resource import PEResourceParser

        pe_data, _ = build_pe_with_resources()
        pe = PE(pe_data)
        parser = PEResourceParser(pe)

        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                paths = parser.extract_all()
                self.assertEqual(len(paths), 1)
                self.assertTrue(os.path.exists(paths[0]))
            finally:
                os.chdir(old_cwd)


class TestRecognizeSprite(unittest.TestCase):
    """Tests for ResourceRecognizer.recognize_sprite()."""

    def test_exact_width_match(self):
        """When width is given, returns {width, height}."""
        from pydbg.resource.recognizer import ResourceRecognizer
        data = b'\x00' * (32 * 64)  # 32 wide, 64 tall
        result = ResourceRecognizer().recognize_sprite(data, width=32)
        self.assertEqual(result['width'], 32)
        self.assertEqual(result['height'], 64)

    def test_width_with_remainder(self):
        """When width doesn't divide size evenly, height is floor division."""
        from pydbg.resource.recognizer import ResourceRecognizer
        data = b'\x00' * 100
        result = ResourceRecognizer().recognize_sprite(data, width=30)
        # 100 // 30 = 3 (floor division, remainder discarded)
        self.assertEqual(result['width'], 30)
        self.assertEqual(result['height'], 3)

    def test_candidate_dimensions(self):
        """Without width, returns list of possible dimension tuples."""
        from pydbg.resource.recognizer import ResourceRecognizer
        data = b'\x00' * 1024
        result = ResourceRecognizer().recognize_sprite(data)
        self.assertIsInstance(result, list)
        self.assertTrue(len(result) > 0)
        # 1024 = 32*32, 16*64, 64*16, etc.
        for w, h in result:
            self.assertEqual(w * h, 1024)

    def test_empty_data_no_width(self):
        """Empty data without width returns empty list."""
        from pydbg.resource.recognizer import ResourceRecognizer
        result = ResourceRecognizer().recognize_sprite(b'')
        self.assertEqual(result, [])

    def test_empty_data_with_width(self):
        """Empty data with width returns zero dimensions."""
        from pydbg.resource.recognizer import ResourceRecognizer
        result = ResourceRecognizer().recognize_sprite(b'', width=10)
        self.assertEqual(result['width'], 0)
        self.assertEqual(result['height'], 0)

    def test_width_zero(self):
        """Width of zero returns zero dimensions."""
        from pydbg.resource.recognizer import ResourceRecognizer
        data = b'\x00' * 100
        result = ResourceRecognizer().recognize_sprite(data, width=0)
        self.assertEqual(result['width'], 0)
        self.assertEqual(result['height'], 0)


if __name__ == "__main__":
    unittest.main()
