"""Tests for PE resource directory parser."""

import os
import struct
import unittest

from tests.pe_builder import (
    RESOURCE_RVA, build_resource_image,
)

# One RT_RCDATA payload; the shared builder puts it at RESOURCE_DATA_OFFSET
# inside .rsrc, so its RVA is RESOURCE_RVA + 0x58.
RESOURCE_DATA = b"\xDE\xAD\xBE\xEF" * 4


def build_pe_with_resources():
    """A synthetic PE32+ with a .rsrc holding one RT_RCDATA resource.

    The tree (type 10 -> name 100 -> language 0x0409 -> data) is built by
    tests/pe_builder.build_resource_image, which tests/test_pe_version.py
    uses for its RT_VERSION image too: one builder, two resource types.
    """
    return (build_resource_image(10, RESOURCE_DATA, name_id=100),
            RESOURCE_DATA)


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
        from pydbg.pe.resource import ResourceEntry
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
        from pydbg.pe.resource import ResourceEntry
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
        from pydbg.pe.resource import RESOURCE_TYPES
        self.assertEqual(RESOURCE_TYPES[1], "RT_CURSOR")
        self.assertEqual(RESOURCE_TYPES[2], "RT_BITMAP")
        self.assertEqual(RESOURCE_TYPES[10], "RT_RCDATA")
        self.assertEqual(RESOURCE_TYPES[24], "RT_MANIFEST")

    def test_rt_version_has_one_definition(self):
        """The type ID lives beside the type table; version.py imports it.

        A second literal in version.py is a second answer to "which resource
        is a version resource", and the two could drift.
        """
        from pydbg.pe import version
        from pydbg.pe.resource import RESOURCE_TYPES, RT_VERSION

        self.assertEqual(RESOURCE_TYPES[RT_VERSION], "RT_VERSION")
        self.assertIs(version.RT_VERSION, RT_VERSION)


class TestPEResourceParser(unittest.TestCase):
    """Tests for PEResourceParser with synthetic PE data."""

    def test_parse_resources(self):
        """Parse finds 1 resource with correct type/name/size."""
        from pydbg.pe import PE
        from pydbg.pe.resource import PEResourceParser

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
        from pydbg.pe.resource import PEResourceParser

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
        from pydbg.pe.resource import PEResourceParser

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
        from pydbg.pe.resource import PEResourceParser

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
        from pydbg.pe.resource import PEResourceParser

        pe_data = build_pe_without_resources()
        pe = PE(pe_data)
        parser = PEResourceParser(pe)
        entries = parser.parse()

        self.assertEqual(entries, [])

    def test_parse_is_idempotent(self):
        """Calling parse() twice returns the same result."""
        from pydbg.pe import PE
        from pydbg.pe.resource import PEResourceParser

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
        from pydbg.pe.resource import PEResourceParser

        pe_data, _ = build_pe_with_resources()
        pe = PE(pe_data)
        parser = PEResourceParser(pe)
        entries = parser.parse()

        # The shared builder lays .rsrc out with raw offset == RVA (0x3000),
        # so the data at RVA 0x3058 is at file offset 0x3058 as well.
        self.assertEqual(entries[0].data_offset, 0x3058)


class TestResourceParserRobustness(unittest.TestCase):
    """The tree is self-relative offsets with no terminator and no length.

    So a truncated or tangling .rsrc is not a hypothetical: it is what packed
    and hand-edited images actually contain. The answer has to be the entries
    that were readable, not an exception out of the middle of a walk.
    """

    RSRC_FILE_OFFSET = RESOURCE_RVA     # see build_pe_with_resources

    def test_pe_facade_exposes_the_tree(self):
        from pydbg.pe import PE

        pe_data, expected = build_pe_with_resources()
        pe = PE(pe_data)
        entries = pe.resources
        self.assertEqual(len(entries), 1)
        self.assertEqual(pe.resource_parser().extract(entries[0]), expected)

    def test_truncated_tree_stops_instead_of_raising(self):
        """Chop the image so the language directory is not readable.

        Before, every read here went to Source.read, which for an in-memory
        image raises past the end — so meeting a truncated tree meant an
        exception from three frames down rather than a short answer.
        """
        from pydbg.pe import PE

        pe_data, _ = build_pe_with_resources()
        # Keep the type directory, cut before the name directory.
        cut = pe_data[:self.RSRC_FILE_OFFSET + 0x18]
        self.assertEqual(PE(cut).resources, [])

    def test_directory_pointing_at_itself_terminates(self):
        """A cycle is free to read and never ends on its own."""
        from pydbg.pe import PE

        pe_data = bytearray(build_pe_with_resources()[0])
        # First type-level entry's DataOrSubdirOffset -> the type directory's
        # own offset, so every level walks the same node again.
        entry_at = self.RSRC_FILE_OFFSET + 16
        struct.pack_into("<I", pe_data, entry_at + 4, 0x80000000 | 0x0000)
        self.assertEqual(PE(bytes(pe_data)).resources, [])

    def test_unreadable_data_raises_rather_than_short_slicing(self):
        """extract() must not hand back something that looks like the data."""
        from pydbg.pe import PE
        from pydbg.pe.resource import PEResourceParser

        pe_data, _ = build_pe_with_resources()
        pe = PE(pe_data[:self.RSRC_FILE_OFFSET + 0x58])   # data cut off
        entries = PE(pe_data).resources
        parser = PEResourceParser(pe)
        with self.assertRaises(ValueError):
            parser.extract(entries[0])


class TestResourceRealImage(unittest.TestCase):
    """A synthetic tree proves the walk; only a real .rsrc proves the layout.

    kernel32 is a useful target precisely because it does not look like the
    fixture: its manifest sits under the *named* type 'MUI', not under
    RT_MANIFEST the way an application's does. That is where a parser which
    only understood numeric type IDs gets caught, and the first version of
    this test asserted RT_MANIFEST and failed for exactly that reason.
    """

    KERNEL32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                            "System32", "kernel32.dll")

    def setUp(self):
        if not os.path.exists(self.KERNEL32):
            self.skipTest(f"environment: no system DLL at {self.KERNEL32}")
        from pydbg.pe import PE
        self.pe = PE.from_file(self.KERNEL32)

    def test_kernel32_resources_are_readable(self):
        entries = self.pe.resources
        self.assertTrue(entries, "kernel32.dll has a .rsrc")
        by_name = {entry.type_name: entry for entry in entries}
        self.assertIn("RT_VERSION", by_name)
        self.assertIn("MUI", by_name)
        # A named type has no ID, and 0 is how that is spelled. Inventing a
        # number instead would let get_by_type() match it.
        self.assertEqual(by_name["MUI"].type_id, 0)

    def test_extracted_resource_matches_its_declared_size(self):
        parser = self.pe.resource_parser()
        for name in ("RT_VERSION", "MUI"):
            for entry in parser.get_by_name(name):
                self.assertEqual(len(parser.extract(entry)), entry.data_size)


class TestGuessExtension(unittest.TestCase):
    """Tests for the _guess_extension helper."""

    def test_riff_wav(self):
        from pydbg.pe.resource import _guess_extension as guess
        self.assertEqual(guess(b"RIFF\x00\x00\x00\x00"), ".wav")

    def test_bmp(self):
        from pydbg.pe.resource import _guess_extension as guess
        self.assertEqual(guess(b"BM\x00\x00"), ".bmp")

    def test_unknown_bin(self):
        from pydbg.pe.resource import _guess_extension as guess
        self.assertEqual(guess(b"\x00\x00\x00\x00"), ".bin")

    def test_short_data(self):
        from pydbg.pe.resource import _guess_extension as guess
        self.assertEqual(guess(b"\x00"), ".bin")
        self.assertEqual(guess(b""), ".bin")


if __name__ == "__main__":
    unittest.main()
