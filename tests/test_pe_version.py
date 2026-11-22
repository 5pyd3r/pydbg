"""Tests for RT_VERSION decoding — VS_VERSIONINFO into fixed info and strings.

The version resource is the one place a PE says, in a machine-readable way,
what it claims to be and who built it. It is also a tree of length-delimited
nodes whose value lengths are counted in different units at every level, which
is why the fixtures here are assembled node by node from the format's rules
rather than copied from a hex dump.
"""

import os
import struct
import unittest

from pydbg.pe.resource import RT_VERSION

from tests.pe_builder import (
    PEBuilder, RESOURCE_DATA_OFFSET, RESOURCE_RVA, build_resource_image,
)


def _utf16z(text):
    """A Windows string: UTF-16LE plus the terminating NUL."""
    return text.encode("utf-16-le") + b"\x00\x00"


def _align4(offset):
    return (offset + 3) & ~3


def version_node(key, value=b"", value_length=None, w_type=1, children=b""):
    """Assemble one VS_VERSIONINFO node; 'wLength' includes its padding.

    The value must start on a 4-byte boundary measured from the node start,
    and the 6-byte header makes that offset odd in a way that padding just the
    key would miss. 'value_length' is in whatever unit the caller's level
    defines: bytes by default, characters for a String node.
    """
    if value_length is None:
        value_length = len(value)
    body = bytearray(_utf16z(key))
    body += b"\x00" * (_align4(6 + len(body)) - (6 + len(body)))
    body += value
    body += b"\x00" * (_align4(6 + len(body)) - (6 + len(body)))
    body += children
    length = _align4(6 + len(body))
    blob = struct.pack("<HHH", length, value_length, w_type) + bytes(body)
    return blob + b"\x00" * (length - len(blob))


def string_node(key, text):
    """One String node: wValueLength counts UTF-16 characters incl. the NUL."""
    return version_node(key, _utf16z(text), value_length=len(text) + 1)


def string_table(lang, codepage, strings):
    children = b"".join(string_node(key, text) for key, text in strings.items())
    return version_node(f"{lang:04X}{codepage:04X}", children=children)


def string_file_info(tables):
    return version_node("StringFileInfo", children=b"".join(tables))


def var_file_info(translations):
    value = b"".join(struct.pack("<HH", lang, codepage)
                     for lang, codepage in translations)
    translation = version_node("Translation", value, w_type=0)
    return version_node("VarFileInfo", children=translation)


def fixed_file_info(signature=0xFEEF04BD, file_version=(1, 2, 3, 4),
                    product_version=(5, 6, 7, 8)):
    """The 13 DWORDs of VS_FIXEDFILEINFO, versions split into MS/LS halves."""
    def high(quad):
        return (quad[0] << 16) | quad[1]

    def low(quad):
        return (quad[2] << 16) | quad[3]

    return struct.pack(
        "<13I", signature, 0x00010000,
        high(file_version), low(file_version),
        high(product_version), low(product_version),
        0x3F, 0x00, 0x40004, 0x01, 0x00, 0x12345678, 0x9ABCDEF0)


def build_version_blob(fixed=None, tables=None, translations=None):
    """A complete VS_VERSIONINFO blob with one StringTable unless told else."""
    if fixed is None:
        fixed = fixed_file_info()
    if tables is None:
        tables = [string_table(0x0409, 1200,
                               {"CompanyName": "Acme Corp",
                                "FileDescription": "Widget"})]
    if translations is None:
        translations = [(0x0409, 1200)]
    children = string_file_info(tables) + var_file_info(translations)
    return version_node("VS_VERSION_INFO", fixed, w_type=0, children=children)


def build_pe_with_version_resource(blob=None):
    """A synthetic PE32+ whose .rsrc holds 'blob' under RT_VERSION.

    The tree comes from tests.pe_builder.build_resource_image, the same
    three-level builder tests/test_resource.py uses for its RT_RCDATA image;
    only the resource type, name, language and payload differ.
    """
    if blob is None:
        blob = build_version_blob()
    return build_resource_image(RT_VERSION, blob, name_id=1,
                                language_id=0x0409, code_page=1200)


class TestParseVersionInfo(unittest.TestCase):

    def test_fixed_info_and_strings_are_decoded(self):
        from pydbg.pe.version import parse_version_info

        info = parse_version_info(build_version_blob())
        self.assertIsNotNone(info)
        self.assertEqual(info.fixed.file_version, (1, 2, 3, 4))
        self.assertEqual(info.fixed.product_version, (5, 6, 7, 8))
        self.assertEqual(info.fixed.file_flags_mask, 0x3F)
        self.assertEqual(info.fixed.file_flags, 0x00)
        self.assertEqual(info.fixed.file_os, 0x40004)
        self.assertEqual(info.fixed.file_type, 0x01)
        self.assertEqual(info.fixed.file_subtype, 0x00)
        # dwFileDateMS and dwFileDateLS are one 64-bit value, not two.
        self.assertEqual(info.fixed.file_date, 0x123456789ABCDEF0)
        self.assertEqual(info.strings, {"CompanyName": "Acme Corp",
                                        "FileDescription": "Widget"})
        self.assertEqual(info.translations, [(0x0409, 1200)])
        self.assertEqual((info.language, info.codepage), (0x0409, 1200))

    def test_strings_come_from_the_first_table_and_all_translations_are_kept(self):
        """A merged image can carry several languages; only one map is 'the' map.

        Taking the first table keeps 'strings' meaning what it says — the
        values of one language — instead of a mixture where a later table
        silently overwrote an earlier one's key. The translations are the
        place where every language is reported.
        """
        from pydbg.pe.version import parse_version_info

        blob = build_version_blob(
            tables=[
                string_table(0x0409, 1200, {"CompanyName": "Acme Corp"}),
                string_table(0x0407, 1200, {"CompanyName": "Acme GmbH",
                                            "OnlyGerman": "ja"}),
            ],
            translations=[(0x0409, 1200), (0x0407, 1200)])
        info = parse_version_info(blob)
        self.assertEqual(info.strings, {"CompanyName": "Acme Corp"})
        self.assertEqual(info.translations, [(0x0409, 1200), (0x0407, 1200)])
        self.assertEqual((info.language, info.codepage), (0x0409, 1200))

    def test_wrong_signature_still_parses_the_string_tables(self):
        """The signature says 'this is not a VS_FIXEDFILEINFO', nothing more.

        Zeroing it must not throw away the string tables, which are a separate
        part of the resource and are what a version check usually reads.
        """
        from pydbg.pe.version import parse_version_info

        info = parse_version_info(build_version_blob(
            fixed=fixed_file_info(signature=0xDEADBEEF)))
        self.assertIsNotNone(info)
        self.assertIsNone(info.fixed)
        self.assertEqual(info.strings["CompanyName"], "Acme Corp")
        self.assertEqual(info.translations, [(0x0409, 1200)])

    def test_zero_length_root_is_none(self):
        """wLength is the only boundary the format gives; zero means no node."""
        from pydbg.pe.version import parse_version_info

        blob = bytearray(build_version_blob())
        struct.pack_into("<H", blob, 0, 0)
        self.assertIsNone(parse_version_info(bytes(blob)))

    def test_truncated_blob_returns_the_parsed_prefix(self):
        """Cut at the first child: the fixed info is whole, the tables are not.

        The honest answer is the prefix that was readable, and the test cuts
        exactly where the StringFileInfo node would start so the boundary is
        the fixture's, not the parser's.
        """
        from pydbg.pe.version import parse_version_info

        blob = build_version_blob()
        cut = blob.index(_utf16z("StringFileInfo")) - 6
        info = parse_version_info(blob[:cut])
        self.assertIsNotNone(info)
        self.assertEqual(info.fixed.file_version, (1, 2, 3, 4))
        self.assertEqual(info.strings, {})
        self.assertEqual(info.translations, [])

    def test_odd_length_truncation_does_not_raise(self):
        """A cut through a UTF-16 unit must cost the tail, not raise."""
        from pydbg.pe.version import parse_version_info

        blob = build_version_blob()
        self.assertIsNone(parse_version_info(blob[:5]))    # inside the header
        self.assertIsNone(parse_version_info(blob[:6]))    # no key at all
        self.assertIsNone(parse_version_info(blob[:7]))    # half a UTF-16 unit
        # A cut in the middle of the string tables keeps what was readable.
        info = parse_version_info(blob[:len(blob) // 2])
        self.assertIsNotNone(info)
        self.assertIsInstance(info.strings, dict)

    def test_garbage_is_none(self):
        from pydbg.pe.version import parse_version_info

        for data in (b"", b"\x00", b"\x00" * 6, b"not a version resource"):
            with self.subTest(data=data):
                self.assertIsNone(parse_version_info(data))


class TestPEVersionInfo(unittest.TestCase):

    def test_read_version_info_is_a_public_import(self):
        """PE.version_info delegates to it, so it belongs in the package's API.

        It was imported in pe/__init__.py but left out of __all__, which made
        the public surface depend on whether a caller used the name or the
        star-import.
        """
        import pydbg.pe as pe_package

        self.assertIn("read_version_info", pe_package.__all__)
        from pydbg.pe import read_version_info
        self.assertTrue(callable(read_version_info))

    def test_synthetic_image_matches_direct_parse(self):
        from pydbg.pe import PE
        from pydbg.pe.version import parse_version_info

        pe = PE(build_pe_with_version_resource())
        self.assertEqual(pe.version_info, parse_version_info(build_version_blob()))

    def test_parsed_once_and_remembered(self):
        from pydbg.pe import PE

        pe = PE(build_pe_with_version_resource())
        self.assertIs(pe.version_info, pe.version_info)

    def test_image_without_resources_is_none(self):
        from pydbg.pe import PE

        builder = PEBuilder()
        builder.add_section(".text", b"\x90" * 0x10, 0x1000)
        self.assertIsNone(PE(builder.build()).version_info)

    def test_resources_without_rt_version_is_none(self):
        """Another resource type is not a version resource."""
        from pydbg.pe import PE
        from tests.test_resource import build_pe_with_resources

        self.assertIsNone(PE(build_pe_with_resources()[0]).version_info)

    def test_unreadable_payload_is_none(self):
        """A data entry pointing past the file is None, not an exception."""
        from pydbg.pe import PE

        data = build_pe_with_version_resource()
        pe = PE(data[:RESOURCE_RVA + RESOURCE_DATA_OFFSET])
        self.assertIsNone(pe.version_info)


class TestRealImageVersionInfo(unittest.TestCase):
    """Only a real image proves the fixture resembles what a linker writes."""

    KERNEL32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                            "System32", "kernel32.dll")

    def setUp(self):
        if not os.path.exists(self.KERNEL32):
            self.skipTest(f"environment: no system DLL at {self.KERNEL32}")
        from pydbg.pe import PE
        self.pe = PE.from_file(self.KERNEL32)

    def test_kernel32_version_resource_is_decoded(self):
        info = self.pe.version_info
        self.assertIsNotNone(info)
        self.assertIsNotNone(info.fixed)
        self.assertIn("CompanyName", info.strings)
        self.assertIn("FileDescription", info.strings)
        self.assertTrue(info.translations)


if __name__ == "__main__":
    unittest.main()
