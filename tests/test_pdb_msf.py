"""Tests for the MSF 7.0 reader and the PDB info stream (spec §10.2, §10.3).

The reader is the validation shell the rest of pdb/ stands on. dbghelp accepts
a PDB from a different build without complaint — the only symptom is a handful
of wrong symbols — so "is this a well-formed MSF, and does its info stream name
the same build" has to be answered here, in Python.

Synthetic fixtures come from tests/pdb_builder.py. The real-PDB case takes
TEST_PDB_PATH / TEST_PDB_TARGET_PATH from the meson build and skips with a
"target not built:" reason when they are absent, as the suite requires.
"""

import os
import tempfile
import unittest

from pydbg.pdb import MSFFile, PdbFormatError
from tests.pdb_builder import (
    BLOCK_SIZES, SAMPLE_GUID_BYTES, SAMPLE_GUID_TEXT, build_msf,
    patch_field, pdb_info_stream,
)


def write_file(directory, data, name="synthetic.pdb"):
    """Write 'data' into 'directory' and return the path.

    No handle is kept: MSFFile reads what it needs and closes, so the temporary
    directory can delete the file on Windows without a share violation.
    """
    path = os.path.join(directory, name)
    with open(path, "wb") as handle:
        handle.write(data)
    return path


class MSFCase(unittest.TestCase):
    """Open synthetic containers from a per-test temporary directory."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)

    def open_pdb(self, data, name="synthetic.pdb"):
        return MSFFile(write_file(self._directory.name, data, name))


class TestReadStream(MSFCase):
    def test_reads_one_stream_byte_for_byte(self):
        stream = pdb_info_stream()
        msf = self.open_pdb(build_msf({1: stream}))
        self.assertEqual(msf.block_size, 4096)
        self.assertEqual(msf.stream_count, 2)
        self.assertEqual(msf.stream_size(1), len(stream))
        self.assertEqual(msf.read_stream(1), stream)

    def test_every_supported_block_size_reads_the_same_streams(self):
        streams = {
            0: b"",
            1: pdb_info_stream(),
            2: bytes(range(256)) * ((4096 + 77) // 256 + 1),
            3: b"tail",
        }
        for block_size in BLOCK_SIZES:
            with self.subTest(block_size=block_size):
                msf = self.open_pdb(
                    build_msf(streams, block_size), name=f"bs{block_size}.pdb")
                self.assertEqual(msf.block_size, block_size)
                self.assertEqual(msf.stream_count, len(streams))
                for index, expected in streams.items():
                    self.assertEqual(msf.stream_size(index), len(expected))
                    self.assertEqual(msf.read_stream(index), expected)

    def test_empty_and_nil_streams_both_read_as_empty(self):
        # Index 0 is present and empty; index 2 is missing from the mapping and
        # so is the nil stream (0xFFFFFFFF). The format keeps them apart; the
        # reader reports 0 bytes for both.
        msf = self.open_pdb(build_msf({0: b"", 1: pdb_info_stream(),
                                       3: b"present"}))
        self.assertEqual(msf.stream_count, 4)
        for index in (0, 2):
            with self.subTest(index=index):
                self.assertEqual(msf.stream_size(index), 0)
                self.assertEqual(msf.read_stream(index), b"")
        self.assertEqual(msf.read_stream(3), b"present")


class TestPdbInfo(MSFCase):
    def test_info_reads_the_fixed_header_at_the_measured_offsets(self):
        msf = self.open_pdb(build_msf({1: pdb_info_stream()}))
        info = msf.info
        self.assertEqual(info.version, 20000404)
        self.assertEqual(info.signature, 0x6B030339)
        self.assertEqual(info.age, 2)
        self.assertEqual(info.guid_bytes, SAMPLE_GUID_BYTES)
        # The expected text is the bytes_le rendering from research §A3; using
        # bytes= would produce a different, also-plausible GUID.
        self.assertEqual(info.guid, SAMPLE_GUID_TEXT)

    def test_an_unknown_version_is_reported_rather_than_rejected(self):
        # GUID and age sit at fixed offsets regardless of version, so an
        # unfamiliar version is explicit unknown, not a bad file.
        msf = self.open_pdb(
            build_msf({1: pdb_info_stream(version=19990903, age=7)}))
        self.assertEqual(msf.info.version, 19990903)
        self.assertEqual(msf.info.age, 7)

    def test_info_ignores_the_data_after_the_header(self):
        stream = pdb_info_stream(trailing=b"/LinkInfo\x00/TMCache\x00")
        msf = self.open_pdb(build_msf({1: stream}))
        self.assertEqual(msf.info.guid, SAMPLE_GUID_TEXT)


class TestFormatErrors(MSFCase):
    """Every structural failure is a PdbFormatError that names its reason.

    The expected fragments are the short reason strings from research §A5, so a
    drift in either the rule or its message fails here instead of surfacing as a
    DBGHELP-style handful of wrong symbols.
    """

    def assert_rejected(self, data, fragment, name="bad.pdb"):
        with self.assertRaises(PdbFormatError) as caught:
            self.open_pdb(data, name)
        self.assertIn(fragment, str(caught.exception))
        return caught.exception

    def test_truncated_superblock(self):
        self.assert_rejected(b"\x00" * 20, "truncated superblock")

    def test_bad_magic(self):
        data = build_msf({}, magic=b"Microsoft C/C++ MSF 6.00\r\n\x1aDS")
        self.assert_rejected(data, "not a PDB 7.0 file")

    def test_unsupported_block_size(self):
        data = build_msf({}, block_size=8192)
        self.assert_rejected(data, "unsupported block size 8192")

    def test_invalid_free_block_map_index(self):
        data = build_msf({}, free_block_map=3)
        self.assert_rejected(data, "invalid free block map index 3")

    def test_unknown1_is_an_explicit_unknown_not_a_guess(self):
        data = build_msf({}, unknown1=1)
        self.assert_rejected(data, "directory page-list indirection")

    def test_directory_size_not_aligned(self):
        data = build_msf({1: pdb_info_stream()}, block_size=512)
        data = patch_field(data, 44, "<I", 6)
        self.assert_rejected(data, "not 4-byte aligned")

    def test_too_many_directory_blocks(self):
        data = build_msf({1: pdb_info_stream()}, block_size=512)
        data = patch_field(data, 44, "<I", 512 * 512)
        self.assert_rejected(data, "too many directory blocks")

    def test_block_count_must_match_file_size(self):
        data = build_msf({1: pdb_info_stream()})
        num_blocks = len(data) // 4096
        self.assert_rejected(patch_field(data, 40, "<I", num_blocks + 1),
                             "block count does not match file size")

    def test_file_cut_mid_block(self):
        data = build_msf({1: pdb_info_stream()})
        self.assert_rejected(data[:len(data) - 100], "not block aligned")

    def test_block_map_at_reserved_block_zero(self):
        data = build_msf({1: pdb_info_stream()})
        self.assert_rejected(patch_field(data, 52, "<I", 0),
                             "block map at reserved block 0")

    def test_block_map_out_of_range(self):
        data = build_msf({1: pdb_info_stream()})
        num_blocks = len(data) // 4096
        self.assert_rejected(patch_field(data, 52, "<I", num_blocks),
                             "block map out of range")

    def test_directory_page_out_of_range(self):
        data = build_msf({1: pdb_info_stream()}, block_size=512)
        self.assert_rejected(patch_field(data, 3 * 512, "<I", 0xFFFF),
                             "directory page out of range")

    def test_truncated_stream_table(self):
        data = build_msf({1: pdb_info_stream()}, block_size=512)
        data = patch_field(data, 4 * 512, "<I", 0x1000)
        self.assert_rejected(data, "truncated stream table")

    def test_truncated_stream_directory(self):
        # Declaring one more stream than the directory holds makes the last
        # size field consume a page number, so the page list runs past the end.
        data = build_msf({1: pdb_info_stream()}, block_size=512)
        data = patch_field(data, 4 * 512, "<I", 3)
        self.assert_rejected(data, "truncated stream directory")

    def test_stream_page_out_of_range(self):
        data = build_msf({1: pdb_info_stream()}, block_size=512)
        # count(4) + two sizes(8) then stream 1's single page number.
        data = patch_field(data, 4 * 512 + 12, "<I", 0xFFFF)
        self.assert_rejected(data, "stream 1 page out of range")

    def test_stream_index_out_of_range(self):
        msf = self.open_pdb(build_msf({1: pdb_info_stream()}))
        for index in (-1, msf.stream_count):
            with self.subTest(index=index):
                with self.assertRaises(PdbFormatError) as caught:
                    msf.read_stream(index)
                self.assertIn("out of range", str(caught.exception))

    def test_missing_info_stream(self):
        msf = self.open_pdb(build_msf({0: b""}))
        with self.assertRaises(PdbFormatError) as caught:
            _ = msf.info
        self.assertIn("missing PDB info stream", str(caught.exception))

    def test_info_stream_shorter_than_its_header(self):
        msf = self.open_pdb(build_msf({1: b"\x01\x02\x03"}))
        with self.assertRaises(PdbFormatError) as caught:
            _ = msf.info
        self.assertIn("missing PDB info stream", str(caught.exception))


class TestRealPdb(unittest.TestCase):
    """A compiler-written PDB, not a synthetic one.

    The synthetic fixtures prove the layout logic; only a real file proves the
    reader against what MSVC's writer actually produced. Both paths come from
    the meson build (spec §10.6(8)) and the case skips — loudly — when it was
    never built.
    """

    def setUp(self):
        pdb_path = os.environ.get("TEST_PDB_PATH")
        image_path = os.environ.get("TEST_PDB_TARGET_PATH")
        if not pdb_path or not os.path.isfile(pdb_path):
            self.skipTest("target not built: pdb_target.pdb (meson); "
                          "set TEST_PDB_PATH")
        if not image_path or not os.path.isfile(image_path):
            self.skipTest("target not built: pdb_target.exe (meson); "
                          "set TEST_PDB_TARGET_PATH")
        self.pdb_path = pdb_path
        self.image_path = image_path

    def test_info_matches_the_codeview_record_of_its_image(self):
        from pydbg.pe import PE

        msf = MSFFile(self.pdb_path)
        self.assertGreater(msf.stream_count, 10)
        info = msf.info
        self.assertGreaterEqual(info.age, 1)

        entries = PE.from_file(self.image_path).codeview_entries
        self.assertTrue(entries, "image has no CodeView record")
        self.assertEqual(info.guid, entries[0].guid)
