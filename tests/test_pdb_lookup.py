"""Tests for PDB discovery and GUID/age validation (spec §10.2(1), §10.3, §10.6(2)).

dbghelp accepts a PDB from a different build without complaint, so "which PDB
belongs to this image, and is it the same build" has to be answered here.
These tests drive that through the public entry points: `Pdb.matches`,
`find` and `open_for`.

Synthetic fixtures come from tests/pdb_builder.py; a stub image stands in for
the PE with the two things the lookup may read — `codeview_entries()` and
`path`. The real-PDB case takes TEST_PDB_PATH / TEST_PDB_TARGET_PATH from the
meson build and skips with a "target not built:" reason when they are absent.
"""

import os
import tempfile
import unittest
from types import SimpleNamespace

from pydbg.pe import CodeViewInfo
from pydbg.pdb import Pdb, PdbLookup, find, open_for
from tests.pdb_builder import (
    INFO_STREAM_AGE, SAMPLE_GUID_BYTES, SAMPLE_GUID_TEXT, build_msf,
    info_guid_offset, pdb_info_stream,
)

OTHER_GUID_TEXT = "B30D707C-054A-43FE-8F7D-B696349E3F16"


def write_file(directory, data, name):
    """Write 'data' into 'directory' and return the path."""
    path = os.path.join(directory, name)
    with open(path, "wb") as handle:
        handle.write(data)
    return path


def synthetic_pdb_bytes(age=INFO_STREAM_AGE, guid=SAMPLE_GUID_BYTES):
    """A minimal MSF 7.0 container whose info stream names one build."""
    return build_msf({1: pdb_info_stream(age=age, guid=guid)})


def rsds_entry(pdb_path="C:/build/target.pdb", guid=SAMPLE_GUID_TEXT,
               age=INFO_STREAM_AGE):
    """The image-side identity a current MSVC build records."""
    return CodeViewInfo(signature="RSDS", pdb_path=pdb_path, age=age,
                        guid=guid)


class StubImage:
    """Duck-typed image: the ticket's `codeview_entries()` method plus `path`."""

    def __init__(self, entries=(), path=None):
        self._entries = list(entries)
        self.path = path

    def codeview_entries(self):
        return list(self._entries)


class LookupCase(unittest.TestCase):
    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)

    @property
    def directory(self):
        return self._directory.name

    def write_pdb(self, name="target.pdb", **kwargs):
        return write_file(self.directory, synthetic_pdb_bytes(**kwargs), name)


class TestPdbMatches(LookupCase):
    def test_matches_the_image_whose_codeview_record_names_the_same_build(self):
        pdb = Pdb(self.write_pdb())
        image = StubImage([rsds_entry()])
        self.assertTrue(pdb.matches(image))

    def test_matches_when_only_the_guid_text_is_available(self):
        # CodeViewInfo carries the rendered GUID, not raw bytes; the fallback
        # compares the 8-4-4-4-12 strings case-insensitively.
        pdb = Pdb(self.write_pdb())
        image = StubImage([rsds_entry(guid=SAMPLE_GUID_TEXT.lower())])
        self.assertTrue(pdb.matches(image))

    def test_a_different_age_is_a_mismatch(self):
        pdb = Pdb(self.write_pdb())
        image = StubImage([rsds_entry(age=INFO_STREAM_AGE + 1)])
        self.assertFalse(pdb.matches(image))

    def test_a_different_guid_is_a_mismatch(self):
        pdb = Pdb(self.write_pdb())
        image = StubImage([rsds_entry(guid=OTHER_GUID_TEXT)])
        self.assertFalse(pdb.matches(image))

    def test_an_image_without_a_codeview_record_never_matches(self):
        pdb = Pdb(self.write_pdb())
        self.assertFalse(pdb.matches(StubImage([])))

    def test_an_nb10_record_never_matches(self):
        # PDB 2.0 has no GUID, so sameness cannot be proven either way.
        pdb = Pdb(self.write_pdb())
        entry = CodeViewInfo(signature="NB10", pdb_path="C:/build/old.pdb",
                             age=INFO_STREAM_AGE, timestamp=0x1234)
        self.assertFalse(pdb.matches(StubImage([entry])))


class TestFind(LookupCase):
    def test_finds_and_verifies_the_pdb_recorded_in_codeview(self):
        pdb_path = self.write_pdb()
        image = StubImage([rsds_entry(pdb_path=pdb_path)])
        lookup = find(image)
        self.assertIsNone(lookup.reason)
        self.assertIsInstance(lookup, PdbLookup)
        self.assertIsInstance(lookup.pdb, Pdb)
        self.assertEqual(lookup.pdb.path, pdb_path)
        self.assertEqual(lookup.path, pdb_path)

    def test_open_for_is_the_lookup_without_the_reason(self):
        pdb_path = self.write_pdb()
        image = StubImage([rsds_entry(pdb_path=pdb_path)])
        found = open_for(image)
        self.assertIsInstance(found, Pdb)
        self.assertEqual(found.path, find(image).path)
        self.assertIsNone(open_for(StubImage([rsds_entry(
            pdb_path=pdb_path, age=INFO_STREAM_AGE + 1)])))

    def test_the_pdb_is_verified_against_the_image_not_just_opened(self):
        pdb_path = self.write_pdb()
        image = StubImage([rsds_entry(pdb_path=pdb_path, age=INFO_STREAM_AGE + 1)])
        lookup = find(image)
        self.assertIsNone(lookup.pdb)
        self.assertEqual(lookup.reason, "pdb mismatch")
        # The file that was inspected is still reported for diagnosis.
        self.assertEqual(lookup.path, pdb_path)
        self.assertIsNone(open_for(image))

    def test_a_changed_guid_is_a_pdb_mismatch(self):
        pdb_path = self.write_pdb()
        image = StubImage([rsds_entry(pdb_path=pdb_path, guid=OTHER_GUID_TEXT)])
        self.assertEqual(find(image).reason, "pdb mismatch")

    def test_the_lookup_keeps_the_image_base_for_the_symbol_reader(self):
        pdb_path = self.write_pdb()
        image = StubImage([rsds_entry(pdb_path=pdb_path)])
        image.image_base = 0x140000000
        self.assertEqual(find(image).pdb.image_base, 0x140000000)


class TestFindReasons(LookupCase):
    def test_an_image_with_no_codeview_reports_no_codeview(self):
        lookup = find(StubImage([]))
        self.assertIsNone(lookup.pdb)
        self.assertIsNone(lookup.path)
        self.assertEqual(lookup.reason, "no codeview")

    def test_a_recorded_path_that_does_not_exist_is_not_found(self):
        missing = os.path.join(self.directory, "gone.pdb")
        lookup = find(StubImage([rsds_entry(pdb_path=missing)]))
        self.assertIsNone(lookup.pdb)
        self.assertIsNone(lookup.path)
        self.assertEqual(lookup.reason, "not found")
        # The diagnostic says what was searched, without changing the reason.
        self.assertIn(missing, lookup.message)

    def test_a_directory_in_place_of_a_pdb_is_not_found(self):
        # isfile() is the test, so a directory is not a candidate file.
        directory = os.path.join(self.directory, "target.pdb")
        os.mkdir(directory)
        lookup = find(StubImage([rsds_entry(pdb_path=directory)]))
        self.assertEqual(lookup.reason, "not found")

    def test_an_nb10_record_is_unsupported_rather_than_guessed(self):
        entry = CodeViewInfo(signature="NB10", pdb_path="C:/build/old.pdb",
                             age=INFO_STREAM_AGE, timestamp=0x1234)
        lookup = find(StubImage([entry]))
        self.assertIsNone(lookup.pdb)
        self.assertEqual(lookup.reason, "pdb 2.0 unsupported")

    def test_a_file_that_is_not_a_pdb_is_bad_pdb(self):
        # Long enough for the superblock, so the magic is what fails.
        path = write_file(self.directory, b"\x00" * 64, "broken.pdb")
        lookup = find(StubImage([rsds_entry(pdb_path=path)]))
        self.assertIsNone(lookup.pdb)
        self.assertEqual(lookup.reason, "bad pdb")
        # The path was right; the file was not, so it is reported.
        self.assertEqual(lookup.path, path)
        self.assertIn("not a PDB 7.0", lookup.message)

    def test_a_pdb_without_an_info_stream_is_bad_pdb(self):
        path = write_file(self.directory, build_msf({0: b""}), "no-info.pdb")
        lookup = find(StubImage([rsds_entry(pdb_path=path)]))
        self.assertEqual(lookup.reason, "bad pdb")
        self.assertIn("missing PDB info stream", lookup.message)

    def test_a_mismatch_names_both_identities_for_diagnosis(self):
        pdb_path = self.write_pdb()
        image = StubImage([rsds_entry(pdb_path=pdb_path, guid=OTHER_GUID_TEXT)])
        lookup = find(image)
        self.assertEqual(lookup.reason, "pdb mismatch")
        self.assertIn(SAMPLE_GUID_TEXT, lookup.message)
        self.assertIn(OTHER_GUID_TEXT, lookup.message)


class TestSearchOrder(LookupCase):
    def test_a_search_path_wins_over_the_recorded_absolute_path(self):
        recorded = write_file(self.directory, synthetic_pdb_bytes(age=3),
                              "recorded.pdb")
        explicit = write_file(self.directory, synthetic_pdb_bytes(),
                              "explicit.pdb")
        image = StubImage([rsds_entry(pdb_path=recorded)])
        lookup = find(image, search_paths=[explicit])
        self.assertIsNone(lookup.reason)
        self.assertEqual(lookup.path, explicit)
        self.assertEqual(lookup.pdb.path, explicit)

    def test_a_mismatching_search_path_stops_the_search(self):
        # An explicit override that is the wrong build must be reported, not
        # silently replaced by the correct PDB at the recorded path.
        good = self.write_pdb("recorded.pdb")
        wrong = write_file(self.directory, synthetic_pdb_bytes(age=3),
                           "explicit.pdb")
        image = StubImage([rsds_entry(pdb_path=good)])
        lookup = find(image, search_paths=[wrong])
        self.assertEqual(lookup.reason, "pdb mismatch")
        self.assertEqual(lookup.path, wrong)

    def test_search_paths_are_tried_in_the_given_order(self):
        first = write_file(self.directory, synthetic_pdb_bytes(age=3),
                           "first.pdb")
        second = write_file(self.directory, synthetic_pdb_bytes(), "second.pdb")
        image = StubImage([rsds_entry(pdb_path="C:/gone/target.pdb")])
        lookup = find(image, search_paths=[first, second])
        self.assertEqual(lookup.path, first)
        self.assertEqual(lookup.reason, "pdb mismatch")

    def test_a_missing_search_path_is_skipped(self):
        good = self.write_pdb("recorded.pdb")
        image = StubImage([rsds_entry(pdb_path=good)])
        lookup = find(image, search_paths=[
            os.path.join(self.directory, "absent.pdb")])
        self.assertIsNone(lookup.reason)
        self.assertEqual(lookup.path, good)

    def test_the_recorded_path_wins_over_the_image_directory(self):
        recorded = self.write_pdb("recorded.pdb")
        write_file(self.directory, synthetic_pdb_bytes(age=3), "target.pdb")
        image = StubImage([rsds_entry(pdb_path=recorded)],
                          path=os.path.join(self.directory, "target.exe"))
        self.assertEqual(find(image).path, recorded)

    def test_the_image_directory_pdb_is_the_last_resort(self):
        sibling = self.write_pdb("target.pdb")
        image = StubImage([rsds_entry(pdb_path="Z:/gone/target.pdb")],
                          path=os.path.join(self.directory, "target.exe"))
        lookup = find(image)
        self.assertIsNone(lookup.reason)
        self.assertEqual(lookup.path, sibling)


class TestDuckTypedInputs(LookupCase):
    class PropertyImage:
        """An image that exposes codeview_entries as a property, like PE does."""

        def __init__(self, entries):
            self._entries = list(entries)

        @property
        def codeview_entries(self):
            return list(self._entries)

    def test_an_analysis_wrapper_is_unwrapped_through_pe(self):
        pdb_path = self.write_pdb()
        image = StubImage([rsds_entry(pdb_path=pdb_path)])
        wrapper = SimpleNamespace(pe=image)
        self.assertIsNone(find(wrapper).reason)
        self.assertTrue(Pdb(pdb_path).matches(wrapper))

    def test_codeview_entries_may_be_a_property(self):
        pdb_path = self.write_pdb()
        image = self.PropertyImage([rsds_entry(pdb_path=pdb_path)])
        self.assertIsNone(find(image).reason)

    def test_raw_guid_bytes_are_compared_when_the_record_has_them(self):
        pdb_path = self.write_pdb()
        entry = SimpleNamespace(signature="RSDS", pdb_path=pdb_path,
                                age=INFO_STREAM_AGE,
                                guid_bytes=SAMPLE_GUID_BYTES)
        self.assertIsNone(find(StubImage([entry])).reason)
        self.assertTrue(Pdb(pdb_path).matches(StubImage([entry])))

    def test_one_changed_raw_guid_byte_is_a_mismatch(self):
        pdb_path = self.write_pdb()
        changed = bytes([SAMPLE_GUID_BYTES[0] ^ 0xFF]) + SAMPLE_GUID_BYTES[1:]
        entry = SimpleNamespace(signature="RSDS", pdb_path=pdb_path,
                                age=INFO_STREAM_AGE, guid_bytes=changed)
        self.assertEqual(find(StubImage([entry])).reason, "pdb mismatch")

    def test_raw_bytes_win_over_a_stale_rendered_guid(self):
        # The bytes are the identity; the rendered string is display only.
        pdb_path = self.write_pdb()
        entry = SimpleNamespace(signature="RSDS", pdb_path=pdb_path,
                                age=INFO_STREAM_AGE,
                                guid_bytes=SAMPLE_GUID_BYTES,
                                guid=OTHER_GUID_TEXT)
        self.assertIsNone(find(StubImage([entry])).reason)

    def test_an_rsds_record_after_an_nb10_record_is_still_used(self):
        pdb_path = self.write_pdb()
        nb10 = CodeViewInfo(signature="NB10", pdb_path="C:/build/old.pdb",
                            age=INFO_STREAM_AGE, timestamp=0x1234)
        image = StubImage([nb10, rsds_entry(pdb_path=pdb_path)])
        self.assertIsNone(find(image).reason)


class TestRealPdb(unittest.TestCase):
    """A compiler-written PDB, not a synthetic one.

    The synthetic fixtures prove the lookup logic; only a real image/PDB pair
    proves the identity comparison against what MSVC's writer actually
    produced. Both paths come from the meson build (spec §10.6(8)) and the
    case skips — loudly — when it was never built.
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
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)

    def test_finds_and_verifies_the_real_pdb(self):
        from pydbg.pe import PE

        pe = PE.from_file(self.image_path)
        lookup = find(pe)
        self.assertIsNone(lookup.reason, lookup.message)
        self.assertIsNotNone(lookup.pdb)
        self.assertTrue(lookup.pdb.matches(pe))
        self.assertTrue(os.path.isfile(lookup.pdb.path))
        self.assertEqual(lookup.pdb.path, find(pe).pdb.path)

    def test_a_guid_edited_copy_is_a_pdb_mismatch(self):
        from pydbg.pe import PE

        with open(self.pdb_path, "rb") as handle:
            data = bytearray(handle.read())
        data[info_guid_offset(data)] ^= 0xFF
        mutated = write_file(self._directory.name, bytes(data), "mutated.pdb")

        pe = PE.from_file(self.image_path)
        lookup = find(pe, search_paths=[mutated])
        self.assertEqual(lookup.reason, "pdb mismatch")
        self.assertEqual(lookup.path, mutated)
        self.assertIsNone(open_for(pe, search_paths=[mutated]))
        # The untouched original still verifies, so the edit is what failed.
        self.assertTrue(Pdb(self.pdb_path).matches(pe))


if __name__ == "__main__":
    unittest.main()
