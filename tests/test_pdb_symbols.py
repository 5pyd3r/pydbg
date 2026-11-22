"""Tests for the offline dbghelp symbol reader (spec §10.2(2)(3)(5)(6), §10.3).

dbghelp is the symbol reader for a verified PDB, and it is used without a
debuggee: load the image, point dbghelp at the PDB's directory, enumerate.
The parts that decide what a symbol *is* — Tag to kind, NameLen trimming,
demangling, RVA range, duplicate removal — are pure functions, so they are
tested without dbghelp at all. The real-PDB case takes TEST_PDB_PATH /
TEST_PDB_TARGET_PATH from the meson build and skips with a "target not built:"
reason when they are absent, as the suite requires.
"""

import ctypes
import os
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from pydbg.pdb import Pdb, PdbError, dbghelp, find
from pydbg.pdb.dbghelp import (
    NAME_OFFSET, SYMBOL_INFOW, PdbSymbol, build_symbols, symbol_kind, trim_name,
)
from tests.pdb_builder import (
    INFO_STREAM_AGE, SAMPLE_GUID_TEXT, build_msf, pdb_info_stream,
)

# The enumeration callback's record: (tag, address, size, text, name_len).
# Tests feed these straight to build_symbols, which is the pure half of
# "SYMBOL_INFOW callback -> PdbSymbol" and needs no dbghelp at all.
BASE = 0x140000000
IMAGE_SIZE = 0x1000


def record(tag, rva, name="sym", size=0, name_len=None):
    """One raw enumeration record for a symbol at `rva` above BASE."""
    if name_len is None:
        name_len = len(name) + 1        # NameLen includes the terminating NUL
    return (tag, BASE + rva, size, name, name_len)


class TestSymbolKind(unittest.TestCase):
    def test_the_three_measured_tags_get_their_kinds(self):
        # cvconst.h: SymTagFunction=5, SymTagData=7, SymTagPublicSymbol=10.
        self.assertEqual(symbol_kind(5), "function")
        self.assertEqual(symbol_kind(7), "data")
        self.assertEqual(symbol_kind(10), "public")

    def test_any_other_tag_stays_unknown(self):
        # Type tags (UDT=11, Enum=12, BaseType=16) are not symbols at the top
        # level; if one appears it is reported as unknown, not mislabelled.
        for tag in (0, 1, 11, 12, 16, 24, 0xFFFFFFFF):
            with self.subTest(tag=tag):
                self.assertEqual(symbol_kind(tag), "unknown")


class TestTrimName(unittest.TestCase):
    def test_name_len_counts_the_terminating_nul(self):
        # Measured: NameLen == wcslen + 1 for every enumerated symbol.
        self.assertEqual(trim_name("add_numbers", 12), "add_numbers")

    def test_text_is_cut_to_name_len_minus_one(self):
        # NameLen 6 describes a 5-character name plus its NUL.
        self.assertEqual(trim_name("add_numbers", 6), "add_n")

    def test_a_zero_name_len_leaves_the_text_alone(self):
        # Defensive: a bogus NameLen must not turn every name into "".
        self.assertEqual(trim_name("helper", 0), "helper")


class TestBuildSymbols(unittest.TestCase):
    def test_each_tag_becomes_its_kind_and_only_public_is_public(self):
        symbols = build_symbols([
            record(5, 0x10, "fn"),
            record(7, 0x20, "g_value"),
            record(10, 0x30, "_imp_fn"),
        ], BASE, IMAGE_SIZE)
        self.assertEqual([symbol.kind for symbol in symbols],
                         ["function", "data", "public"])
        self.assertEqual([symbol.is_public for symbol in symbols],
                         [False, False, True])
        self.assertEqual([symbol.rva for symbol in symbols], [0x10, 0x20, 0x30])
        self.assertEqual(symbols[0], PdbSymbol(0x10, "fn", 0, "function", False))

    def test_an_unknown_tag_is_reported_unknown_not_relabelled(self):
        # SymTagTypedef is not a symbol dbghelp enumerates; keep it honest.
        symbols = build_symbols([record(17, 0x10, "MyInt")], BASE, IMAGE_SIZE)
        self.assertEqual(symbols[0].kind, "unknown")
        self.assertFalse(symbols[0].is_public)

    def test_the_name_is_trimmed_by_name_len(self):
        symbols = build_symbols([record(5, 0x10, "helper", name_len=4)],
                                BASE, IMAGE_SIZE)
        self.assertEqual(symbols[0].name, "hel")

    def test_a_rva_at_or_past_the_image_end_is_dropped(self):
        symbols = build_symbols([
            record(5, 0x00, "at_start"),
            record(5, 0x10, "inside"),
            record(5, IMAGE_SIZE, "at_end"),
            record(5, IMAGE_SIZE + 0x10, "past_end"),
        ], BASE, IMAGE_SIZE)
        self.assertEqual([symbol.name for symbol in symbols],
                         ["at_start", "inside"])

    def test_an_address_below_the_loaded_base_is_dropped(self):
        # Address 0 belongs to no image; Address-base is negative for it.
        records = [(5, 0, 8, "no_address", 11),
                   record(5, 0x10, "inside")]
        symbols = build_symbols(records, BASE, IMAGE_SIZE)
        self.assertEqual([symbol.name for symbol in symbols], ["inside"])

    def test_a_repeated_rva_and_name_keeps_the_first_record(self):
        # dbghelp reports the compiland record before the public alias; the
        # first one carries the real Tag and size.
        symbols = build_symbols([
            record(5, 0x10, "dup", size=5),
            record(10, 0x10, "dup", size=9),
        ], BASE, IMAGE_SIZE)
        self.assertEqual(len(symbols), 1)
        self.assertFalse(symbols[0].is_public)
        self.assertEqual(symbols[0].kind, "function")
        self.assertEqual(symbols[0].size, 5)

    def test_a_public_alias_never_decides_the_kind_even_if_listed_first(self):
        """Callback order is not a contract; the Tag is what a symbol means.

        dbghelp happens to list the compiland record first, but relying on
        that made `kind`/`is_public` depend on an implementation detail.
        """
        for tag, kind in ((5, "function"), (7, "data")):
            with self.subTest(tag=tag):
                symbols = build_symbols([
                    record(10, 0x10, "dup", size=9),
                    record(tag, 0x10, "dup", size=5),
                ], BASE, IMAGE_SIZE)
                self.assertEqual(len(symbols), 1)
                self.assertFalse(symbols[0].is_public)
                self.assertEqual(symbols[0].kind, kind)
                self.assertEqual(symbols[0].size, 5)

    def test_the_same_rva_with_different_names_is_kept(self):
        symbols = build_symbols([
            record(5, 0x10, "first"),
            record(10, 0x10, "alias"),
        ], BASE, IMAGE_SIZE)
        self.assertEqual([symbol.name for symbol in symbols],
                         ["alias", "first"])

    def test_the_tuple_is_ordered_by_rva_then_name(self):
        symbols = build_symbols([
            record(5, 0x20, "b"),
            record(5, 0x10, "z"),
            record(5, 0x10, "a"),
        ], BASE, IMAGE_SIZE)
        self.assertEqual([(symbol.rva, symbol.name) for symbol in symbols],
                         [(0x10, "a"), (0x10, "z"), (0x20, "b")])


class TestDemangle(unittest.TestCase):
    def test_a_decorated_name_is_replaced_by_its_bare_form(self):
        with mock.patch.object(dbghelp, "_undecorate",
                               return_value="use_arr") as undecorate:
            symbols = build_symbols(
                [record(10, 0x10, "?use_arr@@YAHPEAUArr@@@Z")],
                BASE, IMAGE_SIZE)
        undecorate.assert_called_once_with("?use_arr@@YAHPEAUArr@@@Z")
        self.assertEqual(symbols[0].name, "use_arr")

    def test_a_plain_name_never_reaches_demangling(self):
        with mock.patch.object(dbghelp, "_undecorate") as undecorate:
            symbols = build_symbols([record(5, 0x10, "add_numbers")],
                                    BASE, IMAGE_SIZE)
        undecorate.assert_not_called()
        self.assertEqual(symbols[0].name, "add_numbers")

    def test_a_failed_demangle_keeps_the_original_name(self):
        with mock.patch.object(dbghelp, "_undecorate", return_value=None):
            symbols = build_symbols([record(5, 0x10, "?broken@@")],
                                    BASE, IMAGE_SIZE)
        self.assertEqual(symbols[0].name, "?broken@@")


def make_symbol(tag, address, name, size=0, name_len=None):
    """A SYMBOL_INFOW in a buffer big enough to hold 'name'.

    dbghelp writes the name past the structure's Name[1]; the extra bytes here
    reproduce that, so the callback reads a real zero-terminated buffer.
    """
    buffer = ctypes.create_string_buffer(ctypes.sizeof(SYMBOL_INFOW) + 0x100)
    info = SYMBOL_INFOW.from_buffer(buffer)
    info.Tag = tag
    info.Address = address
    info.Size = size
    info.NameLen = len(name) + 1 if name_len is None else name_len
    encoded = name.encode("utf-16-le") + b"\x00\x00"
    ctypes.memmove(ctypes.addressof(info) + NAME_OFFSET, encoded, len(encoded))
    return buffer, info


class TestRecordCallback(unittest.TestCase):
    """The ctypes callback is the one place a Python exception could reach C."""

    def test_a_well_formed_record_is_copied_out(self):
        _buffer, info = make_symbol(5, BASE + 0x10, "helper", size=21)
        records, failures = [], []
        callback = dbghelp._record_callback(records, failures)
        self.assertTrue(callback(ctypes.pointer(info), 21, None))
        self.assertEqual(records, [(5, BASE + 0x10, 21, "helper", 7)])
        self.assertEqual(failures, [])

    def test_an_exception_is_captured_and_stops_the_enumeration(self):
        # A NULL SYMBOL_INFOW is how an unreadable record would look; the
        # callback must return FALSE instead of letting ctypes swallow it.
        records, failures = [], []
        callback = dbghelp._record_callback(records, failures)
        null = ctypes.cast(0, ctypes.POINTER(SYMBOL_INFOW))
        self.assertFalse(callback(null, 0, None))
        self.assertEqual(records, [])
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], ValueError)


class TestImagePathWiring(unittest.TestCase):
    """`find` has to hand the image it used to the symbol reader."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)

    def test_find_records_the_image_path_and_base_for_symbols(self):
        from pydbg.pe import CodeViewInfo

        pdb_path = os.path.join(self._directory.name, "target.pdb")
        with open(pdb_path, "wb") as handle:
            handle.write(build_msf({1: pdb_info_stream()}))
        image_path = os.path.join(self._directory.name, "target.exe")
        entry = CodeViewInfo(signature="RSDS", pdb_path=pdb_path,
                             age=INFO_STREAM_AGE, guid=SAMPLE_GUID_TEXT)
        image = SimpleNamespace(path=image_path,
                                codeview_entries=[entry],
                                image_base=0x140000000)
        lookup = find(image)
        self.assertIsNone(lookup.reason, lookup.message)
        self.assertEqual(lookup.pdb.image_path, image_path)
        self.assertEqual(lookup.pdb.image_base, 0x140000000)

    def test_a_pdb_without_an_image_path_still_constructs(self):
        # The PDB stays useful for identity checks; only symbols() needs the
        # image, and it says so instead of guessing.
        pdb = Pdb(os.path.join(self._directory.name, "target.pdb"))
        self.assertIsNone(pdb.image_path)


class TestSymbolsWithoutImage(unittest.TestCase):
    def test_symbols_without_an_image_path_says_it_is_required(self):
        with self.assertRaises(PdbError) as caught:
            Pdb("target.pdb").symbols()
        self.assertIn("image path", str(caught.exception))

    def test_a_missing_image_is_a_pdb_error_not_a_crash(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = os.path.join(directory, "absent.exe")
            pdb = Pdb(os.path.join(directory, "target.pdb"),
                      image_path=missing)
            with self.assertRaises(PdbError) as caught:
                pdb.symbols()
        self.assertIn(missing, str(caught.exception))


class TestRealPdbSymbols(unittest.TestCase):
    """The compiler-written PDB and image from the meson build.

    The pure tests prove the translation; only this pair proves that dbghelp
    loads the image, finds the PDB beside it, and names the symbols the source
    put there. Both paths come from the meson build (spec §10.6(8)), and the
    class skips — loudly — when it was never built.
    """

    @classmethod
    def setUpClass(cls):
        from pydbg.pe import PE

        pdb_path = os.environ.get("TEST_PDB_PATH")
        image_path = os.environ.get("TEST_PDB_TARGET_PATH")
        if not pdb_path or not os.path.isfile(pdb_path):
            raise unittest.SkipTest(
                "target not built: pdb_target.pdb (meson); set TEST_PDB_PATH")
        if not image_path or not os.path.isfile(image_path):
            raise unittest.SkipTest(
                "target not built: pdb_target.exe (meson); "
                "set TEST_PDB_TARGET_PATH")
        cls.pdb_path = pdb_path
        cls.image_path = image_path
        cls.pe = PE.from_file(image_path)

        # The acceptance budget covers the whole Phase 5 read path, not just
        # symbol enumeration: find + symbols + structs in one measurement.
        started = time.perf_counter()
        lookup = find(cls.pe)
        if lookup.reason is not None:
            raise AssertionError(
                f"find failed: {lookup.reason}: {lookup.message}")
        cls.lookup = lookup
        cls.symbols = lookup.pdb.symbols()
        cls.structs = lookup.pdb.structs()
        cls.elapsed = time.perf_counter() - started

    def test_the_exported_static_and_data_symbols_are_present(self):
        by_name = {symbol.name: symbol for symbol in self.symbols}
        self.assertIn("add_numbers", by_name, "exported function missing")
        self.assertIn("helper", by_name, "static function missing")
        self.assertIn("g_pt", by_name, "global data missing")
        self.assertEqual(by_name["add_numbers"].kind, "function")
        self.assertEqual(by_name["helper"].kind, "function")
        self.assertEqual(by_name["g_pt"].kind, "data")

    def test_names_are_undecorated(self):
        # Tag 5/7 names are stored undecorated; if a '?' name is demangled it
        # must be NAME_ONLY, never COMPLETE (which appends "__cdecl ...").
        by_name = {symbol.name: symbol for symbol in self.symbols}
        self.assertEqual(by_name["add_numbers"].name, "add_numbers")
        self.assertEqual(by_name["helper"].name, "helper")
        for symbol in self.symbols:
            self.assertNotIn(" __cdecl", symbol.name)
            self.assertFalse(symbol.name.startswith("?add_numbers"),
                             symbol.name)

    def test_every_rva_is_inside_the_image_and_names_are_unique(self):
        image_size = self.pe.optional_header.size_of_image
        for symbol in self.symbols:
            self.assertGreaterEqual(symbol.rva, 0, symbol.name)
            self.assertLess(symbol.rva, image_size, symbol.name)
        keys = [(symbol.rva, symbol.name) for symbol in self.symbols]
        self.assertEqual(len(set(keys)), len(keys))

    def test_two_enumerations_are_equal_and_do_not_reload_the_module(self):
        pdb = self.lookup.pdb
        self.assertEqual(self.symbols, pdb.symbols())

        # A second Pdb for the same image must reuse the loaded module.
        again = Pdb(self.pdb_path, image_path=self.image_path,
                    image_base=pdb.image_base)
        self.assertEqual(self.symbols, again.symbols())

        api = dbghelp._api()
        with mock.patch.object(api, "load_module_ex",
                               wraps=api.load_module_ex) as load:
            self.assertEqual(
                self.symbols,
                dbghelp.symbols(self.pdb_path, self.image_path,
                                pdb.image_base))
        load.assert_not_called()

    def test_find_symbols_and_structs_take_under_two_seconds(self):
        """Spec §10.6(6): the whole read path is what has to stay fast."""
        print(f"\npdb: find + symbols + structs = {self.elapsed * 1000:.1f} ms, "
              f"{len(self.symbols)} symbols, {len(self.structs)} structs")
        self.assertTrue(self.structs, "the type stream enumerated no UDTs")
        self.assertLess(self.elapsed, 2.0)


if __name__ == "__main__":
    unittest.main()
