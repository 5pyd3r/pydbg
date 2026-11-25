"""Tests for the PDB line reader — `Pdb.line_for(rva)` (spec §13.6).

A line is a single point lookup: dbghelp is asked which source line covers one
virtual address, and it answers file, line number and how far into that line the
address is. The pure part is the `LineInfo` answer itself; the real-PDB cases use
the compiler-written `pdb_target` from the meson build and skip with a
"target not built:" reason when it is absent, as the suite requires.

The cache is a requirement, not an optimisation (spec §13.6): a repeated query
for one RVA must not parse the module again, and a new `Pdb` for the same image
must reuse the module the session already loaded.
"""

import dataclasses
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from pydbg.pe import PE
from pydbg.pdb import LineInfo, Pdb, PdbError, dbghelp, find

TARGET_SOURCE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "target", "pdb_target.c")


def source_line(text):
    """The 1-based line in pdb_target.c that contains 'text'.

    The expected line number comes from the source, not from a number copied
    beside it: a test that hard-codes 40 stops noticing when the file moves the
    statement, and then it is either failing for no reason or passing for the
    wrong one.
    """
    with open(TARGET_SOURCE, encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, 1):
            if text in line:
                return number
    raise AssertionError(f"{text!r} is not in {TARGET_SOURCE}")


def verified_pdb():
    """The Pdb named by TEST_PDB_PATH / TEST_PDB_TARGET_PATH, or a skip.

    Located through `find` — GUID and age checked — so the tests exercise the
    same public path a caller uses and not a private constructor.
    """
    pdb_path = os.environ.get("TEST_PDB_PATH")
    image_path = os.environ.get("TEST_PDB_TARGET_PATH")
    if not pdb_path or not os.path.isfile(pdb_path):
        raise unittest.SkipTest(
            "target not built: pdb_target.pdb (meson); set TEST_PDB_PATH")
    if not image_path or not os.path.isfile(image_path):
        raise unittest.SkipTest(
            "target not built: pdb_target.exe (meson); "
            "set TEST_PDB_TARGET_PATH")
    lookup = find(SimpleNamespace(pe=PE.from_file(image_path), path=image_path))
    if lookup.reason is not None:
        raise AssertionError(f"find failed: {lookup.reason}: {lookup.message}")
    return lookup.pdb


class TestLineInfo(unittest.TestCase):
    """The answer object is a value: file, line and displacement, nothing else."""

    def test_it_is_a_frozen_file_line_displacement_value(self):
        info = LineInfo("C:\\build\\pdb_target.c", 40, 3)
        self.assertEqual((info.file, info.line, info.displacement),
                         ("C:\\build\\pdb_target.c", 40, 3))
        self.assertEqual(info, LineInfo("C:\\build\\pdb_target.c", 40, 3))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            info.line = 41

    def test_it_carries_no_other_fields(self):
        names = {field.name for field in dataclasses.fields(LineInfo)}
        self.assertEqual(names, {"file", "line", "displacement"})


class TestLineForWithoutImage(unittest.TestCase):
    """`line_for` needs the image for the same reason `symbols()` does."""

    def test_without_an_image_path_it_says_the_path_is_required(self):
        with self.assertRaises(PdbError) as caught:
            Pdb("target.pdb").line_for(0x10)
        self.assertIn("image path", str(caught.exception))

    def test_a_missing_image_is_a_pdb_error_not_a_crash(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = os.path.join(directory, "absent.exe")
            pdb = Pdb(os.path.join(directory, "target.pdb"),
                      image_path=missing)
            with self.assertRaises(PdbError) as caught:
                pdb.line_for(0x10)
        self.assertIn(missing, str(caught.exception))


class TestLoadLinesEnabled(unittest.TestCase):
    """SymGetLineFromAddrW64 documents SYMOPT_LOAD_LINES as required, so the
    shared session word must keep asking for line tables."""

    def test_line_tables_are_among_the_session_options(self):
        self.assertTrue(dbghelp.SYM_SET_OPTIONS & dbghelp.LOAD_LINES,
                        hex(dbghelp.SYM_SET_OPTIONS))


class TestRealPdbLines(unittest.TestCase):
    """The compiler-written PDB: a function's line, and the absent cases."""

    @classmethod
    def setUpClass(cls):
        cls.pdb = verified_pdb()
        image = PE.from_file(cls.pdb.image_path)
        cls.image_size = image.optional_header.size_of_image
        cls.symbols = {symbol.name: symbol for symbol in cls.pdb.symbols()}
        cls.add_numbers = cls.symbols["add_numbers"]
        cls.add_line = cls.pdb.line_for(cls.add_numbers.rva)
        if cls.add_line is None:
            raise AssertionError("add_numbers has no line in the PDB; "
                                 "every line test below would be vacuous")

    def test_add_numbers_returns_the_recorded_line(self):
        self.assertIsNotNone(self.add_line,
                             "add_numbers has no line in the PDB")
        self.assertIsInstance(self.add_line, LineInfo)
        # The function's opening line is where its entry address maps; a
        # compiler that attributes the prologue to the body instead still
        # answers with a line of add_numbers, which is the fact under test.
        self.assertIn(self.add_line.line,
                      {source_line("int add_numbers(int a, int b) {"),
                       source_line("return a + b + helper(b);")})
        self.assertTrue(os.path.isabs(self.add_line.file),
                        self.add_line.file)
        self.assertEqual(os.path.basename(self.add_line.file),
                         "pdb_target.c")
        self.assertGreaterEqual(self.add_line.displacement, 0)

    def test_displacement_counts_bytes_into_the_same_line(self):
        # Measured: the line's start is the function entry, so one byte in is
        # the same line with displacement 1 — not a different line.
        one_byte_in = self.pdb.line_for(self.add_numbers.rva + 1)
        self.assertIsNotNone(one_byte_in)
        self.assertEqual(one_byte_in.file, self.add_line.file)
        self.assertEqual(one_byte_in.line, self.add_line.line)
        self.assertEqual(one_byte_in.displacement, 1)

    def test_a_repeated_query_returns_the_same_line(self):
        self.assertEqual(self.pdb.line_for(self.add_numbers.rva),
                         self.add_line)

    def test_a_new_pdb_for_the_same_module_does_not_reload_it(self):
        again = Pdb(self.pdb.path, image_path=self.pdb.image_path,
                    image_base=self.pdb.image_base)
        api = dbghelp._api()
        with mock.patch.object(api, "load_module_ex",
                               wraps=api.load_module_ex) as load:
            self.assertEqual(again.line_for(self.add_numbers.rva),
                             self.add_line)
        load.assert_not_called()

    def test_one_rva_is_parsed_once_per_pdb(self):
        # The requirement (spec §13.6): the second query is answered from the
        # module's cached line table rather than parsed again.
        fresh = Pdb(self.pdb.path, image_path=self.pdb.image_path,
                    image_base=self.pdb.image_base)
        api = dbghelp._api()
        with mock.patch.object(api, "line_from_addr",
                               wraps=api.line_from_addr) as query:
            first = fresh.line_for(self.add_numbers.rva)
            second = fresh.line_for(self.add_numbers.rva)
        self.assertEqual(first, second)
        query.assert_called_once()

    def test_a_line_query_can_be_the_first_read_of_a_new_session(self):
        # Measured: after an explicit-base SymLoadModuleExW, the first
        # SymGetLineFromAddrW64 answers FALSE until a symbol enumeration has
        # happened, so line_for primes the module once and retries.
        fresh = Pdb(self.pdb.path, image_path=self.pdb.image_path,
                    image_base=self.pdb.image_base)
        dbghelp._close_session()
        try:
            self.assertEqual(fresh.line_for(self.add_numbers.rva),
                             self.add_line)
        finally:
            # Leave the session loaded for the tests that follow.
            dbghelp.symbols(self.pdb.path, self.pdb.image_path,
                            self.pdb.image_base)

    def test_a_data_symbol_has_no_line_information(self):
        # G_pt is inside the image, so the address is valid; it is simply not
        # code the PDB has a line record for.
        self.assertIsNone(self.pdb.line_for(self.symbols["g_pt"].rva))

    def test_an_address_outside_the_image_is_none(self):
        for rva in (-1, self.image_size, self.image_size + 0x1000):
            with self.subTest(rva=rva):
                self.assertIsNone(self.pdb.line_for(rva))

    def test_an_unmapped_address_inside_the_image_is_none(self):
        # RVA 0 is the DOS/PE headers: inside the image, no executable code.
        self.assertIsNone(self.pdb.line_for(0))

    def test_the_line_reader_does_not_change_the_symbol_or_type_answers(self):
        # LOAD_LINES is process-wide; the rows the other readers return are
        # not allowed to move because of it.
        self.assertIn("add_numbers", self.symbols)
        self.assertEqual(self.symbols["add_numbers"].kind, "function")
        self.assertEqual(self.pdb.layout_of("Point").size, 8)


if __name__ == "__main__":
    unittest.main()
