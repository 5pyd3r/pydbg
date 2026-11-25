"""32-bit PDB acceptance (spec §13.6, ticket P41).

The MSF/PDB readers are machine-agnostic: `src/pydbg/pdb/*` has no machine
branch, and the x64 acceptance already proved `find` + `symbols` + `structs`.
What was missing is a *32-bit PDB* sample — a `PE32` image built with `/Zi` and
linked `/DEBUG` — so this module runs the same read path against one.

The sample comes from `scripts/build-target32.ps1` (the x86 toolchain is not
part of the meson build, the same split as `simple_target32.exe`), which leaves
`tests/target/pdb_target32.exe` and `.pdb` beside it. Both paths are exposed by
`tests/meson.build` as TEST_PDB_TARGET32_PATH / TEST_PDB32_PATH; without them
the tests skip with a `target not built:` reason, as the suite requires.

The pointer-width check is the one piece of the read path that is not already
covered by the x64 acceptance: a `void *` member must be four bytes in a PE32
image. `Point` itself has no pointer member (it is two ints in both builds), so
the sample adds `PointerHolder` for exactly that assertion.
"""

import os
import time
import unittest

from pydbg.pdb import find

MACHINE_I386 = 0x14C
PE32_MAGIC = 0x10B


def _require_target(env_var, name):
    """The path from 'env_var', or a `target not built:` skip.

    The 32-bit targets are produced out of band by
    scripts/build-target32.ps1, so a checkout that never ran it has no file
    here. Skipping is the documented outcome; a test that silently passed
    without the sample would prove nothing.
    """
    path = os.environ.get(env_var)
    if not path or not os.path.isfile(path):
        raise unittest.SkipTest(
            f"target not built: {name} (scripts/build-target32.ps1); "
            f"set {env_var}")
    return path


class TestRealPdb32(unittest.TestCase):
    """The PE32 image and PDB written by scripts/build-target32.ps1."""

    @classmethod
    def setUpClass(cls):
        from pydbg.pe import PE

        image_path = _require_target("TEST_PDB_TARGET32_PATH",
                                     "pdb_target32.exe")
        pdb_path = _require_target("TEST_PDB32_PATH", "pdb_target32.pdb")
        cls.image_path = image_path
        cls.pdb_path = pdb_path
        cls.pe = PE.from_file(image_path)

        started = time.perf_counter()
        cls.lookup = find(cls.pe)
        if cls.lookup.reason is not None:
            raise AssertionError(
                f"find failed: {cls.lookup.reason}: {cls.lookup.message}")
        cls.symbols = cls.lookup.pdb.symbols()
        cls.structs = cls.lookup.pdb.structs()
        cls.elapsed = time.perf_counter() - started

    def test_the_image_is_a_32_bit_pe(self):
        # The whole point is a PE32 sample: if the script ever emits x64 here,
        # these assertions are what stop the module from "passing" against the
        # wrong architecture.
        self.assertEqual(self.pe.file_header.machine, MACHINE_I386)
        self.assertEqual(self.pe.optional_header.magic, PE32_MAGIC)

    def test_find_verifies_the_32_bit_pdb(self):
        # find() compares the PDB GUID/age against the image's CodeView record;
        # a reason-free lookup is that verification having passed for PE32.
        self.assertIsNone(self.lookup.reason, self.lookup.message)
        self.assertIsNotNone(self.lookup.pdb)
        # The lookup may select the CodeView record's recorded path (written
        # with backslashes) or the meson env path (written with forward
        # slashes), so compare the files, not the strings.
        self.assertTrue(os.path.samefile(self.lookup.path, self.pdb_path))
        self.assertTrue(self.lookup.pdb.matches(self.pe))

    def test_symbols_include_the_stdcall_export(self):
        # `add_numbers` is __stdcall. The ticket allows asserting either the
        # decorated `_add_numbers@8` or the demangled `add_numbers`; measured
        # here, dbghelp enumerates one Tag 5 record under the *undecorated*
        # spelling the compiler recorded, so `add_numbers` is the assertion.
        by_name = {symbol.name: symbol for symbol in self.symbols}
        self.assertIn("add_numbers", by_name, "exported function missing")
        self.assertEqual(by_name["add_numbers"].kind, "function")
        self.assertIn("helper", by_name, "static function missing")
        self.assertEqual(by_name["helper"].kind, "function")

    def test_the_image_really_exports_the_decorated_stdcall_name(self):
        # The decoration still exists in the image: x86 __stdcall exports keep
        # it in the export table (`_name@N`, N = argument bytes). This is what
        # makes the sample a genuine decorated-name case even though the PDB
        # reader's function records are undecorated.
        names = [entry.name for entry in self.pe.exports]
        self.assertIn("_add_numbers@8", names)

    def test_point_is_the_source_layout(self):
        point = self.lookup.pdb.layout_of("Point")
        self.assertIsNotNone(point)
        self.assertEqual((point.name, point.size, point.source),
                         ("Point", 8, "pdb"))
        self.assertFalse(point.truncated)
        self.assertEqual([(field.offset, field.name, field.type_name,
                           field.size) for field in point.fields],
                         [(0, "x", "int", 4), (4, "y", "int", 4)])

    def test_a_pointer_member_is_four_bytes_wide(self):
        # The machine-agnostic reader gets the width from the PDB's type
        # stream, so this is the actual proof that a PE32 PDB describes 32-bit
        # pointers: `void *` is 4 bytes, not the host's 8.
        holder = self.lookup.pdb.layout_of("PointerHolder")
        self.assertIsNotNone(holder)
        self.assertEqual((holder.name, holder.size), ("PointerHolder", 4))
        pointer, = holder.fields
        self.assertEqual((pointer.offset, pointer.name, pointer.type_name,
                          pointer.size), (0, "owner", "void*", 4))

    def test_structs_include_point_and_are_sorted(self):
        by_name = {layout.name: layout for layout in self.structs}
        self.assertIn("Point", by_name)
        for name in ("Bits", "Grid", "PointerHolder"):
            self.assertIn(name, by_name)
        names = [layout.name or "" for layout in self.structs]
        self.assertEqual(names, sorted(names))

    def test_find_symbols_and_structs_take_under_two_seconds(self):
        # Same deliberately loose ceiling as the x64 acceptance: it catches an
        # order-of-magnitude regression, not timer jitter.
        print(f"\npdb32: find + symbols + structs = {self.elapsed * 1000:.1f} "
              f"ms, {len(self.symbols)} symbols, {len(self.structs)} structs")
        self.assertLess(self.elapsed, 2.0)


if __name__ == "__main__":
    unittest.main()
