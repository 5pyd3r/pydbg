"""Tests for the structure-field-table exit.

A field table has two tracks: one read from a PDB's type stream, and one
derived from base-relative memory accesses. This module owns the exit where
both are queryable through the same shape, and where they can be compared
offset by offset — including the offsets only one track knows about, because a
comparison that hides those is not one.

`pdb` stays duck-typed here on purpose: the type exit only calls `structs()`
and `layout_of()`, never `isinstance`, so a fake stands in for the real handle.
The value classes (`Field`, `StructLayout`) are shared with `pydbg.pdb` rather
than copied, and that identity is itself part of the contract.
"""

import os
import unittest
from types import SimpleNamespace

from pydbg.analysis import FieldUse, analyze_bytes, profiles, types
from tests.pe_builder import PEBuilder

TEXT_RVA = 0x1000
IMAGE_BASE = 0x400000
TEXT_SIZE = 0x40
FUNCTION_RVA_OFFSET = 0x20


def build(code):
    text = bytearray(b"\x90" * TEXT_SIZE)
    text[0:len(code)] = code
    text[FUNCTION_RVA_OFFSET] = 0xC3
    builder = PEBuilder(magic=0x10B, image_base=IMAGE_BASE,
                        entry_rva=TEXT_RVA)
    builder.add_section(".text", bytes(text), TEXT_RVA)
    return builder.build()


def analyze(code):
    return analyze_bytes(build(code))


def profile_result():
    """An image whose analysis yields one structure profile.

    `mov eax, [ebx+0x18]`, `mov ecx, [ebx+0x1c]`, `mov edx, [ebx+0x20]` —
    three 4-byte reads through one base, which is the threshold for a profile.
    """
    code = (b"\x8b\x43\x18" + b"\x8b\x4b\x1c" + b"\x8b\x53\x20" + b"\xc3")
    return analyze(code)


def fake_field(offset, name=None, type_name=None, size=0):
    return SimpleNamespace(offset=offset, name=name, type_name=type_name,
                           size=size, bit_position=None, bit_width=None)


def fake_layout(name, size, fields, source="pdb", truncated=False):
    return SimpleNamespace(name=name, size=size, fields=tuple(fields),
                           source=source, truncated=truncated)


class FakePdb:
    """The duck-typed `Pdb` surface the type exit uses."""

    def __init__(self, layouts):
        self._layouts = tuple(layouts)
        self._by_name = {layout.name: layout for layout in self._layouts}

    def symbols(self):
        return ()

    def structs(self):
        return self._layouts

    def layout_of(self, key):
        return self._by_name.get(key)


POINT = fake_layout("Point", 8, [fake_field(0, "x", "int", 4),
                                 fake_field(4, "y", "int", 4)])


class TestStructs(unittest.TestCase):

    def test_without_a_pdb_the_access_profiles_become_layouts(self):
        layout, = types.structs(profile_result())
        self.assertEqual(layout.source, "profile")
        self.assertEqual(layout.name, f"{TEXT_RVA}:ebx")
        self.assertEqual(layout.size, 0x24)
        self.assertEqual([field.offset for field in layout.fields],
                         [0x18, 0x1C, 0x20])
        self.assertEqual([field.size for field in layout.fields], [4, 4, 4])

    def test_a_profile_layout_never_invents_a_field_name_or_type(self):
        """The honest half: offsets and widths, no guessed `this->foo`."""
        layout, = types.structs(profile_result())
        for field in layout.fields:
            self.assertIsNone(field.name)
            self.assertIsNone(field.type_name)

    def test_with_a_pdb_the_handles_layouts_come_through_untouched(self):
        layouts = (POINT, fake_layout("Grid", 24, [fake_field(8, "cells",
                                                              "int[4]", 16)]))
        pdb = FakePdb(layouts)
        found = types.structs(profile_result(), pdb=pdb)
        self.assertEqual(found, layouts)
        for returned, original in zip(found, layouts):
            self.assertIs(returned, original)

    def test_an_empty_pdb_yields_no_layouts_rather_than_inventing_them(self):
        self.assertEqual(types.structs(profile_result(), pdb=FakePdb(())), ())

    def test_a_signed_profile_offset_still_produces_a_layout(self):
        """`[ebx-0x8]` is a field location, not a reason to refuse the table."""
        code = (b"\x8b\x43\xf8" + b"\x8b\x4b\xfc" + b"\x8b\x53\x00" + b"\xc3")
        layout, = types.structs(analyze(code))
        self.assertEqual([field.offset for field in layout.fields],
                         [-8, -4, 0])


class TestSharedValueClasses(unittest.TestCase):
    """One `Field`/`StructLayout`, so the two tracks cannot drift apart.

    They were copied once and had already diverged in defaults and
    validation; a PDB layout and a profile layout are compared field by field,
    which is only trustworthy if both are the same shape.
    """

    def test_the_value_classes_are_the_pdb_ones(self):
        from pydbg.pdb import Field as PdbField
        from pydbg.pdb import StructLayout as PdbStructLayout
        self.assertIs(types.Field, PdbField)
        self.assertIs(types.StructLayout, PdbStructLayout)

    def test_a_profile_field_is_a_pdb_field(self):
        layout, = types.structs(profile_result())
        for field in layout.fields:
            self.assertIsInstance(field, types.Field)

    def test_the_profile_track_still_accepts_an_offset(self):
        layout, = types.structs(profile_result())
        self.assertEqual(layout.fields[0].offset, 0x18)


class TestLayoutOf(unittest.TestCase):

    def test_a_name_finds_a_pdb_layout(self):
        found = types.layout_of(profile_result(), "Point", pdb=FakePdb([POINT]))
        self.assertIs(found, POINT)

    def test_an_unknown_name_is_none(self):
        self.assertIsNone(types.layout_of(profile_result(), "Nope",
                                          pdb=FakePdb([POINT])))

    def test_an_rva_finds_the_profile_layout_for_that_function(self):
        layout = types.layout_of(profile_result(), TEXT_RVA)
        self.assertIsNotNone(layout)
        self.assertEqual(layout.name, f"{TEXT_RVA}:ebx")
        self.assertEqual(layout.source, "profile")

    def test_an_integer_key_never_reaches_the_pdb(self):
        """An RVA and a TypeIndex are both ints; only a name is a PDB key."""
        calls = []

        class RecordingPdb(FakePdb):
            def layout_of(self, key):
                calls.append(key)
                return super().layout_of(key)

        layout = types.layout_of(profile_result(), TEXT_RVA,
                                 pdb=RecordingPdb([POINT]))
        self.assertEqual(calls, [])
        self.assertIsNotNone(layout)
        self.assertEqual(layout.source, "profile")

    def test_an_unknown_rva_or_a_name_without_a_pdb_is_none(self):
        result = profile_result()
        self.assertIsNone(types.layout_of(result, 0xDEADBEEF))
        self.assertIsNone(types.layout_of(result, f"{TEXT_RVA}:ebx"))


class TestFieldReport(unittest.TestCase):

    def report(self, layout, fields):
        profile = SimpleNamespace(function=TEXT_RVA, base_reg="ebx",
                                  fields=dict(fields))
        return types.field_report(layout, profile)

    def test_pdb_only_profile_only_and_both_offsets_are_all_reported(self):
        """Aligned by offset, and nothing is dropped for not matching."""
        profile_fields = {
            0: FieldUse(offset=0, size=4, reads=3, writes=1),
            8: FieldUse(offset=8, size=8, reads=2),
        }
        rows = self.report(POINT, profile_fields)
        self.assertEqual(
            [(row.offset, row.name, row.type_name, row.size, row.reads,
              row.writes, row.called, row.present_in) for row in rows],
            [(0, "x", "int", 4, 3, 1, False, "both"),
             (4, "y", "int", 4, 0, 0, False, "pdb"),
             (8, None, None, 8, 2, 0, False, "profile")])

    def test_a_called_field_is_reported_as_one(self):
        profile_fields = {0: FieldUse(offset=0, size=4, reads=1, called=True)}
        rows = self.report(POINT, profile_fields)
        self.assertTrue(rows[0].called)
        self.assertFalse(rows[1].called)

    def test_a_profile_only_offset_is_listed_in_offset_order(self):
        layout = fake_layout("Sparse", 12, [fake_field(8, "z", "int", 4)])
        profile_fields = {0: FieldUse(offset=0, size=4, reads=1),
                          8: FieldUse(offset=8, size=4, reads=2)}
        rows = self.report(layout, profile_fields)
        self.assertEqual([row.offset for row in rows], [0, 8])
        self.assertEqual([row.present_in for row in rows], ["profile", "both"])

    def test_an_access_less_profile_reports_the_layout_alone(self):
        rows = self.report(POINT, {})
        self.assertEqual([row.present_in for row in rows], ["pdb", "pdb"])
        self.assertEqual([row.reads for row in rows], [0, 0])

    def test_a_profile_layout_is_reported_as_profile_evidence(self):
        """One track present is not "both", and never "pdb".

        A layout derived from accesses put next to those accesses is still
        only profile evidence; labelling its fields "pdb" would claim a type
        stream was read when none was.
        """
        result = profile_result()
        layout, = types.structs(result)
        profile = list(profiles(result).values())[0]
        rows = types.field_report(layout, profile)
        self.assertEqual({row.present_in for row in rows}, {"profile"})
        self.assertEqual([row.offset for row in rows], [0x18, 0x1C, 0x20])


class TestRealImageProfiles(unittest.TestCase):
    """Acceptance: the existing test target yields at least one layout."""

    @classmethod
    def setUpClass(cls):
        path = os.environ.get("TEST_TARGET_PATH")
        if not path or not os.path.exists(path):
            raise unittest.SkipTest(
                f"target not built: no image at {path!r}")
        from pydbg.analysis import analyze_file
        cls.result = analyze_file(path)

    def test_at_least_one_profile_layout_is_produced(self):
        layouts = types.structs(self.result)
        self.assertTrue(layouts)
        self.assertTrue(any(layout.source == "profile" for layout in layouts))
        self.assertTrue(any(field.name is None
                            for layout in layouts for field in layout.fields))


class TestExports(unittest.TestCase):

    def test_the_type_exit_is_reachable_from_the_package(self):
        from pydbg.analysis import FieldReport, field_report, layout_of, structs
        self.assertIs(structs, types.structs)
        self.assertIs(layout_of, types.layout_of)
        self.assertIs(field_report, types.field_report)
        self.assertEqual(
            sorted(FieldReport.__dataclass_fields__),
            ["called", "name", "offset", "present_in", "reads", "size",
             "type_name", "writes"])


if __name__ == "__main__":
    unittest.main()
