"""Tests for the PDB type reader (spec §10.2(4)(5)(6), §10.3, §10.6(4)).

dbghelp turns a PDB's type stream into fields one TI_* call at a time. The parts
that decide what a field *is* — the cvconst base-type table, the shape of a
field, the null shape a failed member degrades to — are pure functions over a
small reader protocol, so they are tested without dbghelp at all. The real-PDB
cases take TEST_PDB_PATH / TEST_PDB_TARGET_PATH (and the C++ pair) from the
meson build and skip with a "target not built:" reason when they are absent, as
the suite requires.
"""

import dataclasses
import os
import tempfile
import time
import unittest
from types import SimpleNamespace

from pydbg.pe import PE
from pydbg.pdb import Field, Pdb, PdbError, StructLayout, find
from pydbg.pdb.types import (
    base_type_name, build_layout, build_structs,
)

# cvconst.h BasicType numbers, measured in research/pdb-format.md §B8: `short`
# is not a BasicType of its own, it is btInt with length 2, which is why the
# mapping has to consider the length.
BT_VOID = 1
BT_CHAR = 2
BT_INT = 6
BT_UINT = 7
BT_FLOAT = 8
BT_BOOL = 10
BT_ULONG = 14
BT_ENUM = 12
SYMTAG_FUNCTION = 5
SYMTAG_DATA = 7
SYMTAG_UDT = 11
SYMTAG_ENUM = 12
SYMTAG_FUNCTION_TYPE = 13
SYMTAG_POINTER = 14
SYMTAG_ARRAY = 15
SYMTAG_BASE_TYPE = 16
SYMTAG_BASE_CLASS = 18
SYMTAG_VTABLE = 25


class TestBaseTypeNames(unittest.TestCase):
    """The cvconst table is the only thing that names an unnamed base type."""

    def test_each_measured_basic_type_maps_to_its_c_spelling(self):
        self.assertEqual(base_type_name(BT_CHAR, 1), "char")
        self.assertEqual(base_type_name(BT_INT, 2), "short")
        self.assertEqual(base_type_name(BT_INT, 4), "int")
        self.assertEqual(base_type_name(BT_INT, 8), "long long")
        self.assertEqual(base_type_name(BT_UINT, 4), "unsigned int")
        self.assertEqual(base_type_name(BT_FLOAT, 4), "float")
        self.assertEqual(base_type_name(BT_FLOAT, 8), "double")
        self.assertEqual(base_type_name(BT_VOID, 0), "void")
        self.assertEqual(base_type_name(BT_BOOL, 1), "bool")
        self.assertEqual(base_type_name(BT_ULONG, 4), "unsigned long")

    def test_an_unknown_basic_type_number_has_no_name(self):
        # Guessing a C type from a number dbghelp was never measured to use
        # would be exactly the invention the spec forbids.
        self.assertIsNone(base_type_name(99, 4))
        self.assertIsNone(base_type_name(None, 4))

    def test_a_known_basic_type_with_an_unmapped_width_has_no_name(self):
        # A width the table does not know is not evidence for another width.
        self.assertIsNone(base_type_name(BT_INT, 3))
        self.assertIsNone(base_type_name(BT_FLOAT, 2))


class TestFieldShape(unittest.TestCase):
    def test_a_plain_field_carries_no_bit_metadata(self):
        field = Field(4, "y", "int", 4)
        self.assertEqual((field.offset, field.name, field.type_name,
                          field.size), (4, "y", "int", 4))
        self.assertIsNone(field.bit_position)
        self.assertIsNone(field.bit_width)

    def test_a_bitfield_carries_its_position_and_width(self):
        field = Field(0, "a", "unsigned int", 4, bit_position=3, bit_width=5)
        self.assertEqual((field.bit_position, field.bit_width), (3, 5))

    def test_negative_offset_or_size_is_rejected(self):
        with self.assertRaises(ValueError):
            Field(-1, "x", "int", 4)
        with self.assertRaises(ValueError):
            Field(0, "x", "int", -4)

    def test_a_half_described_bitfield_is_rejected(self):
        # bit_position without bit_width (and the reverse) describes no field
        # that a caller could lay out.
        with self.assertRaises(ValueError):
            Field(0, "a", "unsigned int", 4, bit_position=3)
        with self.assertRaises(ValueError):
            Field(0, "a", "unsigned int", 4, bit_width=5)

    def test_a_zero_width_bitfield_is_rejected(self):
        with self.assertRaises(ValueError):
            Field(0, "a", "unsigned int", 4, bit_position=0, bit_width=0)

    def test_the_degraded_shape_is_constructible(self):
        # A member whose queries failed is reported, not dropped: no name, no
        # type, no size, so no caller can mistake it for a read field.
        field = Field(0, None, None, 0)
        self.assertIsNone(field.name)
        self.assertIsNone(field.type_name)
        self.assertEqual(field.size, 0)


class TestNoTypeIndexInResults(unittest.TestCase):
    """TypeIndex is a session-scoped id; it must not reach a returned object."""

    def test_struct_layout_has_no_type_index_field(self):
        names = {field.name for field in dataclasses.fields(StructLayout)}
        self.assertEqual(names,
                         {"name", "size", "fields", "source", "truncated"})
        self.assertNotIn("type_index", names)
        self.assertNotIn("TypeIndex", names)

    def test_field_has_no_type_index_field(self):
        names = {field.name for field in dataclasses.fields(Field)}
        self.assertEqual(names, {"offset", "name", "type_name", "size",
                                 "bit_position", "bit_width"})
        self.assertNotIn("type_index", names)


class StubReader:
    """A dict-backed type stream, so traversal is tested without dbghelp.

    Each node lists exactly what the matching TI_* call would answer. A key that
    is absent (or explicitly None) means the query failed and the reader returns
    None, which is how the degradation tests simulate a broken PDB record.
    """

    def __init__(self, nodes, enumeration=()):
        self.nodes = nodes
        self.enumeration = list(enumeration)

    def _node(self, type_id):
        return self.nodes.get(type_id, {})

    def sym_tag(self, type_id):
        return self._node(type_id).get("tag")

    def sym_name(self, type_id):
        return self._node(type_id).get("name")

    def length(self, type_id):
        return self._node(type_id).get("length")

    def base_type(self, type_id):
        return self._node(type_id).get("base")

    def type_of(self, type_id):
        return self._node(type_id).get("type")

    def count(self, type_id):
        return self._node(type_id).get("count")

    def offset(self, member_id):
        return self._node(member_id).get("offset")

    def bit_position(self, member_id):
        return self._node(member_id).get("bitpos")

    def children(self, type_id):
        return self._node(type_id).get("children")

    def types(self):
        return tuple(self.enumeration)


class TypeTable:
    """Builds `StubReader` type streams one node at a time."""

    def __init__(self):
        self.nodes = {}
        self.enumeration = []

    def add(self, type_id, **node):
        self.nodes[type_id] = node
        return type_id

    def base(self, type_id, base=BT_INT, length=4):
        return self.add(type_id, tag=SYMTAG_BASE_TYPE, base=base, length=length)

    def pointer(self, type_id, target, length=8):
        return self.add(type_id, tag=SYMTAG_POINTER, type=target,
                        length=length)

    def array(self, type_id, element, count, length):
        return self.add(type_id, tag=SYMTAG_ARRAY, type=element, count=count,
                        length=length)

    def udt(self, type_id, name, length, children=(), enumerated=True):
        self.add(type_id, tag=SYMTAG_UDT, name=name, length=length,
                 children=tuple(children))
        if enumerated:
            self.enumeration.append((type_id, SYMTAG_UDT))
        return type_id

    def member(self, member_id, name, offset, member_type, bitpos=None,
               length=None):
        """A Tag=7 child; `length` is the member-node length (bit width)."""
        return self.add(member_id, tag=SYMTAG_DATA, name=name, offset=offset,
                        type=member_type, bitpos=bitpos, length=length)

    def reader(self):
        return StubReader(self.nodes, self.enumeration)


class TestBuildLayout(unittest.TestCase):
    """Traversal as a pure function of the reader protocol."""

    def test_a_struct_becomes_offsets_names_types_and_sizes(self):
        table = TypeTable()
        int_type = table.base(10)
        table.member(100, "x", 0, int_type)
        table.member(101, "y", 4, int_type)
        point = table.udt(1, "Point", 8, [100, 101])

        layout = build_layout(table.reader(), point)

        self.assertEqual(layout, StructLayout("Point", 8, (
            Field(0, "x", "int", 4), Field(4, "y", "int", 4))))
        self.assertFalse(layout.truncated)
        self.assertEqual(layout.source, "pdb")

    def test_a_bitfield_reports_the_storage_offset_and_bit_span(self):
        # Measured: offset is the storage unit, the member node's length is the
        # bit width, and the type's length is the storage size.
        table = TypeTable()
        uint = table.base(10, base=BT_UINT, length=4)
        table.member(100, "a", 0, uint, bitpos=0, length=3)
        table.member(101, "b", 0, uint, bitpos=3, length=5)
        bits = table.udt(1, "Bits", 4, [100, 101])

        layout = build_layout(table.reader(), bits)

        self.assertEqual(layout.fields, (
            Field(0, "a", "unsigned int", 4, bit_position=0, bit_width=3),
            Field(0, "b", "unsigned int", 4, bit_position=3, bit_width=5),
        ))
        self.assertFalse(layout.truncated)

    def test_an_array_field_is_named_by_element_and_count(self):
        table = TypeTable()
        int_type = table.base(10)
        array = table.array(11, element=int_type, count=4, length=16)
        table.member(100, "cells", 8, array)
        grid = table.udt(1, "Grid", 24, [100])

        layout = build_layout(table.reader(), grid)

        self.assertEqual(layout.fields,
                         (Field(8, "cells", "int[4]", 16),))
        self.assertFalse(layout.truncated)

    def test_a_pointer_to_a_named_udt_keeps_the_target_name(self):
        table = TypeTable()
        point = table.udt(2, "Point", 8)
        pointer = table.pointer(12, target=point)
        table.member(100, "next", 0, pointer)
        link = table.udt(1, "Link", 8, [100])

        layout = build_layout(table.reader(), link)

        self.assertEqual(layout.fields, (Field(0, "next", "Point*", 8),))

    def test_a_pointer_whose_target_cannot_be_named_is_a_void_pointer(self):
        table = TypeTable()
        function = table.add(13, tag=SYMTAG_FUNCTION_TYPE)
        pointer = table.pointer(12, target=function)
        table.member(100, "fp", 0, pointer)
        holder = table.udt(1, "Holder", 8, [100])

        layout = build_layout(table.reader(), holder)

        self.assertEqual(layout.fields, (Field(0, "fp", "void*", 8),))

    def test_a_nested_udt_member_keeps_the_name_dbghelp_gives_it(self):
        # dbghelp qualifies a type declared inside another: "Outer::Inner".
        table = TypeTable()
        inner = table.udt(2, "Outer::Inner", 8)
        table.member(100, "inner", 0, inner)
        outer = table.udt(1, "Outer", 8, [100])

        layout = build_layout(table.reader(), outer)

        self.assertEqual(layout.fields,
                         (Field(0, "inner", "Outer::Inner", 8),))

    def test_a_member_whose_name_query_failed_keeps_its_offset(self):
        table = TypeTable()
        int_type = table.base(10)
        table.member(100, None, 4, int_type)
        holder = table.udt(1, "Holder", 8, [100])

        layout = build_layout(table.reader(), holder)

        # The offset was read, so it survives; nothing else may be invented.
        self.assertEqual(layout.fields, (Field(4, None, None, 0),))
        self.assertTrue(layout.truncated)

    def test_a_member_whose_width_query_failed_degrades_too(self):
        table = TypeTable()
        unmeasured = table.add(11, tag=SYMTAG_BASE_TYPE, base=BT_INT)
        table.member(100, "x", 0, unmeasured)
        holder = table.udt(1, "Holder", 4, [100])

        layout = build_layout(table.reader(), holder)

        self.assertEqual(layout.fields, (Field(0, None, None, 0),))
        self.assertTrue(layout.truncated)

    def test_a_bitfield_whose_width_query_failed_degrades(self):
        table = TypeTable()
        uint = table.base(10, base=BT_UINT, length=4)
        table.member(100, "a", 0, uint, bitpos=3)
        holder = table.udt(1, "Holder", 4, [100])

        layout = build_layout(table.reader(), holder)

        self.assertEqual(layout.fields, (Field(0, None, None, 0),))
        self.assertTrue(layout.truncated)

    def test_a_member_whose_type_cannot_be_classified_degrades(self):
        table = TypeTable()
        table.member(100, "x", 0, 0xDEAD)
        holder = table.udt(1, "Holder", 4, [100])

        layout = build_layout(table.reader(), holder)

        self.assertEqual(layout.fields, (Field(0, None, None, 0),))
        self.assertTrue(layout.truncated)

    def test_methods_and_nested_type_declarations_are_not_fields(self):
        # dbghelp mixes Tag 5 methods and Tag 11 nested type declarations into
        # a UDT's children; they are not members and do not make it truncated.
        table = TypeTable()
        int_type = table.base(10)
        method = table.add(200, tag=SYMTAG_FUNCTION, name="Shape::area")
        nested = table.add(201, tag=SYMTAG_UDT, name="Inner")
        table.member(100, "sides", 8, int_type)
        shape = table.udt(1, "Shape", 16, [method, 100, nested])

        layout = build_layout(table.reader(), shape)

        self.assertEqual(layout.fields, (Field(8, "sides", "int", 4),))
        self.assertFalse(layout.truncated)

    def test_a_base_class_or_vtable_truncates_without_becoming_a_field(self):
        table = TypeTable()
        int_type = table.base(10)
        base_class = table.add(200, tag=SYMTAG_BASE_CLASS, name="Shape")
        table.member(100, "side_len", 16, int_type)
        square = table.udt(1, "Square", 24, [base_class, 100])

        layout = build_layout(table.reader(), square)

        # Base fields are deliberately not expanded, so the layout says it does
        # not describe every byte of the struct.
        self.assertEqual(layout.fields, (Field(16, "side_len", "int", 4),))
        self.assertTrue(layout.truncated)

        vtable = table.add(201, tag=SYMTAG_VTABLE)
        table.udt(2, "Shaped", 16, [vtable], enumerated=False)
        self.assertTrue(build_layout(table.reader(), 2).truncated)

    def test_a_child_whose_tag_cannot_be_read_is_reported_not_dropped(self):
        table = TypeTable()
        int_type = table.base(10)
        table.member(100, "x", 0, int_type)
        table.member(101, None, 4, int_type)
        table.nodes[102] = {}                     # every query fails
        holder = table.udt(1, "Holder", 8, [100, 102])

        layout = build_layout(table.reader(), holder)

        self.assertEqual(layout.fields,
                         (Field(0, "x", "int", 4), Field(0, None, None, 0)))
        self.assertTrue(layout.truncated)

    def test_a_udt_whose_size_query_failed_is_size_zero_and_truncated(self):
        table = TypeTable()
        table.udt(1, "Opaque", None, [])
        layout = build_layout(table.reader(), 1)
        self.assertEqual(layout.size, 0)
        self.assertTrue(layout.truncated)

    def test_a_non_udt_type_has_no_layout(self):
        table = TypeTable()
        table.add(1, tag=SYMTAG_ENUM, name="Color", length=4)
        self.assertIsNone(build_layout(table.reader(), 1))
        self.assertIsNone(build_layout(table.reader(), 0xDEAD))


class TestBuildStructs(unittest.TestCase):
    def test_only_udts_are_returned_deduplicated_and_sorted(self):
        table = TypeTable()
        int_type = table.base(10)
        member = table.member(100, "v", 0, int_type)
        table.udt(1, "Zeta", 4, [member])
        table.udt(2, "Alpha", 4, [member])
        table.udt(3, "Zeta", 4, [member])         # same layout as 1
        table.add(4, tag=SYMTAG_ENUM, name="Color", length=4)
        table.enumeration.append((4, SYMTAG_ENUM))

        layouts = build_structs(table.reader())

        self.assertEqual([layout.name for layout in layouts],
                         ["Alpha", "Zeta"])
        self.assertEqual(len(layouts), 2)

    def test_an_empty_type_stream_yields_an_empty_tuple(self):
        self.assertEqual(build_structs(StubReader({})), ())


def verified_pdb(pdb_variable, image_variable):
    """The Pdb the environment pair names, or a "target not built:" skip.

    The PDB is located through the image the same way a caller would (find()
    checks the GUID/age), so these tests exercise the public path and not a
    private constructor.
    """
    pdb_path = os.environ.get(pdb_variable)
    image_path = os.environ.get(image_variable)
    if not pdb_path or not os.path.isfile(pdb_path):
        raise unittest.SkipTest(
            f"target not built: the PDB named by {pdb_variable} (meson); "
            f"set {pdb_variable}")
    if not image_path or not os.path.isfile(image_path):
        raise unittest.SkipTest(
            f"target not built: the image named by {image_variable} (meson); "
            f"set {image_variable}")
    image = SimpleNamespace(pe=PE.from_file(image_path), path=image_path)
    lookup = find(image)
    if lookup.reason is not None:
        raise AssertionError(f"find failed: {lookup.reason}: {lookup.message}")
    return lookup.pdb


class TestTypesWithoutImage(unittest.TestCase):
    def test_structs_without_an_image_path_says_it_is_required(self):
        with self.assertRaises(PdbError) as caught:
            Pdb("target.pdb").structs()
        self.assertIn("image path", str(caught.exception))

    def test_layout_of_without_an_image_path_says_it_is_required(self):
        with self.assertRaises(PdbError) as caught:
            Pdb("target.pdb").layout_of("Point")
        self.assertIn("image path", str(caught.exception))

    def test_a_missing_image_is_a_pdb_error_not_a_crash(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = os.path.join(directory, "absent.exe")
            pdb = Pdb(os.path.join(directory, "target.pdb"),
                      image_path=missing)
            with self.assertRaises(PdbError) as caught:
                pdb.structs()
        self.assertIn(missing, str(caught.exception))


class TestRealCStructs(unittest.TestCase):
    """The C target's layouts: a plain struct, bitfields and an array field."""

    @classmethod
    def setUpClass(cls):
        cls.pdb = verified_pdb("TEST_PDB_PATH", "TEST_PDB_TARGET_PATH")
        started = time.perf_counter()
        cls.structs = cls.pdb.structs()
        cls.elapsed = time.perf_counter() - started

    def layout(self, name):
        layout = self.pdb.layout_of(name)
        self.assertIsNotNone(layout, name)
        return layout

    def test_point_is_the_source_layout(self):
        point = self.layout("Point")
        self.assertEqual((point.name, point.size, point.source),
                         ("Point", 8, "pdb"))
        self.assertFalse(point.truncated)
        self.assertEqual([(field.offset, field.name, field.type_name,
                           field.size) for field in point.fields],
                         [(0, "x", "int", 4), (4, "y", "int", 4)])
        for field in point.fields:
            self.assertIsNone(field.bit_position)
            self.assertIsNone(field.bit_width)

    def test_bits_keeps_each_bitfields_position_and_width(self):
        bits = self.layout("Bits")
        self.assertEqual(bits.size, 4)
        self.assertEqual([(field.bit_position, field.bit_width)
                          for field in bits.fields],
                         [(0, 3), (3, 5), (8, 1)])
        # `offset` is the storage unit, so all three live at byte 0.
        self.assertEqual([field.offset for field in bits.fields], [0, 0, 0])
        self.assertEqual([field.size for field in bits.fields], [4, 4, 4])
        self.assertEqual([field.type_name for field in bits.fields],
                         ["unsigned int"] * 3)
        self.assertFalse(bits.truncated)

    def test_grid_has_a_udt_field_and_an_array_field(self):
        grid = self.layout("Grid")
        self.assertEqual((grid.size, grid.truncated), (24, False))
        origin, cells = grid.fields
        self.assertEqual((origin.offset, origin.name, origin.type_name,
                          origin.size), (0, "origin", "Point", 8))
        self.assertEqual((cells.offset, cells.name, cells.type_name,
                          cells.size), (8, "cells", "int[4]", 16))

    def test_structs_cover_the_target_and_are_sorted(self):
        by_name = {layout.name: layout for layout in self.structs}
        for name in ("Point", "Bits", "Grid"):
            self.assertIn(name, by_name)
            self.assertIsInstance(by_name[name], StructLayout)
        names = [layout.name or "" for layout in self.structs]
        self.assertEqual(names, sorted(names))
        self.assertEqual(self.structs, self.pdb.structs())

    def test_an_unknown_name_or_type_index_is_none(self):
        self.assertIsNone(self.pdb.layout_of("NoSuchType"))
        # A type id the PDB never assigned; dbghelp answers FALSE, not AV.
        self.assertIsNone(self.pdb.layout_of(0xFFFFFF))

    def test_no_layout_or_field_carries_a_type_index(self):
        for layout in self.structs:
            self.assertFalse(hasattr(layout, "type_index"))
            for field in layout.fields:
                self.assertFalse(hasattr(field, "type_index"))

    def test_structs_take_under_two_seconds(self):
        print(f"\npdb types: structs = {self.elapsed * 1000:.1f} ms, "
              f"{len(self.structs)} layouts")
        self.assertLess(self.elapsed, 2.0)


class TestRealCppStructs(unittest.TestCase):
    """The C++ target: a vftable and a base class are edges, not crashes."""

    @classmethod
    def setUpClass(cls):
        cls.pdb = verified_pdb("TEST_PDB_CPP_PDB_PATH",
                               "TEST_PDB_CPP_TARGET_PATH")

    def test_a_class_layout_is_readable(self):
        square = self.pdb.layout_of("Square")
        self.assertIsNotNone(square)
        self.assertEqual((square.name, square.size), ("Square", 24))
        fields = {field.name: field for field in square.fields}
        self.assertIn("side_len", fields)
        field = fields["side_len"]
        self.assertEqual((field.offset, field.type_name, field.size),
                         (16, "int", 4))

    def test_the_vtable_and_base_class_make_the_layout_truncated(self):
        # Both are data the field table deliberately does not describe; saying
        # so is the difference between "no fields" and "unknown bytes".
        square = self.pdb.layout_of("Square")
        self.assertTrue(square.truncated)
        shape = self.pdb.layout_of("Shape")
        self.assertIsNotNone(shape)
        self.assertTrue(shape.truncated)

    def test_the_base_class_is_not_expanded_into_the_derived_layout(self):
        square = self.pdb.layout_of("Square")
        self.assertNotIn("sides", [field.name for field in square.fields])
        shape = self.pdb.layout_of("Shape")
        self.assertIn("sides", [field.name for field in shape.fields])

    def test_structs_include_the_class_records(self):
        names = {layout.name for layout in self.pdb.structs()}
        self.assertIn("Shape", names)
        self.assertIn("Square", names)


class TestTwoImagesInOneProcess(unittest.TestCase):
    """The C and C++ targets share a preferred base, and dbghelp keeps one
    module per address. Reading the two PDBs in turn is exactly the case that
    must not silently answer with the other module's types."""

    @classmethod
    def setUpClass(cls):
        cls.c_pdb = verified_pdb("TEST_PDB_PATH", "TEST_PDB_TARGET_PATH")
        cls.cpp_pdb = verified_pdb("TEST_PDB_CPP_PDB_PATH",
                                   "TEST_PDB_CPP_TARGET_PATH")

    def test_reading_them_in_turn_keeps_each_layout_correct(self):
        self.assertEqual(self.c_pdb.layout_of("Point").size, 8)
        self.assertEqual(self.cpp_pdb.layout_of("Square").size, 24)
        self.assertEqual(self.c_pdb.layout_of("Point").size, 8)
        self.assertEqual(self.cpp_pdb.layout_of("Square").size, 24)


class TestFreshSessionTypeIndex(unittest.TestCase):
    """A raw TypeIndex must work even as the first type question of a session.

    dbghelp answers E_INVALIDARG for ids that are valid once the type stream has
    been opened, and it returns a bogus index from SymGetTypeFromNameW before
    that. So an id carried over from another call is only usable if the reader
    opens the new session's stream before asking about it.
    """

    @classmethod
    def setUpClass(cls):
        cls.pdb = verified_pdb("TEST_PDB_PATH", "TEST_PDB_TARGET_PATH")

    def test_a_raw_type_index_is_readable_in_a_fresh_session(self):
        from pydbg.pdb import dbghelp

        index = dbghelp.read_types(
            self.pdb.path, self.pdb.image_path, self.pdb.image_base,
            lambda reader: reader.find_type("Point"))
        self.assertIsNotNone(index)

        dbghelp._close_session()                  # next read starts a new one
        layout = self.pdb.layout_of(index)

        self.assertIsNotNone(layout)
        self.assertEqual((layout.name, layout.size), ("Point", 8))


if __name__ == "__main__":
    unittest.main()
