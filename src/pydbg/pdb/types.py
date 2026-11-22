"""Struct layouts read from a PDB's type stream (spec §10.3, §10.5).

A layout is a field table: the struct's name and size, and for every data member
its byte offset, name, C type spelling and width, plus the bit position and bit
width when it is a bitfield. Everything here comes from dbghelp's TI_* queries
through `pydbg.pdb.dbghelp` (one session, one lock — this module never loads the
library itself).

Three rules decide the output:

- **A UDT's fields are its `Tag == 7` children only.** dbghelp lists methods,
  vftables, base-class nodes and nested type declarations among the same
  children. A base class is *not* expanded into the derived layout (its fields
  would then be indistinguishable from the derived ones); a vtable pointer is
  not a field either. Both make the layout `truncated`, because bytes of the
  struct exist that the field table does not describe.
- **Width comes from the type, not the member.** `TI_GET_LENGTH` on a plain
  member fails; only the member's type carries a byte length. The one exception
  is a bitfield, where the member node's length is the bit width and the type's
  length is the storage unit.
- **A failed member is reported, never guessed.** If any query about a member
  fails it stays in `fields` as `Field(offset, None, None, 0)` and the layout is
  `truncated`; a width is never inferred from a neighbouring field.

`TypeIndex` is deliberately absent from the returned objects: it is opaque and
valid only inside one dbghelp session (spec §10.2(4)), so nothing that escapes a
session may carry one.
"""

from dataclasses import dataclass

from .dbghelp import read_types

SOURCE_PDB = "pdb"

# dbghelp.h `SymTagEnum`, values measured in research/pdb-format.md §B8.
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

# cvconst.h `BasicType` numbers, measured in research/pdb-format.md §B8. `short`
# and `long long` are btInt with another length, so these two tables are keyed
# by the number the PDB records and the length dbghelp reports.
BASETYPE_NAMES = {
    1: "void",              # btVoid
    2: "char",              # btChar
    3: "wchar_t",           # btWChar
    10: "bool",             # btBool
    13: "long",             # btLong
    14: "unsigned long",    # btULong
    32: "char16_t",         # btChar16
    33: "char32_t",         # btChar32
    34: "char8_t",          # btChar8
}
BASETYPE_BY_LENGTH = {
    6: {1: "char", 2: "short", 4: "int", 8: "long long"},          # btInt
    7: {1: "unsigned char", 2: "unsigned short", 4: "unsigned int",
        8: "unsigned long long"},                                  # btUInt
    8: {4: "float", 8: "double"},                                  # btFloat
}


def base_type_name(base_type, length):
    """The C spelling of a BaseType node from its cvconst number and length.

    A `(number, length)` pair the table does not know returns None rather than a
    neighbouring spelling: btInt with length 3 is not evidence for "int", and an
    unmeasured number is not evidence for anything.
    """
    if base_type in BASETYPE_NAMES:
        return BASETYPE_NAMES[base_type]
    lengths = BASETYPE_BY_LENGTH.get(base_type)
    if lengths is None:
        return None
    return lengths.get(length)


@dataclass(frozen=True)
class Field:
    """One data member of a `StructLayout`.

    `offset` is the member's byte offset inside the struct — for a bitfield the
    offset of its storage unit, with `bit_position`/`bit_width` locating the
    bits within it. `size` is the type's byte length (the storage unit for a
    bitfield). `name` or `type_name` is None when dbghelp could not read it; a
    member that failed a query is reported as `Field(offset, None, None, 0)`,
    which is why the enclosing layout's `truncated` flag matters.
    """

    offset: int
    name: str | None
    type_name: str | None
    size: int
    bit_position: int | None = None
    bit_width: int | None = None

    def __post_init__(self):
        if self.offset < 0:
            raise ValueError(f"field offset cannot be negative: {self.offset}")
        if self.size < 0:
            raise ValueError(f"field size cannot be negative: {self.size}")
        if (self.bit_position is None) != (self.bit_width is None):
            raise ValueError(
                "a bitfield needs both bit_position and bit_width; "
                f"got {self.bit_position!r} and {self.bit_width!r}")
        if self.bit_position is not None and self.bit_position < 0:
            raise ValueError(
                f"bit position cannot be negative: {self.bit_position}")
        if self.bit_width is not None and self.bit_width < 1:
            raise ValueError(f"bit width must be at least 1: {self.bit_width}")


@dataclass(frozen=True)
class StructLayout:
    """A UDT's field table, in declaration order.

    `source` is "pdb" for a layout read from a type stream and "profile" for one
    derived by `analysis.types` from memory accesses. `truncated` is true when a
    member could not be read (it then appears as `Field(offset, None, None, 0)`)
    or when the UDT has bytes the field table does not describe — a base class
    that was not expanded, or a vtable pointer. `fields` is always a tuple, so
    two layouts compare equal by value and neither can be mutated after the
    fact.
    """

    name: str | None
    size: int
    fields: tuple[Field, ...]
    source: str = SOURCE_PDB
    truncated: bool = False

    def __post_init__(self):
        if not isinstance(self.fields, tuple):
            object.__setattr__(self, "fields", tuple(self.fields))


def type_name(reader, type_id):
    """The C spelling of 'type_id', or None when dbghelp cannot name it.

    Base types come from the cvconst table; a pointer is its target's spelling
    plus "*", an array is its element's spelling plus "[N]", and a UDT or enum
    keeps the name dbghelp recorded (qualified when it was declared inside
    another type). A function type has no spelling in this grammar, so a pointer
    to one becomes "void*" — the one loss the ticket allows rather than an
    invented signature.
    """
    tag = reader.sym_tag(type_id)
    if tag is None:
        return None
    if tag == SYMTAG_BASE_TYPE:
        return base_type_name(reader.base_type(type_id), reader.length(type_id))
    if tag == SYMTAG_POINTER:
        target = reader.type_of(type_id)
        pointed = None if target is None else type_name(reader, target)
        return "void*" if pointed is None else pointed + "*"
    if tag == SYMTAG_ARRAY:
        element = reader.type_of(type_id)
        count = reader.count(type_id)
        if element is None or count is None:
            return None
        spelled = type_name(reader, element)
        return None if spelled is None else f"{spelled}[{count}]"
    if tag in (SYMTAG_UDT, SYMTAG_ENUM):
        return reader.sym_name(type_id)
    return None


def _null_field(offset=0):
    """The shape a member has after any query about it failed."""
    return Field(offset, None, None, 0)


def _member_field(reader, member_id):
    """(Field, truncated) for one Tag==7 child.

    The offset is read first so a member that fails later still reports where it
    lives; everything else is nulled rather than guessed. Width comes from the
    member's type, except for a bitfield, where the member node's own length is
    the bit width and the type's length is the storage unit.
    """
    offset = reader.offset(member_id)
    if offset is None:
        return _null_field(), True
    name = reader.sym_name(member_id)
    type_id = reader.type_of(member_id)
    tag = None if type_id is None else reader.sym_tag(type_id)
    if name is None or tag is None:
        return _null_field(offset), True
    bit_position = reader.bit_position(member_id)
    if bit_position is not None:
        bit_width = reader.length(member_id)
        unit_size = reader.length(type_id)
        if bit_width is None or unit_size is None:
            return _null_field(offset), True
        spelled = type_name(reader, type_id)
        return (Field(offset, name, spelled, unit_size,
                      bit_position=bit_position, bit_width=bit_width),
                spelled is None)
    size = reader.length(type_id)
    if size is None:
        return _null_field(offset), True
    spelled = type_name(reader, type_id)
    return Field(offset, name, spelled, size), spelled is None


def build_layout(reader, type_id):
    """The `StructLayout` for one UDT type id, or None if it is not a UDT.

    Only `Tag == 7` children become fields. Methods (`Tag 5`) and nested type
    declarations (`Tag 11`) are dropped without marking the layout incomplete;
    a base class (`Tag 18`) or a vtable (`Tag 25`) is dropped *and* marks it
    truncated, because those bytes exist in the struct but no field describes
    them. Base classes are deliberately not expanded: their fields would then
    be reported at the derived type's offsets as if they were declared there.

    An unreadable child tag is kept as a null field instead of being dropped:
    a child that might be a member must not vanish.
    """
    if reader.sym_tag(type_id) != SYMTAG_UDT:
        return None
    size = reader.length(type_id)
    truncated = size is None
    children = reader.children(type_id)
    if children is None:
        truncated = True
        children = ()
    fields = []
    for child in children:
        child_tag = reader.sym_tag(child)
        if child_tag == SYMTAG_DATA:
            field, failed = _member_field(reader, child)
            fields.append(field)
            truncated = truncated or failed
        elif child_tag in (SYMTAG_BASE_CLASS, SYMTAG_VTABLE):
            truncated = True
        elif child_tag is None:
            fields.append(_null_field())
            truncated = True
    return StructLayout(reader.sym_name(type_id), size or 0, tuple(fields),
                        truncated=truncated)


def build_structs(reader):
    """Every UDT in the type stream, sorted by name and size.

    Two type indices that describe the same layout collapse to one — dbghelp
    reports duplicate records for some classes — while layouts that merely share
    a name (anonymous types do) are both kept, because a name is not an
    identity.
    """
    layouts = []
    seen = set()
    for type_id, tag in reader.types():
        if tag != SYMTAG_UDT:
            continue
        layout = build_layout(reader, type_id)
        if layout is None or layout in seen:
            continue
        seen.add(layout)
        layouts.append(layout)
    layouts.sort(key=lambda layout: (layout.name or "", layout.size))
    return tuple(layouts)


def _layout_for(reader, name_or_type_index):
    """The layout of one UDT keyed by name or TypeIndex, or None.

    Only a UDT has a field table; an enum or a base type found by name returns
    None instead of pretending to have no fields.
    """
    if isinstance(name_or_type_index, int):
        return build_layout(reader, name_or_type_index)
    type_id = reader.find_type(name_or_type_index)
    if type_id is None:
        return None
    return build_layout(reader, type_id)


def structs(pdb_path, image_path, image_base=None):
    """Every UDT the PDB for 'image_path' describes, sorted by name and size.

    The PDB is read through the same offline dbghelp session `symbols()` uses;
    an image path is required for the same reason. A PDB whose types cannot be
    enumerated raises rather than returning an empty tuple, but an empty tuple
    is still no proof the PDB was read: dbghelp also returns TRUE for a PDB it
    silently ignored (spec §10.2(6)).

    Raises:
        PdbError: no image path was supplied, the image cannot be read, or
            dbghelp failed to load the module or enumerate its types.
    """
    return read_types(pdb_path, image_path, image_base, build_structs)


def layout_of(pdb_path, image_path, image_base, name_or_type_index):
    """The layout of one UDT by name or by session TypeIndex, or None.

    A TypeIndex is opaque and valid only for the session that produced it
    (spec §10.2(4)), so a name is the portable key; an id is accepted because a
    caller may still hold one from the same live session. An unknown name, an
    id dbghelp does not know, and a type that is not a UDT all return None
    rather than raising.

    Raises:
        TypeError: the key is neither a name nor a TypeIndex.
        PdbError: no image path was supplied, the image cannot be read, or
            dbghelp failed to load the module.
    """
    if not isinstance(name_or_type_index, (int, str)):
        raise TypeError(
            "a layout is looked up by type name or TypeIndex, not "
            f"{type(name_or_type_index).__name__}")
    return read_types(pdb_path, image_path, image_base,
                      lambda reader: _layout_for(reader, name_or_type_index))
