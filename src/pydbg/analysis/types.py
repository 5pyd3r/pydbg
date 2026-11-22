"""Structure field tables — one exit, two tracks.

A PDB can say what a structure's fields are called; base-relative accesses can
say which offsets a function actually touches, and how. Neither alone is the
whole answer, so this module gives both the same query surface:

    from pydbg.analysis import types
    types.structs(result)                    # layouts from access profiles
    types.structs(result, pdb=pdb)           # layouts read from the PDB
    types.layout_of(result, "Point", pdb=pdb)

`pdb` is duck-typed (anything with `symbols()`, `structs()` and
`layout_of(key)`), so this package never imports `pydbg.pdb`. The layout shape
below mirrors `pydbg.pdb.StructLayout` attribute for attribute, which is what
lets `field_report` compare a PDB layout against an access profile without
either package knowing the other's classes.

Without a PDB the field names are *never invented*: a derived layout carries
`name=None` and only offsets, widths and use counts — the honest half of
structure recovery.
"""

from dataclasses import dataclass

from .access import profiles


@dataclass(frozen=True)
class Field:
    """One data member of a `StructLayout`.

    `offset` is the byte offset inside the structure, and may be negative: a
    base-relative access with a signed displacement is still a field location.
    A profile-derived field has no name and no type — those cannot be read off
    a `mov eax, [ebx+0x18]`, and guessing them would read exactly like a
    layout that knew. `bit_position`/`bit_width` are carried for parity with
    `pydbg.pdb.Field`; a profile never has them.
    """

    offset: int
    name: str | None
    type_name: str | None
    size: int
    bit_position: int | None = None
    bit_width: int | None = None


@dataclass(frozen=True)
class StructLayout:
    """A structure's field table, in declaration order.

    `source` is "pdb" for a layout read from a type stream and "profile" for
    one derived here from memory accesses. `truncated` says the table does not
    describe every byte of the structure (a base class, a vtable, or a member
    that could not be read) — it is always False for a derived layout, whose
    span is exactly what the accesses touched.
    """

    name: str | None
    size: int
    fields: tuple[Field, ...]
    source: str = "pdb"
    truncated: bool = False

    def __post_init__(self):
        if not isinstance(self.fields, tuple):
            object.__setattr__(self, "fields", tuple(self.fields))


def _profile_layout(profile):
    """The `StructLayout` for one (function, base register) access profile.

    The name is a label, not an identity: `"<function rva>:<base register>"`
    says exactly which observation this table came from, because the same
    layout may be seen through a different register in a different function
    and this cannot prove they are one type.
    """
    fields = tuple(
        Field(offset=offset, name=None, type_name=None, size=use.size)
        for offset, use in sorted(profile.fields.items()))
    return StructLayout(name=f"{profile.function}:{profile.base_reg}",
                        size=profile.span, fields=fields, source="profile")


def structs(result, pdb=None):
    """Every structure layout the available evidence supports.

    With a PDB, the handle's layouts are returned as-is: they are the more
    precise description and there is nothing here to improve on them.
    Without one, the access profiles are promoted to layouts — only those that
    look like structures (at least `STRUCTURE_MIN_OFFSETS` offsets), and with
    no invented names.
    """
    if pdb is not None:
        return tuple(pdb.structs())
    return tuple(_profile_layout(profile)
                 for profile in profiles(result).values())


def layout_of(result, key, pdb=None):
    """One structure layout by name (with a PDB) or by function RVA.

    A name is the portable key and only a PDB knows names. Without one, an
    integer RVA finds the first profile layout for that function — first by
    base register, since several registers may each describe a structure and
    only the caller can say which one it meant. Anything else, and any miss,
    returns None rather than raising: probing for a type is not an error.
    """
    if pdb is not None:
        return pdb.layout_of(key)
    if not isinstance(key, int):
        return None
    for profile in profiles(result).values():
        if profile.function == key:
            return _profile_layout(profile)
    return None


@dataclass(frozen=True)
class FieldReport:
    """One offset's view across both tracks.

    `present_in` says which evidence has this offset: "pdb", "profile", or
    "both". `reads`/`writes`/`called` come from the access profile and are
    zero/False where the profile saw nothing — a field the PDB names but no
    recovered code touches is still worth reporting, with the absence of use
    showing.
    """

    offset: int
    name: str | None
    type_name: str | None
    size: int
    reads: int
    writes: int
    called: bool
    present_in: str


def field_report(layout, profile):
    """Align a layout's fields with a profile's offsets, ascending.

    Every offset either side knows appears exactly once per layout field and
    once per profile-only offset. Offsets that match are "both"; layout-only
    are "pdb" (the layout is the PDB track); profile-only are "profile" and
    carry no name or type, because the accesses cannot supply one. Nothing is
    dropped for not matching, which is the point of putting the two tracks in
    one table.

    A layout whose own `source` is "profile" is a profile-track table, so its
    fields are reported as "profile" rather than being mislabelled as PDB
    evidence: there is only one track present in that call.
    """
    uses = dict(profile.fields) if profile is not None else {}
    layout_fields = tuple(layout.fields) if layout is not None else ()
    layout_is_pdb = getattr(layout, "source", "pdb") != "profile"
    rows = []
    seen = set()
    for order, field in enumerate(layout_fields):
        use = uses.get(field.offset)
        rows.append((field.offset, 0, order, FieldReport(
            offset=field.offset,
            name=field.name,
            type_name=field.type_name,
            size=field.size,
            reads=0 if use is None else use.reads,
            writes=0 if use is None else use.writes,
            called=False if use is None else use.called,
            present_in=(("both" if use is not None else "pdb")
                        if layout_is_pdb else "profile"))))
        seen.add(field.offset)
    for offset in sorted(offset for offset in uses if offset not in seen):
        use = uses[offset]
        rows.append((offset, 1, 0, FieldReport(
            offset=offset,
            name=None,
            type_name=None,
            size=use.size,
            reads=use.reads,
            writes=use.writes,
            called=use.called,
            present_in="profile")))
    rows.sort(key=lambda row: row[:3])
    return tuple(row[3] for row in rows)
