"""Find the PDB that belongs to an image, and prove it is the same build.

dbghelp loads a PDB from a different build without an error: the only symptom
is a handful of public symbols whose addresses are wrong. Finding the file and
comparing its identity against the image's CodeView record is therefore the
only defence, and it lives here rather than behind a load call.

All lookups go through `find`; `open_for` is its convenience form. See
research/pdb-format.md §A3 for the identity layout (raw GUID bytes plus age)
and §A5 for the reason strings a failed lookup reports.
"""

import os
from dataclasses import dataclass

from .dbghelp import symbols as read_symbols
from .errors import PdbFormatError
from .msf import MSFFile
from .types import layout_of as read_layout, structs as read_structs

RSDS = "RSDS"     # PDB 7.0 CodeView record; the only form that carries a GUID
NB10 = "NB10"     # PDB 2.0 CodeView record; no GUID, so no identity to check

NO_CODEVIEW = "no codeview"
NOT_FOUND = "not found"
PDB_MISMATCH = "pdb mismatch"
PDB_2_UNSUPPORTED = "pdb 2.0 unsupported"
BAD_PDB = "bad pdb"


@dataclass(frozen=True)
class PdbLookup:
    """The outcome of looking for an image's PDB.

    Exactly one story is told: `reason is None` means `pdb` is the verified
    file; otherwise `pdb` is None and `reason` is the short string from spec
    §10.3. `path` is the file the lookup selected — the loaded one on success,
    the inspected one on "pdb mismatch" or "bad pdb", and None when no file was
    selected. `message` is human-readable detail that never decides anything
    (the original PdbFormatError text for "bad pdb", the searched locations for
    "not found").
    """

    pdb: "Pdb | None"
    path: str | None
    reason: str | None = None
    message: str | None = None


def _image_of(pe_or_image):
    """The PE behind an image.

    `pydbg.analysis.AnalyzedImage` wraps the PE as `.pe`, and this package must
    not import `analysis` (the dependency is one-way), so the wrapper is
    recognised structurally. A `pydbg.pe.PE` passes through unchanged.
    """
    return getattr(pe_or_image, "pe", pe_or_image)


def _image_path(pe_or_image, image):
    """Where the image file lives, if either object knows.

    The wrapper is checked too: an AnalyzedImage may carry the path even when
    the inner PE does not. `pydbg.pe.PE` built by from_file() keeps no path at
    all, so the sibling-PDB step is simply unavailable for it.
    """
    for candidate in (pe_or_image, image):
        path = getattr(candidate, "path", None)
        if path:
            return os.fspath(path)
    return None


def _codeview_entries(image):
    """The image's decoded CodeView records, whether stored as a method or property.

    `pydbg.pe.PE.codeview_entries` is a property; a duck-typed image may expose
    it as a method. Both are accepted so a caller does not have to know which.
    """
    entries = getattr(image, "codeview_entries", None)
    if entries is None:
        return []
    if callable(entries):
        entries = entries()
    return list(entries)


def _identity_or_reason(image):
    """The image's RSDS identity, or why there is none to check against.

    RSDS is preferred even when an earlier record is NB10: a merged image can
    carry both, and only the RSDS record can establish sameness. "pdb 2.0
    unsupported" is reported only when there is no RSDS record at all.
    """
    seen_nb10 = False
    for entry in _codeview_entries(image):
        signature = getattr(entry, "signature", None)
        if signature == RSDS:
            return entry, None
        if signature == NB10:
            seen_nb10 = True
    if seen_nb10:
        return None, PDB_2_UNSUPPORTED
    return None, NO_CODEVIEW


def _identity_matches(info, entry):
    """Whether PDB info 'info' names the same build as CodeView 'entry'.

    The authoritative comparison is on the raw 16 GUID bytes plus the age:
    both files store the GUID in Windows memory order, so the bytes are equal
    exactly when the builds are. Some image-side records expose only the
    rendered 8-4-4-4-12 GUID (`pydbg.pe.CodeViewInfo` does), so that form is
    compared case-insensitively as a fallback. The age is compared either way.
    """
    if getattr(entry, "age", None) != info.age:
        return False
    raw = getattr(entry, "guid_bytes", None)
    if isinstance(raw, (bytes, bytearray, memoryview)):
        return bytes(raw) == info.guid_bytes
    guid = getattr(entry, "guid", None)
    if not isinstance(guid, str):
        return False
    return guid.casefold() == info.guid.casefold()


def _entry_guid_text(entry):
    """The image-side GUID for a diagnostic message, however the record holds it."""
    guid = getattr(entry, "guid", None)
    if guid:
        return guid
    raw = getattr(entry, "guid_bytes", None)
    if isinstance(raw, (bytes, bytearray, memoryview)):
        return bytes(raw).hex().upper()
    return "unknown"


def _candidate_paths(entry, image_path, search_paths):
    """The PDB paths to try, in the order the spec fixes.

    Explicit search paths first (they are the caller's override), then the
    absolute path the build recorded, then the image's own directory with the
    image's stem. A candidate is a file path, not a directory: the caller names
    the PDB it wants considered, and a name that does not exist is passed over
    in favour of the next location.
    """
    candidates = [os.fspath(path) for path in search_paths]
    recorded = getattr(entry, "pdb_path", None)
    if recorded:
        candidates.append(recorded)
    if image_path:
        stem = os.path.splitext(os.fspath(image_path))[0]
        candidates.append(stem + ".pdb")
    return candidates


def find(pe_or_image, search_paths=()):
    """Locate the image's PDB and verify it is the same build.

    Lookup order is `search_paths`, then the CodeView record's absolute path,
    then `<image dir>/<image stem>.pdb`. The first candidate that exists is the
    one that decides the outcome: if it is unreadable the reason is "bad pdb",
    and if its GUID/age do not match the image the reason is "pdb mismatch" —
    the search does not fall through to a later location, or a corrupt override
    would be silently ignored.

    Args:
        pe_or_image: A `pydbg.pe.PE`, or anything with `.pe` (an
            AnalyzedImage), or a duck-typed object exposing `codeview_entries`
            and optionally `path`.
        search_paths: PDB file paths to try before the image's own record.

    Returns:
        PdbLookup: the verified `pdb` with reason None, or pdb None with one of
        "no codeview", "not found", "pdb mismatch", "pdb 2.0 unsupported" and
        "bad pdb".
    """
    image = _image_of(pe_or_image)
    entry, reason = _identity_or_reason(image)
    if reason is not None:
        return PdbLookup(None, None, reason)

    image_path = _image_path(pe_or_image, image)
    candidates = _candidate_paths(entry, image_path, search_paths)
    selected = None
    for candidate in candidates:
        if os.path.isfile(candidate):
            selected = candidate
            break
    if selected is None:
        message = "looked for: " + ", ".join(candidates) if candidates else None
        return PdbLookup(None, None, NOT_FOUND, message)

    image_base = getattr(image, "image_base", None)
    if image_base is None:
        image_base = getattr(pe_or_image, "image_base", None)
    pdb = Pdb(selected, image_path=image_path, image_base=image_base)
    try:
        info = pdb._info()
    except (PdbFormatError, OSError) as exc:
        # A file that exists but cannot be read as PDB 7.0 is explicit
        # "bad pdb", not "not found": the path was right, the file was not.
        return PdbLookup(None, selected, BAD_PDB, str(exc))

    if not _identity_matches(info, entry):
        message = (f"pdb {info.guid} age {info.age} does not match image "
                   f"{_entry_guid_text(entry)} age {getattr(entry, 'age', None)}")
        return PdbLookup(None, selected, PDB_MISMATCH, message)
    return PdbLookup(pdb, selected)


def open_for(pe_or_image, search_paths=()):
    """The verified PDB for 'pe_or_image', or None — `find(...).pdb`.

    One implementation, not two: callers that only want the object do not get
    a second, subtly different search.
    """
    return find(pe_or_image, search_paths).pdb


class Pdb:
    """A PDB file on disk, opened lazily on first use.

    Construction only records where the file is; reading it happens when an
    identity is needed, so a lookup can hand back a Pdb without paying for the
    parse until the caller asks something. `image_path` is the image the PDB
    belongs to — dbghelp needs it to locate the PDB and to bound the symbols'
    RVAs, so `symbols()` refuses to guess when it is absent. `image_base` is
    the base the symbols' addresses are relative to (the preferred base for a
    file); it is not used by the identity check and is kept for the symbol
    reader, which passes it to SymLoadModuleExW.
    """

    def __init__(self, path, image_path=None, image_base=None):
        self.path = os.fspath(path)
        self.image_path = (os.fspath(image_path)
                           if image_path is not None else None)
        self.image_base = image_base
        self._msf = None
        self._symbols = None
        self._structs = None

    def _file(self):
        if self._msf is None:
            self._msf = MSFFile(self.path)
        return self._msf

    def _info(self):
        return self._file().info

    def symbols(self):
        """Every named address in this PDB, sorted by (rva, name).

        The first call runs the offline dbghelp session; the tuple is cached,
        so repeated calls are idempotent and cost nothing. A PDB with no image
        cannot be enumerated: dbghelp needs the image to find the file and to
        know the image's size, and guessing either would produce wrong RVAs.

        Returns:
            tuple[PdbSymbol, ...]: empty when dbghelp enumerated nothing; that
            is not proof the PDB was read, and the analysis layer reports
            "pdb: no symbols" rather than treating it as success.

        Raises:
            PdbError: no image path was given, the image is missing or
                unreadable, or dbghelp failed.
        """
        if self._symbols is None:
            self._symbols = read_symbols(self.path, self.image_path,
                                         self.image_base)
        return self._symbols

    def structs(self):
        """Every UDT this PDB describes, sorted by name and size.

        The first call reads the type stream and caches the tuple, so repeated
        calls compare equal and cost nothing. A layout carries no TypeIndex
        (spec §10.2(4)); use `layout_of(name)` rather than keeping an id from
        one call and passing it to another, because dbghelp restarts its session
        when the symbol search path changes.

        Returns:
            tuple[StructLayout, ...]: empty when no UDT was enumerated, which —
            like `symbols() == ()` — is not proof the PDB was read.

        Raises:
            PdbError: no image path was given, the image is missing or
                unreadable, or dbghelp failed to enumerate the types.
        """
        if self._structs is None:
            self._structs = read_structs(self.path, self.image_path,
                                         self.image_base)
        return self._structs

    def layout_of(self, name_or_type_index):
        """The field table of one UDT, by type name or by TypeIndex, or None.

        A name is the portable key. A TypeIndex is a session-scoped id
        (spec §10.2(4)): it is accepted for callers holding one from the same
        live session, and means nothing in another. An unknown name, an id
        dbghelp does not know and a type that is not a UDT all return None
        instead of raising, so probing for a type is not an error path.

        Raises:
            TypeError: the key is neither a name nor a TypeIndex.
            PdbError: no image path was given, the image is missing or
                unreadable, or dbghelp failed to load the module.
        """
        return read_layout(self.path, self.image_path, self.image_base,
                           name_or_type_index)

    def matches(self, pe_or_image):
        """Whether this PDB is the same build as 'pe_or_image'.

        False when the image has no RSDS CodeView record: an NB10 (PDB 2.0)
        record carries no GUID, and no record at all carries no identity, so
        neither can be shown to match.

        Raises:
            PdbFormatError: this file is not a readable PDB 7.0 container.
        """
        entry, _reason = _identity_or_reason(_image_of(pe_or_image))
        if entry is None:
            return False
        return _identity_matches(self._info(), entry)
