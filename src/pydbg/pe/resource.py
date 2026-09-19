"""Resource directory parsing (data directory 2).

The resource tree is three levels deep — type, name, language — and every
offset inside it is relative to the directory's own base RVA rather than to the
file. Working from that base is what lets the same code read a file and a live
module: everything resolves through PE.read_rva.

Every walk stops at the first range it cannot read instead of raising. The tree
is a graph of self-relative offsets with no terminator and no length field, so
a truncated or deliberately tangled .rsrc is an ordinary thing to meet, and the
honest answer to it is the resources that were readable.
"""

import struct
from dataclasses import dataclass

from .parser import DIR_RESOURCE

# Type -> Name -> Language. Anything deeper is a loop or a lie.
MAX_DEPTH = 3

# The other kind of loop costs nothing to read and never terminates on its own:
# two directories that point at each other. The budget is what stops it.
MAX_NODES = 4096

# Standard Win32 resource type IDs -> names
RESOURCE_TYPES = {
    1: "RT_CURSOR",
    2: "RT_BITMAP",
    3: "RT_ICON",
    4: "RT_MENU",
    5: "RT_DIALOG",
    6: "RT_STRING",
    7: "RT_FONTDIR",
    8: "RT_FONT",
    9: "RT_ACCELERATOR",
    10: "RT_RCDATA",
    11: "RT_MESSAGETABLE",
    12: "RT_GROUP_CURSOR",
    14: "RT_GROUP_ICON",
    16: "RT_VERSION",
    17: "RT_DLGINCLUDE",
    19: "RT_PLUGPLAY",
    20: "RT_VXD",
    21: "RT_ANICURSOR",
    22: "RT_ANIICON",
    23: "RT_HTML",
    24: "RT_MANIFEST",
}

# IMAGE_RESOURCE_DIRECTORY: Characteristics(4) TimeDateStamp(4) MajorVersion(2)
# MinorVersion(2) NumberOfNamedEntries(2) NumberOfIdEntries(2).
_DIR_HEADER_SIZE = 16

# IMAGE_RESOURCE_DIRECTORY_ENTRY: IdOrNameOffset(4) DataOrSubdirOffset(4).
_DIR_ENTRY_SIZE = 8

# IMAGE_RESOURCE_DATA_ENTRY: OffsetToData(4) Size(4) CodePage(4) Reserved(4).
_DATA_ENTRY_SIZE = 16


@dataclass
class ResourceEntry:
    """One leaf of the resource tree: a type/name/language triple and its data.

    'data_offset' is the byte's position in whatever the PE was built from — a
    file offset for a file, an offset into the mapped image for a live module.
    It is None when the data RVA falls outside every section, which is a
    different finding from offset zero and must not be spelled the same way.

    A *named* type has no numeric ID, and 'type_id' is 0 there while
    'type_name' holds the name ('MUI' on a system DLL). Zero is not a real
    type ID, so get_by_type(0) cannot match one by accident.
    """

    type_id: int
    type_name: str
    name_id: int
    name_str: str
    language_id: int
    data_rva: int
    data_size: int
    data_offset: int | None


class PEResourceParser:
    """Parse the resource directory tree of a parsed PE.

    Takes the PE object rather than a byte source so the section table and the
    data directories come from the same place the rest of the parse used.
    """

    def __init__(self, pe):
        self._pe = pe
        self._entries = None
        self._base_rva = self._find_base_rva()

    def _find_base_rva(self):
        """The RVAs in the tree are relative to this, and it is directory 2.

        Deliberately not "the .rsrc section's address", which is where it
        almost always is but is not what the offsets are defined against.
        """
        dd = self._pe.optional_header.data_directories.get(DIR_RESOURCE)
        if dd is None or dd.virtual_address == 0 or dd.size == 0:
            return 0
        return dd.virtual_address

    def parse(self) -> list:
        """Every resource entry in the tree; [] when there is no directory.

        Idempotent, so the accessors below can call it without re-walking.
        """
        if self._entries is None:
            self._entries = []
            if self._base_rva:
                budget = [MAX_NODES]
                self._walk(0, 0, budget, 0, "", 0, "")
        return self._entries

    def _walk(self, dir_offset, depth, budget, type_id, type_name, name_id,
              name_str):
        """Walk one IMAGE_RESOURCE_DIRECTORY node.

        'dir_offset' and everything read here are offsets from the resource
        base, not RVAs, because that is how the format stores them.
        """
        if depth >= MAX_DEPTH or budget[0] <= 0:
            return
        budget[0] -= 1

        header = self._read_rva(self._base_rva + dir_offset, _DIR_HEADER_SIZE)
        if header is None:
            return
        num_named, num_id = struct.unpack_from('<HH', header, 12)

        cursor = dir_offset + _DIR_HEADER_SIZE
        for _ in range(num_named + num_id):
            entry = self._read_rva(self._base_rva + cursor, _DIR_ENTRY_SIZE)
            if entry is None:
                return                      # truncated directory ends the walk
            id_or_name, data_or_subdir = struct.unpack_from('<II', entry, 0)

            is_named = (id_or_name & 0x80000000) != 0
            is_subdir = (data_or_subdir & 0x80000000) != 0
            entry_id = id_or_name & 0x7FFFFFFF if not is_named else 0
            entry_name = (self._read_resource_string(id_or_name & 0x7FFFFFFF)
                          if is_named else "")

            if depth == 0:
                if is_subdir:
                    self._walk(data_or_subdir & 0x7FFFFFFF, 1, budget,
                               entry_id,
                               entry_name if is_named
                               else RESOURCE_TYPES.get(entry_id,
                                                       f"RT_{entry_id}"),
                               0, "")
            elif depth == 1:
                if is_subdir:
                    self._walk(data_or_subdir & 0x7FFFFFFF, 2, budget,
                               type_id, type_name, entry_id,
                               entry_name if is_named else "")
            elif not is_subdir:
                self._add_leaf(data_or_subdir, type_id, type_name, name_id,
                               name_str, id_or_name)

            cursor += _DIR_ENTRY_SIZE

    def _add_leaf(self, data_entry_offset, type_id, type_name, name_id,
                  name_str, id_or_name):
        """Record one language-level entry, whose value points at the data."""
        raw = self._read_rva(self._base_rva + data_entry_offset,
                             _DATA_ENTRY_SIZE)
        if raw is None:
            return
        data_rva, data_size, _code_page, _reserved = struct.unpack_from(
            '<IIII', raw, 0)
        self._entries.append(ResourceEntry(
            type_id=type_id,
            type_name=type_name,
            name_id=name_id,
            name_str=name_str,
            language_id=id_or_name & 0xFFFF,     # LangID is the low 16 bits
            data_rva=data_rva,
            data_size=data_size,
            data_offset=self._pe.rva_to_offset(data_rva),
        ))

    def _read_rva(self, rva, size):
        return self._pe.read_rva(rva, size)

    def _read_resource_string(self, offset):
        """A resource name: a 16-bit count followed by that many UTF-16 units."""
        count = self._read_rva(self._base_rva + offset, 2)
        if count is None:
            return ""
        length = struct.unpack_from('<H', count, 0)[0]
        if length == 0:
            return ""
        raw = self._read_rva(self._base_rva + offset + 2, length * 2)
        if raw is None:
            return ""
        return raw.decode('utf-16-le', errors='replace')

    def get_by_type(self, type_id: int) -> list:
        """Every entry whose numeric type ID matches."""
        return [e for e in self.parse() if e.type_id == type_id]

    def get_by_name(self, type_name: str) -> list:
        """Every entry whose type name matches (e.g. 'RT_RCDATA')."""
        return [e for e in self.parse() if e.type_name == type_name]

    def extract(self, entry) -> bytes:
        """The raw bytes of one entry's data.

        Raises ValueError when the image does not actually hold them: a size
        that lies is common in packed images, and returning a short slice here
        would hand back something that looks like the resource.
        """
        if entry.data_size == 0:
            return b""
        data = self._pe.read_rva(entry.data_rva, entry.data_size)
        if data is None:
            raise ValueError(
                f"resource data at RVA {entry.data_rva:#x} "
                f"({entry.data_size} bytes) is not readable")
        return data

    def extract_all(self, output_dir: str = ".") -> list:
        """Write every resource to 'output_dir'; returns the paths written.

        Extensions are guessed from magic bytes, so treat them as a hint for
        opening the file rather than a statement about its format.
        """
        import os

        written = []
        for index, entry in enumerate(self.parse()):
            data = self.extract(entry)
            label = entry.type_name or str(entry.type_id)
            name = f"{label}_{entry.name_id}_{entry.language_id:04x}"
            filepath = os.path.join(output_dir,
                                    f"{index:04d}_{name}{_guess_extension(data)}")
            with open(filepath, "wb") as handle:
                handle.write(data)
            written.append(filepath)
        return written


def _guess_extension(data: bytes) -> str:
    """A file extension guessed from magic bytes — RIFF, BMP, else .bin."""
    if data[:4] == b"RIFF":
        return ".wav"
    if data[:2] == b"BM":
        return ".bmp"
    return ".bin"
