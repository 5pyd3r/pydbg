"""PE resource directory parser.

Parses the 3-layer resource directory tree (Type -> Name -> Language)
from a PE file's .rsrc section.
"""

import struct
from dataclasses import dataclass


@dataclass
class ResourceEntry:
    """A single PE resource entry.

    Represents one leaf node in the 3-layer resource directory tree:
    Type -> Name -> Language.
    """

    type_id: int
    type_name: str
    name_id: int
    name_str: str
    language_id: int
    data_rva: int
    data_size: int
    data_offset: int


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


# IMAGE_RESOURCE_DIRECTORY structure:
# Characteristics(4) + TimeDateStamp(4) + MajorVersion(2) + MinorVersion(2)
# + NumberOfNamedEntries(2) + NumberOfIdEntries(2) = 16 bytes
_RSRC_DIR_HDR_SIZE = 16

# IMAGE_RESOURCE_DIRECTORY_ENTRY:
# IdOrNameOffset(4) + DataOrSubdirOffset(4) = 8 bytes per entry
_RSRC_DIR_ENTRY_SIZE = 8

# IMAGE_RESOURCE_DATA_ENTRY:
# OffsetToData(4) + Size(4) + CodePage(4) + Reserved(4) = 16 bytes
_RSRC_DATA_ENTRY_SIZE = 16


class PEResourceParser:
    """Parse PE resource directories from a .rsrc section.

    Args:
        pe: A parsed PE object with .sections and ._source attributes.
            The PE object must have:
            - sections: list of SectionHeader with virtual_address, virtual_size,
              pointer_to_raw_data
            - _source: Source object with read(offset, size) method
    """

    def __init__(self, pe):
        self._pe = pe
        self._rsrc_section = self._find_rsrc_section()
        self._entries: list[ResourceEntry] = []
        self._parsed = False

    def _find_rsrc_section(self):
        """Find the .rsrc section in the PE."""
        for section in self._pe.sections:
            if section.name == ".rsrc":
                return section
        return None

    def parse(self) -> list[ResourceEntry]:
        """Parse the resource directory tree and return all resource entries.

        Returns:
            List of ResourceEntry objects found in the .rsrc section.
        """
        if self._parsed:
            return self._entries

        self._entries = []
        if self._rsrc_section is None:
            self._parsed = True
            return self._entries

        # Walk the 3-layer tree starting at the .rsrc section base
        rsrc_base = self._rsrc_section.pointer_to_raw_data
        self._walk_directory(rsrc_base, rsrc_base, 0, 0, "", 0, "")
        self._parsed = True
        return self._entries

    def _walk_directory(self, rsrc_base, dir_offset, depth,
                        type_id, type_name, name_id, name_str):
        """Recursively walk the resource directory tree.

        Args:
            rsrc_base: File offset of the .rsrc section start.
            dir_offset: File offset of the current directory node.
            depth: 0=Type, 1=Name, 2=Language.
            type_id: Type ID (accumulated from depth 0).
            type_name: Type name (accumulated from depth 0).
            name_id: Name ID (accumulated from depth 1).
            name_str: Name string (accumulated from depth 1).
        """
        # Read IMAGE_RESOURCE_DIRECTORY header
        hdr = self._pe._source.read(dir_offset, _RSRC_DIR_HDR_SIZE)
        _, _, _, _, num_named, num_id = struct.unpack_from(
            '<IIHHHH', hdr, 0)

        total_entries = num_named + num_id
        entry_offset = dir_offset + _RSRC_DIR_HDR_SIZE

        for _ in range(total_entries):
            entry_data = self._pe._source.read(
                entry_offset, _RSRC_DIR_ENTRY_SIZE)
            id_or_name, data_or_subdir = struct.unpack_from(
                '<II', entry_data, 0)

            # High bit set = offset to name string or subdirectory
            # High bit clear = integer ID
            is_named = (id_or_name & 0x80000000) != 0
            is_subdir = (data_or_subdir & 0x80000000) != 0

            entry_id = id_or_name & 0x7FFFFFFF if not is_named else 0
            entry_name = ""
            if is_named:
                entry_name = self._read_resource_string(
                    rsrc_base, id_or_name & 0x7FFFFFFF)

            if depth == 0:
                # Type level
                cur_type_id = entry_id
                cur_type_name = (entry_name if is_named
                                 else RESOURCE_TYPES.get(
                                     cur_type_id, f"RT_{cur_type_id}"))
                if is_subdir:
                    subdir_offset = rsrc_base + (data_or_subdir & 0x7FFFFFFF)
                    self._walk_directory(
                        rsrc_base, subdir_offset, 1,
                        cur_type_id, cur_type_name, 0, "")

            elif depth == 1:
                # Name level
                cur_name_id = entry_id
                cur_name_str = entry_name if is_named else ""
                if is_subdir:
                    subdir_offset = rsrc_base + (data_or_subdir & 0x7FFFFFFF)
                    self._walk_directory(
                        rsrc_base, subdir_offset, 2,
                        type_id, type_name, cur_name_id, cur_name_str)

            elif depth == 2:
                # Language level -- leaf node
                language_id = id_or_name & 0xFFFF  # LangID is low 16 bits
                # data_or_subdir is an offset to IMAGE_RESOURCE_DATA_ENTRY
                data_entry_offset = rsrc_base + data_or_subdir
                data_entry_data = self._pe._source.read(
                    data_entry_offset, _RSRC_DATA_ENTRY_SIZE)
                data_rva, data_size, _code_page, _ = struct.unpack_from(
                    '<IIII', data_entry_data, 0)

                # Convert data_rva to file offset
                data_file_offset = self._rva_to_offset(data_rva)

                self._entries.append(ResourceEntry(
                    type_id=type_id,
                    type_name=type_name,
                    name_id=name_id,
                    name_str=name_str,
                    language_id=language_id,
                    data_rva=data_rva,
                    data_size=data_size,
                    data_offset=data_file_offset,
                ))

            entry_offset += _RSRC_DIR_ENTRY_SIZE

    def _rva_to_offset(self, rva):
        """Convert RVA to file offset using the PE's section table."""
        for section in self._pe.sections:
            if (section.virtual_address <= rva <
                    section.virtual_address + section.virtual_size):
                return rva - section.virtual_address + section.pointer_to_raw_data
        return 0

    def _read_resource_string(self, rsrc_base, offset):
        """Read a resource directory Unicode string.

        Resource strings are stored as: Length(2) + UTF-16LE characters.
        """
        str_offset = rsrc_base + offset
        data = self._pe._source.read(str_offset, 2)
        length = struct.unpack_from('<H', data, 0)[0]
        if length == 0:
            return ""
        str_data = self._pe._source.read(str_offset + 2, length * 2)
        return str_data.decode('utf-16-le', errors='replace')

    def get_by_type(self, type_id: int) -> list[ResourceEntry]:
        """Get all resource entries matching a given type ID.

        Args:
            type_id: The resource type ID to filter by.

        Returns:
            List of ResourceEntry objects with the matching type_id.
        """
        if not self._parsed:
            self.parse()
        return [e for e in self._entries if e.type_id == type_id]

    def get_by_name(self, name: str) -> list[ResourceEntry]:
        """Get all resource entries matching a given type name.

        Args:
            name: The resource type name to filter by (e.g. "RT_RCDATA").

        Returns:
            List of ResourceEntry objects with the matching type_name.
        """
        if not self._parsed:
            self.parse()
        return [e for e in self._entries if e.type_name == name]

    def extract(self, entry: ResourceEntry) -> bytes:
        """Extract the raw data for a single resource entry.

        Args:
            entry: The ResourceEntry to extract data from.

        Returns:
            The raw bytes of the resource data.
        """
        return self._pe._source.read(entry.data_offset, entry.data_size)

    def extract_all(self, output_dir: str = ".") -> list[str]:
        """Extract all resources to files in the given directory.

        File extensions are guessed based on magic bytes:
        - .wav for RIFF audio
        - .bmp for BMP images
        - .bin for everything else

        Args:
            output_dir: Directory to write extracted files to.

        Returns:
            List of file paths that were written.
        """
        import os

        if not self._parsed:
            self.parse()

        written = []
        for i, entry in enumerate(self._entries):
            data = self.extract(entry)
            ext = self._guess_extension(data)
            type_label = entry.type_name or str(entry.type_id)
            filename = f"{type_label}_{entry.name_id}_{entry.language_id:04x}{ext}"
            filepath = os.path.join(output_dir, filename)
            with open(filepath, "wb") as f:
                f.write(data)
            written.append(filepath)
        return written

    @staticmethod
    def _guess_extension(data: bytes) -> str:
        """Guess file extension from magic bytes."""
        if len(data) >= 4 and data[:4] == b"RIFF":
            return ".wav"
        if len(data) >= 2 and data[:2] == b"BM":
            return ".bmp"
        return ".bin"
