"""RT_VERSION decoding — VS_VERSIONINFO into fixed info, strings, translations.

The version resource is a tree of length-delimited nodes: 'wLength' bounds the
node, 'wValueLength' sizes its value, and the unit of that size changes with
the level — bytes for the fixed info and the translation array, UTF-16
*characters* (including the terminating NUL) for a String. Treating the unit as
uniform is the classic way to read a version resource and get strings with
their last character lopped off, so every node is parsed with the unit its
level defines.

Every walk stops at the first node whose header, key or declared length does
not hold up, and returns what it read before that point. Version resources are
routinely truncated by resource editors and by packers that keep the header and
drop the tail, and the honest answer to those is the readable prefix rather
than an exception from the middle of a walk. The root is the one exception:
without a readable root there is nothing to return, so that is None.
"""

import struct
from dataclasses import dataclass

from .resource import RT_VERSION

# VS_FIXEDFILEINFO.dwSignature — the only proof that the value is that struct.
VS_FFI_SIGNATURE = 0xFEEF04BD

# VS_FIXEDFILEINFO is 13 DWORDs.
_FIXED_SIZE = 52
_FIXED_STRUCT = "<13I"


@dataclass
class FixedFileInfo:
    """The VS_FIXEDFILEINFO half of a version resource.

    'file_version' and 'product_version' are (major, minor, build, revision).
    The format stores each as two DWORDs, one half per pair, so a decoder that
    reports the raw DWORDs loses the four-part shape callers compare against.

    'file_date' is dwFileDateMS and dwFileDateLS joined into one value: they
    are two halves of a single 64-bit timestamp, not two dates.
    """

    file_version: tuple
    product_version: tuple
    file_flags_mask: int
    file_flags: int
    file_os: int
    file_type: int
    file_subtype: int
    file_date: int


@dataclass
class VersionInfo:
    """A decoded RT_VERSION resource.

    'strings' holds the keys of the first StringTable — the language named by
    'language' and 'codepage'. A merged image can carry several tables, and
    merging them into one map would let a later language overwrite an earlier
    key; 'translations' is where every declared (lang, codepage) pair appears.

    'fixed' is None when the resource has no VS_FIXEDFILEINFO or its signature
    is not VS_FFI_SIGNATURE. The string tables are parsed either way, because
    they are a separate part of the resource.
    """

    fixed: FixedFileInfo | None
    strings: dict
    translations: list
    language: int | None
    codepage: int | None


@dataclass
class _Node:
    """One node of the version tree, with its declared length kept.

    'end' is clamped to the enclosing node, but 'length' is what the node
    claims, because that is what locates the next sibling.
    """

    key: str
    value: bytes
    length: int
    children_start: int
    end: int


def parse_version_info(data: bytes) -> VersionInfo | None:
    """Decode a VS_VERSIONINFO blob; None when it is not one.

    Never raises. A truncated or malformed blob yields the prefix that was
    readable, and anything without a readable VS_VERSION_INFO root is None.
    """
    if not data:
        return None
    root = _parse_node(data, 0, len(data), value_is_chars=False)
    if root is None or root.key != "VS_VERSION_INFO":
        return None

    fixed = _parse_fixed(root.value)
    strings = {}
    translations = []
    language = codepage = None
    have_table = False

    for child in _iter_children(data, root):
        if child.key == "StringFileInfo":
            for table in _iter_children(data, child):
                if have_table:
                    break
                have_table = True
                strings = {
                    string.key: _decode_string(string.value)
                    for string in _iter_children(data, table, value_is_chars=True)
                }
                table_key = _parse_table_key(table.key)
                if table_key is not None:
                    language, codepage = table_key
        elif child.key == "VarFileInfo":
            for variable in _iter_children(data, child):
                if variable.key == "Translation":
                    translations.extend(_parse_translations(variable.value))

    return VersionInfo(fixed=fixed, strings=strings,
                       translations=translations,
                       language=language, codepage=codepage)


def read_version_info(pe):
    """The version resource of a parsed PE; None when it has none.

    The first RT_VERSION entry in the resource tree is the one decoded: a file
    with several is carrying copies, not several versions. The payload is read
    through PE.read_rva so a live module is read the same way as a file.
    """
    entries = pe.resource_parser().get_by_type(RT_VERSION)
    if not entries:
        return None
    entry = entries[0]
    data = pe.read_rva(entry.data_rva, entry.data_size)
    if data is None:
        return None
    return parse_version_info(data)


def _parse_node(data, start, limit, value_is_chars):
    """One node at 'start', bounded by 'limit'; None when unreadable.

    'value_is_chars' selects the unit of 'wValueLength': UTF-16 characters
    where the format counts a string, bytes everywhere else.
    """
    if start + 6 > limit:
        return None
    length, value_length, _w_type = struct.unpack_from("<HHH", data, start)
    if length == 0:
        return None
    end = min(start + length, limit)

    key_end = _find_utf16_nul(data, start + 6, end)
    if key_end is None:
        return None
    key = data[start + 6:key_end].decode("utf-16-le", errors="replace")

    value_start = _align4(key_end + 2)
    value_size = value_length * (2 if value_is_chars else 1)
    value_end = min(value_start + value_size, end)
    value = data[value_start:value_end] if value_start < value_end else b""
    return _Node(
        key=key,
        value=value,
        length=length,
        children_start=_align4(value_start + value_size),
        end=end,
    )


def _iter_children(data, node, value_is_chars=False):
    """The child nodes that fit inside 'node', stopping at the first bad one.

    The next sibling sits at the previous node's declared length, so a
    'wLength' of zero or one that does not advance would be a loop; both end
    the walk instead.
    """
    offset = node.children_start
    while offset + 6 <= node.end:
        child = _parse_node(data, offset, node.end, value_is_chars)
        if child is None:
            return
        yield child
        next_offset = _align4(offset + child.length)
        if next_offset <= offset:
            return
        offset = next_offset


def _parse_fixed(raw):
    """VS_FIXEDFILEINFO, or None when it is short or wrongly signed."""
    if len(raw) < _FIXED_SIZE:
        return None
    fields = struct.unpack_from(_FIXED_STRUCT, raw, 0)
    if fields[0] != VS_FFI_SIGNATURE:
        return None

    def version(high, low):
        return (high >> 16, high & 0xFFFF, low >> 16, low & 0xFFFF)

    return FixedFileInfo(
        file_version=version(fields[2], fields[3]),
        product_version=version(fields[4], fields[5]),
        file_flags_mask=fields[6],
        file_flags=fields[7],
        file_os=fields[8],
        file_type=fields[9],
        file_subtype=fields[10],
        file_date=(fields[11] << 32) | fields[12],
    )


def _decode_string(raw):
    """A String node's value, without its terminating NUL."""
    if len(raw) % 2:
        raw = raw[:-1]
    return raw.decode("utf-16-le", errors="replace").rstrip("\x00")


def _parse_table_key(key):
    """A StringTable key such as '040904B0' -> (0x0409, 0x04B0); else None.

    The key is the language and codepage in hex; it is the only place the
    strings' language is stated, since the tree above it carries no IDs.
    """
    try:
        value = int(key, 16)
    except (TypeError, ValueError):
        return None
    if not 0 <= value <= 0xFFFFFFFF:
        return None
    return value >> 16, value & 0xFFFF


def _parse_translations(raw):
    """The Translation value: (lang, codepage) WORD pairs, as many as fit."""
    return [struct.unpack_from("<HH", raw, offset)
            for offset in range(0, len(raw) - 3, 4)]


def _find_utf16_nul(data, start, end):
    """Offset of the first aligned NUL unit in [start, end), or None."""
    offset = start
    while offset + 2 <= end:
        if data[offset] == 0 and data[offset + 1] == 0:
            return offset
        offset += 2
    return None


def _align4(offset):
    return (offset + 3) & ~3
