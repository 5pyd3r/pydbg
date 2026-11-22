"""Strings, section entropy, and the cheap signs that an image is packed.

S8's first facts need no disassembly: the text an image contains, where it
sits, and whether the sections look like a packer wrote them. Keeping them
here — rather than on `PE` — leaves the format parser a format parser, and
keeps the result records importable without the Windows extension (ADR-0001).

Every failure path returns an empty list or 0.0. A truncated or malformed
image is ordinary input for this module: it is the shape of the thing being
analysed, not an error worth aborting a scan for.
"""

from dataclasses import dataclass

ASCII = "ascii"
UTF16LE = "utf-16le"

_PRINTABLE_MIN = 0x20
_PRINTABLE_MAX = 0x7E


@dataclass(frozen=True, slots=True)
class FoundString:
    """One printable run, where it starts, and how it is encoded.

    `text` is the decoded string, so its length is the string's length in
    characters regardless of how many bytes the encoding took.
    """

    rva: int
    encoding: str
    text: str


def _printable(byte):
    return _PRINTABLE_MIN <= byte <= _PRINTABLE_MAX


def strings_in_bytes(data, base_rva=0, min_length=4):
    """Printable runs in `data`, each positioned at `base_rva` + its offset."""
    if not data:
        return []
    found = []
    index = 0
    while index < len(data):
        if not _printable(data[index]):
            index += 1
            continue
        start = index
        while index < len(data) and _printable(data[index]):
            index += 1
        if index - start >= min_length:
            text = data[start:index].decode("ascii")
            found.append(FoundString(base_rva + start, ASCII, text))
    return found
