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


def _utf16_char_at(data, index):
    return (index + 1 < len(data) and _printable(data[index])
            and data[index + 1] == 0)


def _utf16_strings(data, base_rva, min_length, consumed):
    """UTF-16LE runs whose every character is ASCII and followed by a NUL."""
    found = []
    index = 0
    while index + 1 < len(data):
        if not _utf16_char_at(data, index):
            index += 1
            continue
        start = index
        while index + 1 < len(data) and _utf16_char_at(data, index):
            index += 2
        if (index - start) // 2 >= min_length:
            text = data[start:index:2].decode("ascii")
            found.append(FoundString(base_rva + start, UTF16LE, text))
            consumed[start:index] = b"\x01" * (index - start)
    return found


def _ascii_strings(data, base_rva, min_length, consumed):
    """ASCII runs, skipping bytes the UTF-16 pass already claimed."""
    found = []
    index = 0
    while index < len(data):
        if consumed[index] or not _printable(data[index]):
            index += 1
            continue
        start = index
        while (index < len(data) and not consumed[index]
               and _printable(data[index])):
            index += 1
        if index - start >= min_length:
            text = data[start:index].decode("ascii")
            found.append(FoundString(base_rva + start, ASCII, text))
    return found


def strings_in_bytes(data, base_rva=0, min_length=4):
    """Printable runs in `data`, each positioned at `base_rva` + its offset.

    UTF-16LE is recognised first and its bytes are claimed before the ASCII
    pass runs. Doing it the other way around reports a UTF-16 string as a run
    of one-character ASCII fragments — five findings where there is one.

    Results are in address order, whatever order the two passes found them in.
    """
    if not data:
        return []
    consumed = bytearray(len(data))
    found = _utf16_strings(data, base_rva, min_length, consumed)
    found.extend(_ascii_strings(data, base_rva, min_length, consumed))
    found.sort(key=lambda string: (string.rva, string.encoding))
    return found
