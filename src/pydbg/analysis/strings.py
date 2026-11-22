"""Strings, section entropy, and the cheap signs that an image is packed.

S8's first facts need no disassembly: the text an image contains, where it
sits, and whether the sections look like a packer wrote them. Keeping them
here — rather than on `PE` — leaves the format parser a format parser, and
keeps the result records importable without the Windows extension (ADR-0001).

Every failure path returns an empty list or 0.0. A truncated or malformed
image is ordinary input for this module: it is the shape of the thing being
analysed, not an error worth aborting a scan for.
"""

from collections import Counter
from dataclasses import dataclass
import math

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


@dataclass(frozen=True, slots=True)
class SectionEntropy:
    """One section's Shannon entropy, and how many bytes it was measured over.

    `size` is the number of readable bytes, not the section's declared span:
    the two differ whenever the file is truncated, and an entropy figure whose
    denominator is an assumption is worse than one that states it.
    """

    name: str
    entropy: float
    size: int


# Substrings a packer's section names are known to contain, lower-case. The
# match is on the lower-cased name, so `UPX0` and `upx0` are the same evidence.
_SUSPICIOUS_MARKERS = ("upx", ".aspack", ".adata", ".packed",
                       ".themida", ".vmp")


@dataclass(frozen=True, slots=True)
class PackingHints:
    """Cheap, separate signals that an image may be packed.

    Four facts rather than one verdict on purpose. A writable+executable
    section is suspicious with no entropy story at all; a high-entropy section
    is unremarkable in some legitimate images; and an image with almost no
    imports may simply not need any. Collapsing them into "packed: yes" would
    hide which evidence produced the answer.
    """

    high_entropy_sections: list
    write_exec_sections: list
    low_import_count: bool
    suspicious_section_names: list


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


def extract_strings(pe, min_length=4, sections=None):
    """Printable runs in the image's sections, in address order.

    `sections` is None for every section the file stores, or a list of section
    names to limit the search. A section that cannot be read is skipped, which
    is `read_rva`'s contract: a truncated image yields the strings before the
    truncation and nothing else, rather than an exception.
    """
    wanted = None if sections is None else set(sections)
    found = []
    for section in pe.sections:
        if wanted is not None and section.name not in wanted:
            continue
        data = pe.read_rva(section.virtual_address, section.span)
        if not data:
            continue
        found.extend(strings_in_bytes(data, base_rva=section.virtual_address,
                                      min_length=min_length))
    found.sort(key=lambda string: (string.rva, string.encoding))
    return found


def _shannon_entropy(data):
    """-Σ p·log2(p) over the byte distribution; 0.0 when there are no bytes."""
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total)
                for count in counts.values())


def section_entropy(pe):
    """Shannon entropy per section, in section-table order.

    A section that cannot be read is reported at 0.0 with size 0 rather than
    dropped: a section missing from the list and a clean section would look
    alike to a caller wondering where the high-entropy evidence went.
    """
    found = []
    for section in pe.sections:
        data = pe.read_rva(section.virtual_address, section.span)
        if not data:
            found.append(SectionEntropy(section.name, 0.0, 0))
            continue
        found.append(SectionEntropy(section.name, _shannon_entropy(data),
                                    len(data)))
    return found


def _looks_suspicious(name):
    lowered = name.lower()
    return any(marker in lowered for marker in _SUSPICIOUS_MARKERS)


def packing_hints(pe, entropy_threshold=7.0, low_import_threshold=8):
    """Cheap packing evidence, one fact per field, in section-table order.

    Defaults are the ones a normal image clears: textual code and data sit far
    below 7 bits of entropy, and an ordinary program imports more than eight
    functions. They are arguments because a shellcode stub or a driver may
    reasonably want different ones.
    """
    entropies = section_entropy(pe)
    return PackingHints(
        high_entropy_sections=[section.name for section in entropies
                               if section.entropy >= entropy_threshold],
        write_exec_sections=[section.name for section in pe.sections
                             if section.is_executable and section.is_writable],
        low_import_count=len(pe.imports) < low_import_threshold,
        suspicious_section_names=[section.name for section in pe.sections
                                  if _looks_suspicious(section.name)],
    )
