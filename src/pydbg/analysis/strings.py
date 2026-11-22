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


def _ascii_run(data, index):
    """Bytes in the printable run starting at 'index' (0 if it is not one)."""
    end = index
    while end < len(data) and _printable(data[end]):
        end += 1
    return end - index


def _utf16_run(data, index):
    """Bytes in the UTF-16LE run starting at 'index' (0 if no pair starts).

    Whether a run may begin mid-buffer is decided by the caller; the encoding
    comparison and the NUL-boundary question are documented in
    strings_in_bytes.
    """
    end = index
    while end + 1 < len(data) and _utf16_char_at(data, end):
        end += 2
    return end - index


def strings_in_bytes(data, base_rva=0, min_length=4):
    """Printable runs in `data`, each positioned at `base_rva` + its offset.

    Two encodings are considered at every offset: an ASCII run of printable
    bytes and a UTF-16LE run of printable-low/NUL-high pairs. The longer byte
    span wins, so each string is reported once, whole, under the encoding
    that actually explains its bytes; a tie goes to ASCII.

    The comparison replaces the old "a UTF-16 run may not start inside an
    ASCII run" boundary rule, which lost characters. The NUL ending an ASCII
    string is also a valid UTF-16 high byte, so the longest-run rule still
    keeps ``b"hello\\x00"`` and a following wide ``Wide`` apart — but it also
    finds ``Hello`` in ``b"A" + "Hello"`` in UTF-16LE, where the run starts at
    offset 1 and the old rule reported only ``ello`` from offset 3.

    A candidate shorter than `min_length` characters is not emitted, and the
    scan then advances one byte, not the candidate's length: a run that starts
    mid-way must not be hidden by a shorter run that starts before it.
    Results are in address order.
    """
    found = []
    index = 0
    while index < len(data):
        ascii_length = _ascii_run(data, index)
        utf16_length = _utf16_run(data, index)
        if utf16_length > ascii_length:
            length, encoding = utf16_length, UTF16LE
        else:
            length, encoding = ascii_length, ASCII
        chars = length // 2 if encoding == UTF16LE else length
        if length and chars >= min_length:
            if encoding == UTF16LE:
                text = data[index:index + length:2].decode("ascii")
            else:
                text = data[index:index + length].decode("ascii")
            found.append(FoundString(base_rva + index, encoding, text))
            index += length
        else:
            index += 1
    return found


def _section_bytes(pe, section):
    """The bytes of `section` this image can actually supply, or None.

    `read_rva` refuses a range it cannot satisfy in full, and a section's span
    can exceed what the file stores — the uninitialised tail. Asking for the
    span would then return None even though the file-backed prefix is
    readable, so retry with size_of_raw_data before giving up. Only a section
    with no readable bytes at all comes back as None.
    """
    data = pe.read_rva(section.virtual_address, section.span)
    if data is not None:
        return data
    if 0 < section.size_of_raw_data < section.span:
        return pe.read_rva(section.virtual_address, section.size_of_raw_data)
    return None


def extract_strings(pe, min_length=4, sections=None):
    """Printable runs in the image's sections, in address order.

    `sections` is None for every section the file stores, or a list of section
    names to limit the search. A section whose declared span is larger than
    its file-backed data is read up to what exists — an uninitialised tail is
    not a reason to drop the readable prefix. A section with no readable bytes
    at all is skipped, which is `read_rva`'s contract: a truncated image
    yields the strings before the truncation and nothing else, rather than an
    exception.
    """
    wanted = None if sections is None else set(sections)
    found = []
    for section in pe.sections:
        if wanted is not None and section.name not in wanted:
            continue
        data = _section_bytes(pe, section)
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

    Measured over the readable bytes, which for a section with a
    virtual-only tail is its file-backed prefix rather than nothing. A section
    with no readable bytes is reported at 0.0 with size 0 rather than dropped:
    a section missing from the list and a clean section would look alike to a
    caller wondering where the high-entropy evidence went, and `size` says
    what the number was actually computed over.
    """
    found = []
    for section in pe.sections:
        data = _section_bytes(pe, section)
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
