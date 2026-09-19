"""Coverage attribution — what the uncovered bytes actually are.

A coverage figure on its own is not actionable. "92.6%" cannot tell you whether
the missing 7.4% is alignment padding that will never decode, a jump table
sitting in the middle of .text, or real code that no seed reached — and those
three call for completely different work. The same is true of the overlap
number: a count of misaligned bytes says something is wrong without saying
which seed class to change.

So both numbers are broken down by cause here. The classification is
deliberately conservative and says `unknown` when it cannot tell, because the
whole point is to stop a plausible-looking breakdown from being read as fact.
"""

from dataclasses import dataclass, field

from ..disasm.engine import DisasmEngine
from .model import RefKind

# Bytes that fill space rather than encode anything: zero padding, nop
# alignment, and the int3 padding MSVC puts between functions.
PAD_BYTES = frozenset((0x00, 0x90, 0xCC))

# Kinds that mean "something points here as data". A region referenced this way
# is not code however much it might decode like some.
_DATA_KINDS = frozenset((RefKind.MEM, RefKind.IMM, RefKind.TABLE))

# A run must decode to at least this fraction of itself to count as code, and
# must contain one of these to count at all: data rarely decodes to a clean
# run of instructions that also branches.
_CODE_COVERAGE = 0.9

UNCOVERED_PADDING = "padding"
UNCOVERED_DATA = "data"
UNCOVERED_CODE = "code"
UNCOVERED_UNKNOWN = "unknown"


@dataclass
class UncoveredBreakdown:
    """Uncovered bytes in one section, split by what they appear to be."""

    padding: int = 0
    data: int = 0
    code: int = 0
    unknown: int = 0

    @property
    def total(self):
        return self.padding + self.data + self.code + self.unknown

    def as_dict(self):
        return {"padding": self.padding, "data": self.data,
                "code": self.code, "unknown": self.unknown}

    def merge(self, other):
        self.padding += other.padding
        self.data += other.data
        self.code += other.code
        self.unknown += other.unknown
        return self


@dataclass
class CoverageAttribution:
    """Why the coverage and overlap numbers are what they are."""

    sections: dict = field(default_factory=dict)     # name -> UncoveredBreakdown
    overlap_by_origin: dict = field(default_factory=dict)
    runs: dict = field(default_factory=dict)         # name -> [(start, end, kind)]

    def uncovered(self):
        """Totals across every executable section."""
        total = UncoveredBreakdown()
        for breakdown in self.sections.values():
            total.merge(breakdown)
        return total

    def worst_unknown(self, limit=10):
        """The largest unattributed uncovered runs, biggest first.

        These are where the coverage went missing for a reason this could not
        name — the part actually worth looking at.
        """
        runs = [(name, start, end) for name, found in self.runs.items()
                for start, end, kind in found if kind == UNCOVERED_UNKNOWN]
        runs.sort(key=lambda item: item[2] - item[1], reverse=True)
        return runs[:limit]


def _data_referenced(result):
    """RVAs something points at as data rather than as a branch target."""
    targets = set()
    for target, refs in result.xrefs.items():
        for ref in refs:
            if ref.kind in _DATA_KINDS:
                targets.add(target)
                break
    return targets


def _looks_like_pointer_array(image, blob, threshold=0.5):
    """Whether the bytes read as an array of pointers into this image."""
    slot = image.slot_size
    if len(blob) < slot * 2:
        return False
    values = [int.from_bytes(blob[i:i + slot], "little")
              for i in range(0, len(blob) - slot + 1, slot)]
    if not values:
        return False
    inside = sum(1 for value in values if image.va_to_rva(value) is not None)
    return inside / len(values) >= threshold


def _decodes_as_code(result, start, end):
    """Whether the run decodes to instructions that fill it and branch.

    Both halves matter: arbitrary data can decode to *something*, so length
    alone proves nothing, and a single decodable instruction says nothing about
    the rest of the run. Requiring a branch as well is what keeps a run of
    zeros — which decodes to a long chain of `add [eax], al` — from being
    reported as code.
    """
    image = result.image
    blob = image.read_code_bytes(start, end - start)
    if not blob:
        return False

    engine = DisasmEngine(mode=image.mode)
    consumed = 0
    branched = False
    for insn in engine.disasm(image.rva_to_va(start), blob):
        consumed += insn.size
        if insn.is_call or insn.is_jmp or insn.is_ret:
            branched = True
    return branched and consumed >= (end - start) * _CODE_COVERAGE


def _classify_run(result, data_targets, start, end):
    image = result.image
    blob = image.read_code_bytes(start, end - start)
    if not blob:
        return UNCOVERED_UNKNOWN

    if all(byte in PAD_BYTES for byte in blob):
        return UNCOVERED_PADDING
    if any(target in data_targets for target in range(start, end)):
        return UNCOVERED_DATA
    if _looks_like_pointer_array(image, blob):
        return UNCOVERED_DATA
    if _decodes_as_code(result, start, end):
        return UNCOVERED_CODE
    return UNCOVERED_UNKNOWN


def _uncovered_runs(decoder, start, end, min_len=1):
    """Maximal [start, end) spans no instruction claimed."""
    runs = []
    cursor = start
    while cursor < end:
        if decoder.is_covered(cursor):
            cursor += 1
            continue
        run_start = cursor
        while cursor < end and not decoder.is_covered(cursor):
            cursor += 1
        if cursor - run_start >= min_len:
            runs.append((run_start, cursor))
    return runs


def attribute_coverage(result, min_run=4):
    """Break the coverage and overlap numbers down by cause.

    'min_run' ignores uncovered spans shorter than that: the gaps between
    instructions and the tail of a section are not a finding, and counting them
    would bury the runs that are.
    """
    decoder = result.decoder
    if decoder is None:
        raise ValueError("result has no decoder; re-run the analysis")

    data_targets = _data_referenced(result)
    attribution = CoverageAttribution()
    for section in result.image.sections:
        if not section.is_exec:
            continue
        breakdown = UncoveredBreakdown()
        runs = _uncovered_runs(decoder, section.virtual_address,
                               section.virtual_address + section.virtual_size)
        classified = []
        for start, end in runs:
            kind = (UNCOVERED_UNKNOWN if end - start < min_run
                    else _classify_run(result, data_targets, start, end))
            classified.append((start, end, kind))
            setattr(breakdown, kind, getattr(breakdown, kind) + (end - start))
        attribution.sections[section.name] = breakdown
        attribution.runs[section.name] = classified

    attribution.overlap_by_origin = decoder.overlap_by_class()
    return attribution


def deltas(first, second):
    """Bytes covered by 'second' but not by 'first', and the reverse.

    The question behind most of this: a change to the seed set moved the
    coverage number, but did it find code or just decode the same bytes from a
    different offset? Comparing the covered sets answers that; comparing the
    totals does not.
    """
    only_second = []
    only_first = []
    for section in first.image.sections:
        if not section.is_exec:
            continue
        start = section.virtual_address
        end = start + section.virtual_size
        for coordinate in range(start, end):
            a = first.decoder.is_covered(coordinate)
            b = second.decoder.is_covered(coordinate)
            if b and not a:
                only_second.append(coordinate)
            elif a and not b:
                only_first.append(coordinate)
    return only_second, only_first


def _spans(coordinates):
    """Collapse a sorted list of addresses into [start, end) spans."""
    spans = []
    for value in sorted(coordinates):
        if spans and spans[-1][1] == value:
            spans[-1][1] = value + 1
        else:
            spans.append([value, value + 1])
    return [(start, end) for start, end in spans]


def span_summary(coordinates, limit=8):
    """Human-readable spans for a set of addresses."""
    spans = _spans(coordinates)
    text = ", ".join(f"{start:#x}-{end:#x}" for start, end in spans[:limit])
    if len(spans) > limit:
        text += f", +{len(spans) - limit} more"
    return text or "(none)"
