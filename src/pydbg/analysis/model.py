"""Value types for static analysis.

This is the leaf of the package: it imports nothing from a sibling module, at
module level or inside a function. A result record has no business asking the
decoder, the function table or a renderer anything — those answers are free
functions in the module that owns them, taking the result as an argument. The
one exception is the four per-address lookups on `AnalysisResult`, which read
its own reference index and nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:               # annotations only; this must stay a leaf
    from .decoder import InstructionDecoder
    from .functions import FunctionTable
    from .image import AnalyzedImage


class RefKind(IntEnum):
    """How one address refers to another.

    Kept distinct rather than folded into one "reference" bucket because they
    carry very different weight: a BRANCH is exact, a DATA pointer is a guess,
    and a caller deciding whether to trust a function's extent needs to know
    which it is looking at.

    The kinds also differ in what their target *is*, which is easy to get
    wrong when grouping them. For MEM, IMM and TABLE the target is a location
    being read or indexed — data. For DATA it is the value stored in the slot
    — a code address. A pointer read out of a vtable names code, which is why
    DATA is not one of the kinds that mark a region as data.

    DATA is also the one kind that is a claim about the *bytes* rather than
    about the code: the slot holds this address, and nothing here says anything
    uses it. The scan that produces it is bounded (see
    SeedProvider._data_pointers), so absence of a DATA reference means "no slot
    that scan reads holds this address", not "the image never mentions it" —
    `xref_gaps` says which classes ran, and the scan's own limits are written
    where it is.
    """

    BRANCH = 1   # a jump or call target
    IMM = 2      # an immediate that lands in code but is not a branch
    MEM = 3      # an absolute memory operand
    TABLE = 4    # a switch-table base (indexed memory with a table displacement)
    DATA = 5     # a pointer-valued slot the image holds, outside an operand


# What a walked address belongs to. Defined in this module — the lowest layer
# of the analysis package — because functions.py, owners.py and model.py all
# speak it. `OWNED_KINDS` is the public subset that names a function; keeping
# both here is what stops the two from being copied into the modules that use
# them and kept aligned by a test.
OWNER_KINDS = ("start", "body", "gap", "after", "before", "unmapped")

# The OWNER_KINDS members that name a function.
OWNED_KINDS = frozenset(("start", "body", "gap"))


@dataclass(frozen=True, slots=True)
class Xref:
    """One reference, to a target RVA, from the place that makes it.

    'source' is an instruction RVA for every kind except DATA, where it is
    the RVA of the *slot* holding the pointer. The two are not interchangeable
    in the way that matters: a data slot is not a position in the code and has
    no instruction there, so a caller that needs a site it can disassemble has
    to filter by kind rather than assume one.

    'kind' is a `RefKind`, not a bare int. Construction accepts the int form
    and raises ValueError for a value outside the enum: an unknown kind used
    to be filtered out of `ref_kinds_of` without a word, so a producer bug
    looked exactly like an address nothing references.
    """

    source: int
    kind: RefKind

    def __post_init__(self):
        object.__setattr__(self, "kind", RefKind(self.kind))


# Kinds of slot run. `jump_table` is the only one with a producer today;
# `pointer_run` — a contiguous run of code pointers that no instruction indexes
# — is declared so that the two are never merged by shape, and
# `test_analysis_owners` asserts it is still unproduced rather than leaving a
# declared kind to be mistaken for a broken one.
SLOT_TABLE_KINDS = ("jump_table", "pointer_run")


@dataclass(frozen=True, slots=True)
class SlotTable:
    """A run of pointer-sized slots that code indexes into.

    Four integers and the evidence, which is the whole object. What was
    missing before was not a mapping — `data_refs_of` already answers "which
    slots point at this address" — but the table's *identity*: where the run
    begins, how long it is, and which instruction named it. Without that, a
    byte inside a jump table embedded in ``.text`` is indistinguishable from a
    byte inside a function, and a caller has to re-derive the run by hand.

    'kind' is deliberately an open string rather than an enum with one member
    used and the rest aspirational. ``jump_table`` is the only kind currently
    produced; ``pointer_run`` is reserved for a contiguous run of pointers that
    is not indexed by an instruction (a vtable in ``.rdata``), and naming the
    distinction here is what stops a later reader from treating one as the
    other — the two are the same shape of bytes and different claims.

    'truncated' is set when the reader stopped at its entry budget rather than
    at the end of the run. A truncated table must not be rendered as a table
    size: 512 entries and "at least 512 entries" are different statements, and
    silently reporting the first for the second is the same class of defect
    that makes a coverage figure look complete.
    """

    base: int
    count: int
    stride: int
    kind: str = "jump_table"
    referrer: int | None = None      # the instruction whose operand named it
    truncated: bool = False

    def span(self):
        """(start, end) of the slot run, as RVAs."""
        return (self.base, self.base + self.count * self.stride)

    def covers(self, rva):
        return self.base <= rva < self.span()[1]

    def index_of(self, rva):
        """Slot index for 'rva', or None when it is not slot-aligned.

        An address partway into a slot is not an entry, and returning the
        enclosing index would let a byte in the middle of a pointer be
        reported as "the third case of this switch".
        """
        if not self.covers(rva):
            return None
        offset = rva - self.base
        if offset % self.stride:
            return None
        return offset // self.stride


@dataclass(frozen=True)
class Function:
    """A recovered function."""

    rva: int
    size: int
    confident: bool   # backed by call/export/TLS/thunk evidence, not just a pointer


@dataclass
class CoverageReport:
    """How much of one section was decoded, told honestly.

    'overlap_bytes' is overlap *within this section*: bytes claimed by more
    than one instruction. Without it the covered count is the sum of
    instruction sizes, which reads high and is how a 94% figure can be reported
    as 99.5%: misaligned decoding inflates the total while looking like
    success.

    The per-section numbers add up to AnalysisStats.overlap_bytes. They used to
    all carry that global total, so summing the sections multiplied it by the
    number of executable sections. A non-executable section appears here only
    when the decoder claimed bytes in it — a scan can mark any section, and an
    overlap that landed in one would otherwise be missing from the sum.
    """

    covered: int = 0
    total: int = 0
    overlap_bytes: int = 0

    @property
    def ratio(self):
        return (self.covered / self.total) if self.total else 0.0


@dataclass(frozen=True, slots=True)
class IndirectSite:
    """A branch whose target the analysis could not resolve.

    Recorded so the incompleteness is visible rather than implied. A call graph
    with no entry for a function and no record of why is indistinguishable from
    one that simply has no callers — and one target's entry point really was
    reached only through `call [esi+0x18]`, so it appeared nowhere.
    """

    rva: int
    is_call: bool
    text: str            # the operand as written, for the report


@dataclass
class AnalysisStats:
    """Counters, named after the prototype's so runs can be compared."""

    insns: int = 0
    func_starts: int = 0
    func_starts_confident: int = 0
    xref_targets: int = 0
    xrefs: int = 0
    # References of kind DATA, counted from the frozen index rather than from
    # what was recorded: two pointer classes can read the same slot, and the
    # number that matters is how many entries the index ends up carrying.
    data_refs: int = 0
    sweep_rounds: int = 0
    overlap_bytes: int = 0
    overlap_conflicts: int = 0
    entry_point: int = 0
    seed_functions: int = 0
    # Indirect branches split by outcome. The pair matters more than either
    # number: "resolved 400" reads as progress while 12,000 sites stay unknown,
    # and without the second figure there is no way to tell.
    indirect_resolved: int = 0
    indirect_unknown: int = 0
    # True when the whole-run instruction ceiling stopped the traversal.
    # Silent truncation would read as a complete analysis.
    budget_exhausted: bool = False
    # Tentative starts demoted for falling inside a function with evidence.
    pruned_starts: int = 0

    def as_dict(self):
        return dict(self.__dict__)


@dataclass(frozen=True)
class SeedConfig:
    """Tunables for a run."""

    max_instructions: int = 2_000_000
    collect_xrefs: bool = True
    decode_cache_size: int = 4096
    # Recording base-relative accesses costs a tuple per memory operand and
    # saves decoding the whole image a second time to recover them. For a
    # system DLL that is tens of thousands of tuples against half a minute.
    collect_accesses: bool = True
    # Which seed classes to run; None means all of them. Naming a subset is
    # how one class's contribution gets measured without editing code.
    seed_classes: tuple = None
    # A ceiling on instructions decoded across the *whole* run, as opposed
    # to max_instructions, which bounds one sweep. Without it a pathological
    # image can be swept an unbounded number of times.
    max_total_instructions: int = 20_000_000
    # What to do when a branch targets a byte that does not decode. Recording
    # them is cheap and they are the signal that a seed was wrong; silently
    # dropping them hides exactly that.
    track_undecodable: bool = True


@dataclass
class AnalysisResult:
    """Everything a run produced.

    A record plus the four lookups over its own reference index. Every other
    question — ownership, names, accesses, a CFG, a text report — is a free
    function in the module that owns the answer, taking this result as an
    argument: `owners.function_of(result, rva)`, `scan.linear_scan(
    result.decoder, ...)`, `report.render_summary(result)`. Putting those on
    the record is what made model.py import eight sibling modules through
    method bodies while pretending to be the bottom layer.
    """

    image: AnalyzedImage
    functions: FunctionTable
    xrefs: dict[int, tuple[Xref, ...]] = field(default_factory=dict)
    stats: AnalysisStats = field(default_factory=AnalysisStats)
    coverage: dict[str, CoverageReport] = field(default_factory=dict)
    # RVAs a branch targeted that would not decode.
    undecodable: tuple[int, ...] = ()
    # Branches with no resolved target. Present so that "no callers" can be
    # told apart from "no callers we could see".
    indirect_sites: tuple[IndirectSite, ...] = ()
    # Reasons this run's index may be missing *classes* of reference rather
    # than individual sites, as readable strings. Empty when nothing is known
    # to be missing. Present for the same reason indirect_sites is: an answer
    # of "nothing references this" is only worth as much as the list of
    # reference classes the run actually collected, and without this that list
    # lives in the source rather than in the result.
    xref_gaps: tuple[str, ...] = ()
    # Warnings about the analysis itself, as readable strings — "pdb: no
    # symbols" when a PDB handle was supplied but enumerated nothing, which is
    # not proof that it was read (spec §10.2(6)). Empty when nothing is known
    # to be wrong.
    warnings: tuple[str, ...] = ()
    # Import thunk rva -> the IAT slot it jumps through. Names come from here.
    import_thunks: dict[int, int] = field(default_factory=dict)
    # Base-relative memory accesses recorded during the sweep, as
    # (rva, reg id, offset, size, access flags, is branch). None when the run
    # was configured not to collect them. `access.collect_accesses` turns them
    # into Access objects.
    access_records: tuple[tuple, ...] | None = None
    # Runs of indexed slots the sweep read, as SlotTable objects ascending by
    # base. Present so that an address which is a *value in a table* can be
    # told from one which is a *position in code* — the two are otherwise
    # indistinguishable once the bytes have been decoded.
    slot_tables: tuple[SlotTable, ...] = ()
    # Kept so a CFG can be built after the fact without re-decoding. The
    # decoder's bookkeeping is small (bytearrays, not Instruction objects), so
    # holding it costs little and re-running the analysis would cost a lot.
    decoder: InstructionDecoder | None = None

    def callers_of(self, rva):
        """RVAs of everything that references 'rva', ascending.

        Not only instructions. A pointer the image holds in a data slot is a
        reference in exactly the sense an operand is, and it is recorded with
        kind DATA and the slot as its source — `data_refs_of` returns just
        those. Leaving them out is what makes "nobody references this" the
        systematically wrong answer for the vtables and callback tables that a
        binary reaching its code through pointers is built out of: on one
        32-bit Delphi target it turned 11,310 addresses that had no reference
        of any kind into referenced ones.

        Incomplete in two ways, and both are answerable. `refs.indirect_call_sites`
        lists the branches whose target was never resolved, and `xref_gaps`
        names the classes of reference this run did not collect at all.
        """
        return tuple(sorted({xref.source for xref in self.xrefs.get(rva, ())}))

    def xrefs_of(self, rva, kind=None):
        """Xrefs targeting 'rva', optionally only those of one kind.

        A kind outside `RefKind` raises rather than returning an empty tuple:
        "no references of that kind" is an answer, and it must not be the
        automatic result of a caller passing a kind nothing can produce.
        """
        found = self.xrefs.get(rva, ())
        if kind is None:
            return tuple(found)
        want = RefKind(kind)
        return tuple(ref for ref in found if ref.kind is want)

    def data_refs_of(self, rva):
        """RVAs of the data slots holding a pointer to 'rva', ascending.

        The subset of `callers_of` whose sources are slots rather than
        instructions, which is the difference between "some code names this"
        and "some table somewhere names this" — a vtable entry says the second
        and not the first.
        """
        return tuple(sorted({ref.source
                             for ref in self.xrefs_of(rva, RefKind.DATA)}))

    def ref_kinds_of(self, rva):
        """The kinds of reference that target 'rva', ascending.

        The assertion surface for a negative claim. "Nothing references this"
        is a different statement depending on what was being looked for, and
        this is the cheapest way to write down which kinds were: a check that
        a DATA reference exists fails loudly when the data-pointer reader is
        not running, where `callers_of` returning () would not.

        Nothing is filtered here. `Xref` already refuses a kind outside the
        enum, so an answer cannot be narrowed by a producer that invented one.
        """
        return tuple(sorted({ref.kind for ref in self.xrefs.get(rva, ())}))
