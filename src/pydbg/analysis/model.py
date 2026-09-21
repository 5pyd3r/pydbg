"""Value types for static analysis."""

from dataclasses import dataclass, field
from enum import IntEnum


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


# Membership test for the kind queries below. A kind value that is not in the
# enum is not silently dropped from an answer; it is not something an analysis
# produces at all, and `ref_kinds()` is a statement about producers.
_ALL_KINDS = frozenset(RefKind)

# The OWNER_KINDS members that name a function. Duplicated from
# `functions._OWNED` rather than imported: `functions` imports this module, so
# the dependency only runs one way. `tests/test_analysis_owners.py` asserts the
# two sets agree, which is what keeps a duplicated constant from drifting.
_OWNED_KINDS = frozenset(("start", "body", "gap"))


@dataclass(frozen=True, slots=True)
class Xref:
    """One reference, to a target RVA, from the place that makes it.

    'source' is an instruction RVA for every kind except DATA, where it is
    the RVA of the *slot* holding the pointer. The two are not interchangeable
    in the way that matters: a data slot is not a position in the code and has
    no instruction there, so a caller that needs a site it can disassemble has
    to filter by kind rather than assume one.
    """

    source: int
    kind: int


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
    """How much of each executable section was decoded, told honestly.

    'overlap_bytes' is bytes claimed by more than one instruction. Without it
    the covered count is the sum of instruction sizes, which reads high and is
    how a 94% figure can be reported as 99.5%: misaligned decoding inflates the
    total while looking like success.
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
    nameable: int = 0          # function starts whose symbol dbghelp can name
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
    """Everything a run produced."""

    image: object                # AnalyzedImage
    functions: object            # FunctionTable
    xrefs: dict = field(default_factory=dict)   # target_rva -> tuple[Xref, ...]
    stats: AnalysisStats = field(default_factory=AnalysisStats)
    coverage: dict = field(default_factory=dict)  # section name -> CoverageReport
    undecodable: tuple = ()      # RVAs a branch targeted that would not decode
    # Branches with no resolved target. Present so that "no callers" can be
    # told apart from "no callers we could see".
    indirect_sites: tuple = ()
    # Reasons this run's index may be missing *classes* of reference rather
    # than individual sites, as readable strings. Empty when nothing is known
    # to be missing. Present for the same reason indirect_sites is: an answer
    # of "nothing references this" is only worth as much as the list of
    # reference classes the run actually collected, and without this that list
    # lives in the source rather than in the result.
    xref_gaps: tuple = ()
    # Import thunk rva -> the IAT slot it jumps through. Names come from here.
    import_thunks: dict = field(default_factory=dict)
    # Base-relative memory accesses recorded during the sweep, as
    # (rva, reg id, offset, size, access flags, is branch). None when the run
    # was configured not to collect them. Named 'records' because
    # `accesses()` below turns them into Access objects.
    access_records: tuple = None
    # Runs of indexed slots the sweep read, as SlotTable objects ascending by
    # base. Present so that an address which is a *value in a table* can be
    # told from one which is a *position in code* — the two are otherwise
    # indistinguishable once the bytes have been decoded.
    slot_tables: tuple = ()
    # Kept so a CFG can be built after the fact without re-decoding. The
    # decoder's bookkeeping is small (bytearrays, not Instruction objects), so
    # holding it costs little and re-running the analysis would cost a lot.
    decoder: object = None

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

        Incomplete in two ways, and both are answerable. `indirect_call_sites`
        lists the branches whose target was never resolved, and `xref_gaps`
        names the classes of reference this run did not collect at all.
        """
        return tuple(sorted({xref.source for xref in self.xrefs.get(rva, ())}))

    def xrefs_of(self, rva, kind=None):
        """Xrefs targeting 'rva', optionally only those of one kind."""
        found = self.xrefs.get(rva, ())
        if kind is None:
            return tuple(found)
        want = int(kind)
        return tuple(ref for ref in found if ref.kind == want)

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
        """
        return tuple(sorted({RefKind(ref.kind)
                             for ref in self.xrefs.get(rva, ())
                             if ref.kind in _ALL_KINDS}))

    def ref_kinds(self):
        """Every RefKind this run produced anywhere, ascending.

        A kind that is declared in the enum and absent here has no producer,
        which is how an entire class of reference goes missing while every
        individual answer still looks right. Asserting this set is the shape
        of "no declared kind is unproduced" — the check that would have caught
        DATA being labelled in the reports and emitted by nothing.
        """
        return tuple(sorted({RefKind(ref.kind)
                             for refs in self.xrefs.values() for ref in refs
                             if ref.kind in _ALL_KINDS}))

    def xrefs_are_complete(self):
        """False when the index is known to be missing *classes* of reference.

        The counterpart of `call_graph_is_complete`, one level up. That one is
        about individual call sites this analysis could not resolve; this one
        is about kinds of reference the run did not collect at all. Both are
        needed, because a run can have every call site resolved and still be
        blind to every pointer in the image.
        """
        return not self.xref_gaps

    def indirect_call_sites(self):
        """Branches left unresolved that could be calling something.

        The honest footnote to `callers_of`: these are the places a call edge
        could be hidden. A target reached only through one of them appears to
        have no callers at all.
        """
        return tuple(site for site in self.indirect_sites if site.is_call)

    def call_graph_is_complete(self):
        """False when some call site has no resolved target."""
        return not self.indirect_call_sites()

    def function_of(self, rva):
        """The function owning 'rva', or None.

        Bounded, unlike `functions.containing`. An address past everything the
        analysis claimed, before its first start, or outside the image is not
        attributed to the nearest function by accident: those three are
        different findings and `owner_of` names which one it was.
        """
        owner, kind = self.functions.owner_of(rva)
        return owner if kind in _OWNED_KINDS else None

    def owner_of(self, rva):
        """(owner, kind) — see `FunctionTable.owner_of` for the kinds."""
        return self.functions.owner_of(rva)

    def container_of(self, rva):
        """(SlotTable, index) for the table covering 'rva', or None.

        Answers "which table is this byte in" for an address that lives inside
        a run of slots rather than inside a function. None means no table
        covers the address at all.

        'index' is the slot number when the address is slot-aligned and **None
        when it is not** — a byte partway into a pointer is inside the run but
        is not an entry, and rounding it to the enclosing index would report it
        as a case. The two facts are therefore kept separate rather than the
        whole answer being withheld: the byte the feature exists for is exactly
        the unaligned one. In a table embedded in .text, a pseudo-instruction
        decoded out of the table's own bytes starts mid-slot, so refusing to
        name the table for it refuses for the only caller that has one.
        """
        for table in self.slot_tables:
            if table.covers(rva):
                return (table, table.index_of(rva))
        return None

    def boundary_of(self, rva):
        """A `Boundary` describing what the decode has at 'rva'."""
        from .owners import boundary_of
        return boundary_of(self, rva)

    def classify_range(self, start, end, limit=100_000):
        """Per-kind byte counts over [start, end) — the ownership denominator."""
        from .owners import classify_range
        return classify_range(self, start, end, limit=limit)

    def receiver_of(self, rva, base_reg=None):
        """Where the base register of the access at 'rva' came from."""
        from .owners import receiver_of
        return receiver_of(self, rva, base_reg=base_reg)

    def value_set_of(self, rva, **kwargs):
        """The `ValueSet` for the fixed memory address 'rva'.

        Named the long way so it cannot be confused with `xrefs_of` or
        `callers_of`, which answer about a *position in code*. This answers
        about a memory location, which in a data section has no code at it at
        all, and a name like `values_of` would read as though it did.
        """
        from .values import value_set_of
        return value_set_of(self, rva, **kwargs)

    def narrow_value_set(self, rva, **kwargs):
        """`value_set_of` narrowed by the guards that constrain 'rva'."""
        from .values import narrow_by_guards
        return narrow_by_guards(self, rva, **kwargs)

    def references_of(self, rva):
        """Xrefs made *by* the instruction at 'rva'."""
        return tuple(xref for refs in self.xrefs.values() for xref in refs
                     if xref.source == rva)

    # ── rendering (delegated to report.py) ─────────────────────

    def render_summary(self):
        from .report import render_summary
        return render_summary(self)

    def render_functions(self, limit=None):
        from .report import render_functions
        return render_functions(self, limit=limit)

    def render_xrefs(self, target=None, limit=8):
        from .report import render_xrefs
        return render_xrefs(self, target=target, limit=limit)

    def render_coverage(self):
        from .report import render_coverage
        return render_coverage(self)

    def render_stats(self):
        from .report import render_stats
        return render_stats(self)

    def render_listing(self, rva, size, workspace=None):
        from .report import render_listing
        table = self.names(workspace) if workspace is not None else None
        comments = workspace.comments if workspace is not None else None
        return render_listing(self.image, rva, size, names=table,
                              comments=comments)

    def render_indirect_sites(self, limit=40, calls_only=True):
        from .report import render_indirect_sites
        return render_indirect_sites(self, limit=limit, calls_only=calls_only)

    def render_xref_gaps(self):
        from .report import render_xref_gaps
        return render_xref_gaps(self)

    # ── names ──────────────────────────────────────────────────

    def names(self, workspace=None):
        """Recovered names, with any a person supplied on top.

        Built on request: it walks the exports and every function start, which
        is real work for an image with thousands of them, and a caller
        interested only in coverage should not pay for it.
        """
        from .names import resolve
        supplied = None
        if workspace is not None:
            supplied = {rva: name for rva, name in workspace.names.items()}
        return resolve(self, supplied)

    def label(self, rva, workspace=None):
        """A stable name for 'rva', inventing one when nothing named it."""
        return self.names(workspace).label(rva)

    def render_names(self, workspace=None, limit=None, source=None):
        from .report import render_names
        return render_names(self, workspace=workspace, limit=limit,
                            source=source)

    def accesses(self, **kwargs):
        """Every `[reg + disp]` access in the decoded code."""
        from .access import collect_accesses
        return collect_accesses(self, **kwargs)

    def structures(self, min_offsets=None, accesses=None):
        """(function, base register) -> StructureProfile, plausible ones only.

        Keyed by register, not by class: which register holds an object is not
        statically determinable, so the honest unit is "inside this function,
        this register is used as a base at these offsets".
        """
        from .access import profiles
        return profiles(self, accesses=accesses, min_offsets=min_offsets)

    def render_structures(self, workspace=None, limit=None, function=None,
                          min_offsets=None):
        from .report import render_structures
        return render_structures(self, workspace=workspace, limit=limit,
                                 function=function, min_offsets=min_offsets)

    def attribution(self, min_run=4):
        """Break the coverage and overlap numbers down by cause.

        Computed on request rather than during the run: it re-decodes the
        uncovered regions to classify them, and most callers only want the
        totals.
        """
        from .attribution import attribute_coverage
        return attribute_coverage(self, min_run=min_run)

    def render_attribution(self, limit=10):
        from .report import render_attribution
        return render_attribution(self.attribution(), limit=limit)

    def scan(self, start, end, **kwargs):
        """Decode [start, end) linearly, reporting the gaps it had to cross.

        The answer to "what is in this range" for a caller who cannot assume
        the range decodes cleanly. The sweep that produced this result follows
        seeds and stops at whatever it cannot reach, so it is not a substitute:
        its silence about a region means the region was never reached, not that
        it was decoded and found empty.
        """
        from .scan import linear_scan
        return linear_scan(self.decoder, start, end, **kwargs)

    def scan_section(self, name, **kwargs):
        """`scan` over one section, by name."""
        from .scan import scan_section
        return scan_section(self.image, self.decoder, name, **kwargs)

    def scan_text(self, **kwargs):
        """`scan` over every executable section."""
        from .scan import scan_executable
        return scan_executable(self.image, self.decoder, **kwargs)

    def cfg_of(self, rva, max_blocks=4096):
        """The CFG of the function containing 'rva', or None if there is none."""
        from .cfg import build_function_cfg

        entry = self.functions.containing(rva)
        if entry is None:
            return None
        return build_function_cfg(self.decoder, self.image, self.functions,
                                  entry, max_blocks=max_blocks)
