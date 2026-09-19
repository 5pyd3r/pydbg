"""Value types for static analysis."""

from dataclasses import dataclass, field
from enum import IntEnum


class RefKind(IntEnum):
    """How one address refers to another.

    Kept distinct rather than folded into one "reference" bucket because they
    carry very different weight: a BRANCH is exact, a DATA pointer is a guess,
    and a caller deciding whether to trust a function's extent needs to know
    which it is looking at.
    """

    BRANCH = 1   # a jump or call target
    IMM = 2      # an immediate that lands in code but is not a branch
    MEM = 3      # an absolute memory operand
    TABLE = 4    # a switch-table base (indexed memory with a table displacement)
    DATA = 5     # a pointer recovered from the data sections


@dataclass(frozen=True, slots=True)
class Xref:
    """One reference, from an instruction to a target RVA."""

    source: int
    kind: int


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

    def as_dict(self):
        return dict(self.__dict__)


@dataclass(frozen=True)
class SeedConfig:
    """Tunables for a run."""

    max_instructions: int = 2_000_000
    collect_xrefs: bool = True
    decode_cache_size: int = 4096
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
    # Kept so a CFG can be built after the fact without re-decoding. The
    # decoder's bookkeeping is small (bytearrays, not Instruction objects), so
    # holding it costs little and re-running the analysis would cost a lot.
    decoder: object = None

    def callers_of(self, rva):
        """RVAs of the instructions that reference 'rva', ascending.

        May be incomplete: a branch through a register or memory is not an edge
        unless constant propagation resolved it. Callers that need to know
        whether the answer is exhaustive should check `indirect_call_sites()`,
        which lists the branches that were left unknown.
        """
        return tuple(sorted({xref.source for xref in self.xrefs.get(rva, ())}))

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
        """The function containing 'rva', or None."""
        return self.functions.containing(rva)

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

    def render_listing(self, rva, size):
        from .report import render_listing
        return render_listing(self.image, rva, size)

    def render_indirect_sites(self, limit=40, calls_only=True):
        from .report import render_indirect_sites
        return render_indirect_sites(self, limit=limit, calls_only=calls_only)

    def cfg_of(self, rva, max_blocks=4096):
        """The CFG of the function containing 'rva', or None if there is none."""
        from .cfg import build_function_cfg

        entry = self.functions.containing(rva)
        if entry is None:
            return None
        return build_function_cfg(self.decoder, self.image, self.functions,
                                  entry, max_blocks=max_blocks)
