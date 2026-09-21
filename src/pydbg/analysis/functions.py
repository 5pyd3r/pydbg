"""FunctionTable — recovered function starts and their extents."""

from bisect import bisect_right

from .model import Function

# What an address can turn out to be owned by. Every member has a producer in
# `owner_of`, and the three that mean "nothing owns this" are kept apart
# because they are three different findings: an address before the first start,
# one past everything the analysis claimed, and one the image does not map at
# all. Folding them into a bare None is how "past the last function" came to be
# answered with the last function's start.
OWNER_KINDS = ("start", "body", "gap", "after", "before", "unmapped")

_OWNED = frozenset(("start", "body", "gap"))


class FunctionTable:
    """Function starts, two-tier by confidence, plus their extents.

    'starts' is everything believed to begin a function; 'confident' is the
    subset backed by real evidence (a call target, an export, a TLS callback, a
    thunk). The gap between them is the honest answer to "how much of this do
    you actually know", and collapsing it into one set would hide it.
    """

    def __init__(self, image=None):
        self.image = image
        self.starts = set()
        self.confident = set()
        # Addresses worth decoding that are not function entries: switch-table
        # case bodies, for instance. Recording them as starts corrupts every
        # extent that spans them.
        self.code_seeds = set()
        self.call_targets = set()
        self._sorted = None
        self._extents = None
        self._claimed = {}     # rva -> decoded instruction size

    def add_start(self, rva, confident=False):
        """Register a function entry. True if it was not already known."""
        if rva is None:
            return False
        fresh = rva not in self.starts
        self.starts.add(rva)
        if confident:
            self.confident.add(rva)
        return fresh

    def add_code_seed(self, rva):
        if rva is None:
            return False
        fresh = rva not in self.code_seeds
        self.code_seeds.add(rva)
        return fresh

    def add_call_target(self, rva):
        if rva is None:
            return False
        fresh = rva not in self.call_targets
        self.call_targets.add(rva)
        return fresh

    def invalidate(self):
        self._sorted = None
        self._extents = None

    def prune_starts_inside_functions(self):
        """Demote tentative starts that fall inside a trusted function.

        This is the error surface `looks_like_entry` cannot close by itself.
        That filter reads the byte before an address, and for a pointer that
        lands in the middle of a function it is often padding by coincidence —
        an alignment gap the linker left between two real functions the pointer
        happens to point past.

        A start inside a function the analysis already has *evidence* for is
        not a second function, whatever precedes it. The address stays decoded
        (it is moved to code seeds), because something did point at it; what it
        loses is the claim to be a function entry.

        Returns the number demoted.
        """
        from bisect import bisect_right

        trusted = sorted(self.confident)
        if not trusted:
            return 0

        # Where each trusted function ends: the next trusted start, or the
        # furthest byte its own instructions claim, whichever comes first.
        claimed = {}
        for rva, size in self._claimed.items():
            owner_index = bisect_right(trusted, rva) - 1
            if owner_index < 0:
                continue
            owner = trusted[owner_index]
            claimed[owner] = max(claimed.get(owner, 0), rva + size)

        demoted = 0
        for rva in sorted(self.starts):
            if rva in self.confident:
                continue
            index = bisect_right(trusted, rva) - 1
            if index < 0:
                continue
            owner = trusted[index]
            next_start = (trusted[index + 1] if index + 1 < len(trusted)
                          else None)
            end = claimed.get(owner, owner)
            if next_start is not None:
                end = min(end, next_start)
            if rva < end:
                self.starts.discard(rva)
                self.code_seeds.add(rva)
                demoted += 1

        if demoted:
            self.invalidate()
        return demoted

    # ── queries ────────────────────────────────────────────────

    @property
    def sorted_starts(self):
        if self._sorted is None:
            self._sorted = sorted(self.starts)
        return self._sorted

    def containing(self, rva):
        """The nearest preceding start at or before 'rva', or None.

        **Unbounded on purpose.** This answers "which function's span did I walk
        into", which is what rendering a listing wants, and it is the documented
        performance query: the naive alternative — testing every instruction
        against every function — was unusable at real scale (670k instructions
        against 27k functions).

        It is therefore *not* an ownership answer. Past the last function it
        returns that function's start no matter how far past, and it has no
        opinion about whether anything decodes there. `owner_of` is the bounded
        query; the two are kept apart rather than merged because fixing the
        semantics here would change every listing, and the callers that want
        "nearest preceding" (`access.py`, the CLI, `report.py`) genuinely want
        that.
        """
        starts = self.sorted_starts
        index = bisect_right(starts, rva) - 1
        if index < 0:
            return None
        return starts[index]

    def owner_of(self, rva):
        """(owner, kind) for the function 'rva' belongs to, bounded.

        `kind` is one of OWNER_KINDS:

        - ``start`` / ``body`` / ``gap`` — a function owns it, and ``owner`` is
          that function's RVA. ``body`` means a decoded instruction claims
          these bytes. ``gap`` means the address is inside a function's span
          but nothing decodes there — which is the shape a jump table embedded
          in ``.text`` leaves behind, and answering ``body`` for it is how a
          byte that was decoded as part of an *operand* gets reported as
          function interior.
        - ``after`` / ``before`` / ``unmapped`` — nothing owns it, ``owner`` is
          None. ``after`` is the case `containing` gets wrong: an address past
          everything the analysis claimed.

        The upper bound is the function's extent — the furthest byte its own
        instructions claim, itself bounded by the next start (see `extents`).
        An unmapped address is answered from the image rather than from the
        start list, so "the image has nothing here" is not confused with "the
        analysis has not reached here yet".
        """
        if rva is None or rva < 0:
            return (None, "unmapped")
        image = self.image
        if image is not None and not image.is_mapped(rva):
            return (None, "unmapped")

        starts = self.sorted_starts
        index = bisect_right(starts, rva) - 1
        if index < 0:
            return (None, "before")

        start = starts[index]
        if rva == start:
            return (start, "start")

        end = start + self.extents().get(start, 0)
        if rva < end:
            return (start, "body")
        if index + 1 < len(starts):
            return (start, "gap")
        return (None, "after")

    def is_owned(self, rva):
        """Whether a function owns 'rva', without saying which or how."""
        return self.owner_of(rva)[1] in _OWNED

    def extent_of(self, rva):
        """Size of the function starting at 'rva', or 0 if unknown."""
        return self.extents().get(rva, 0)

    def extents(self):
        """RVA -> size for every start, in one pass.

        A function runs to the furthest byte its instructions claim, bounded by
        the next start. Computing it once and caching matters: this is queried
        per instruction when rendering, and the naive per-call form is the
        documented performance trap.
        """
        if self._extents is not None:
            return self._extents

        starts = self.sorted_starts
        ends = {}
        for rva, size in self._claimed.items():
            owner = self.containing(rva)
            if owner is None:
                continue
            ends[owner] = max(ends.get(owner, 0), rva + size)

        extents = {}
        for index, start in enumerate(starts):
            limit = starts[index + 1] if index + 1 < len(starts) else None
            end = ends.get(start, start)
            if limit is not None:
                end = min(end, limit)
            extents[start] = max(end - start, 0)
        self._extents = extents
        return extents

    def functions(self):
        """All functions as Function objects, ascending by RVA."""
        extents = self.extents()
        return [Function(rva=rva, size=extents.get(rva, 0),
                         confident=rva in self.confident)
                for rva in self.sorted_starts]

    # ── extent bookkeeping ─────────────────────────────────────

    def note_instruction(self, rva, size):
        """Record that the instruction at 'rva' claims 'size' bytes."""
        self._claimed[rva] = size

    def __len__(self):
        return len(self.starts)

    def __contains__(self, rva):
        return rva in self.starts
