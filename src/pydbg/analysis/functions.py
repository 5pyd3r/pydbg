"""FunctionTable — recovered function starts and their extents."""

from bisect import bisect_right

from .model import Function


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

    # ── queries ────────────────────────────────────────────────

    @property
    def sorted_starts(self):
        if self._sorted is None:
            self._sorted = sorted(self.starts)
        return self._sorted

    def containing(self, rva):
        """The function containing 'rva', or None.

        Nearest preceding start, via bisect. The prototype recorded the naive
        alternative — testing every instruction against every function — as
        unusable at real scale (670k instructions against 27k functions).
        """
        starts = self.sorted_starts
        index = bisect_right(starts, rva) - 1
        if index < 0:
            return None
        return starts[index]

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
