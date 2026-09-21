"""Value sets for a fixed memory address, with the degenerate answers split.

The gap this closes is not "pydbg cannot do value analysis". It is that the
value analysis people wrote by hand was wrong twice, and **wrong invisibly**:
one version read capstone's operand-kind constant for an immediate, which
produced a plausible wrong set; the other collapsed two epilogue paths into
`UNBOUNDED`, which is indistinguishable from "I did not find out". Both
printed numbers, and the numbers looked like answers.

So what is here is not a more correct analysis — it is a lattice whose
degenerate elements are auditable. Every answer names its writers, and the
answers that carry no information are separate forms that cannot compare equal:

    NONE            no writer was seen at all
    SET             exactly these values; every writer was modelled
    RANGE           a contiguous interval; every writer was modelled
    UNBOUNDED       every writer was modelled, and they admit any value
    UNMODELED       a reaching writer was NOT modelled (its RVA is named)
    UNREPRESENTABLE every writer WAS modelled, and the union still has no
                    single representation here

`UNREPRESENTABLE` is not a fifth form for symmetry. A `SET` joined with a
disjoint `RANGE` is a third thing: every writer was modelled and the result
still is not one interval. Folding it into `UNMODELED` would be the "three
causes in one state" this project forbids; folding it into `UNBOUNDED` is the
second defect verbatim.

`ConstantTracker` is deliberately NOT reused, and the reason is this module's
whole subject. It forgets everything on any instruction it does not recognise,
which is sound *for its own job* — a forgotten constant becomes an
`IndirectSite`, which is recorded and countable. Turned into an answer, the
same trick publishes "no values recorded" as the value set. That is the
defect, not a smaller version of it.
"""

from dataclasses import dataclass
from enum import IntEnum

from ..disasm.engine import ACC_WRITE, OP_IMM, OP_MEM, OP_REG
from .refs import memory_address

# Instructions that put a source operand into the destination. Matched on the
# mnemonic rather than on an operand-kind constant because that constant is
# exactly what the first hand-written version got wrong: it hard-coded
# capstone's OP_IMM value, so every immediate was read as some other kind and
# the resulting set printed normally while being wrong.
_MOV_LIKE = frozenset(("mov", "movabs"))


class Bound(IntEnum):
    """Which form a value set takes, decided or not."""

    NONE = 0
    SET = 1
    RANGE = 2
    UNBOUNDED = 3
    UNMODELED = 4
    UNREPRESENTABLE = 5


# The forms that support a claim. Everything else is a refusal, and which
# refusal it is is what a caller has to be able to see.
DECIDED = frozenset((Bound.NONE, Bound.SET, Bound.RANGE))
UNDECIDED = frozenset((Bound.UNBOUNDED, Bound.UNMODELED, Bound.UNREPRESENTABLE))

# Stated as an equality rather than left implicit, so that adding a member to
# Bound forces a decision here instead of silently inheriting a branch.
assert DECIDED | UNDECIDED == frozenset(Bound)
assert not (DECIDED & UNDECIDED)


@dataclass(frozen=True, slots=True)
class ValueSet:
    """What a fixed address can hold, and the evidence for saying so.

    `writers` and `unmodeled` are both kept even when one decides the answer: a
    `UNMODELED` result that dropped the writers it *did* model would lose the
    one value that was found, which is the "the number and the claim disagree"
    defect in miniature.
    """

    kind: Bound = Bound.NONE
    values: frozenset = frozenset()          # SET
    lo: int | None = None                    # RANGE
    hi: int | None = None
    writers: tuple = ()                      # (rva, description) modelled
    unmodeled: tuple = ()                    # (rva, reason) not modelled
    parts: tuple = ()                        # UNREPRESENTABLE: what was joined
    # Decoded writes whose address this analysis could not resolve, plus
    # unresolved call targets. Each *could* write this address and none is
    # enumerated above, because enumerating them means "every base-relative
    # store in the image" — a statement about the image, not about this
    # address. Carried as a count so the scope of the answer is visible rather
    # than implied by silence.
    unresolved_writes: int = 0

    # ── construction ───────────────────────────────────────────

    @classmethod
    def of_value(cls, value, rva):
        return cls(kind=Bound.SET, values=frozenset((value,)),
                   writers=((rva, f"immediate 0x{value:X}"),))

    @classmethod
    def of_range(cls, lo, hi, writers=()):
        if lo is None or hi is None or hi < lo:
            raise ValueError(f"not a range: [{lo}, {hi}]")
        return cls(kind=Bound.RANGE, lo=lo, hi=hi, writers=tuple(writers))

    @classmethod
    def unbounded(cls, reason, writers=()):
        """The only way to get `UNBOUNDED`.

        It requires writers and a reason, so that "truly unbounded" cannot be
        reached by a code path that merely gave up — which is how the second
        hand-written version came to report it for a set it had not worked out.
        """
        if not writers:
            raise ValueError(
                "UNBOUNDED must name the writers that establish it; without "
                "them it is indistinguishable from 'not found out'")
        if not reason:
            raise ValueError("UNBOUNDED must carry a reason")
        return cls(kind=Bound.UNBOUNDED, writers=tuple(writers))

    @classmethod
    def of_unmodeled(cls, entries, writers=()):
        if not entries:
            raise ValueError("UNMODELED must name at least one writer")
        return cls(kind=Bound.UNMODELED, writers=tuple(writers),
                   unmodeled=tuple(entries))

    @classmethod
    def unrepresentable(cls, parts, writers=()):
        if len(parts) < 2:
            raise ValueError("a union of one thing is not unrepresentable")
        return cls(kind=Bound.UNREPRESENTABLE, parts=tuple(parts),
                   writers=tuple(writers))

    # ── queries ────────────────────────────────────────────────

    def is_decided(self):
        """Whether this supports a claim of the form "the values are ..."."""
        return self.kind in DECIDED

    def contains(self, value):
        """Whether 'value' is in the set. Raises unless `is_decided()`.

        Deliberately not total. Returning False when undecided reads as "this
        value is not possible" — a stronger claim than the evidence supports —
        and `if vs.contains(0)` would take the same branch it takes for a
        decided exclusion. Returning None instead is worse: None is falsy.
        """
        if not self.is_decided():
            raise ValueError(
                f"{self.kind.name} does not support contains(); use "
                f"may_contain() for 'could be', or is_decided() first")
        if self.kind is Bound.NONE:
            return False
        if self.kind is Bound.SET:
            return value in self.values
        return self.lo <= value <= self.hi

    def may_contain(self, value):
        """Whether 'value' might be in the set. Total; never raises.

        The question to ask when the point is what *could* happen. True for
        every undecided form: "I do not know" and "it is possible" are the same
        answer here, which is why this must not be used to support a claim that
        something is impossible.
        """
        if not self.is_decided():
            return True
        return self.contains(value)

    def writers_total(self):
        """Modelled writers plus unmodelled ones — the denominator."""
        return len(self.writers) + len(self.unmodeled)

    def writers_modeled(self):
        return len(self.writers)

    def render(self):
        if self.kind is Bound.NONE:
            body = "no writer found"
        elif self.kind is Bound.SET:
            shown = ", ".join(f"0x{v:X}" for v in sorted(self.values))
            body = f"exactly {{{shown}}}"
        elif self.kind is Bound.RANGE:
            body = f"in [0x{self.lo:X}, 0x{self.hi:X}]"
        elif self.kind is Bound.UNBOUNDED:
            body = "any value, and every writer was modelled"
        elif self.kind is Bound.UNMODELED:
            body = f"{len(self.unmodeled)} writer(s) not modelled"
        else:
            body = f"no single form for {len(self.parts)} modelled part(s)"

        lines = [f"{self.kind.name}: {body}"]
        for rva, description in self.writers:
            lines.append(f"  modelled 0x{rva:X}: {description}")
        for rva, reason in self.unmodeled:
            lines.append(f"  UNMODELLED 0x{rva:X}: {reason}")
        for part in self.parts:
            shown = part.render().splitlines()[0]
            lines.append(f"  part: {shown}")
        if self.unresolved_writes:
            lines.append(
                f"  scope: {self.unresolved_writes} further write(s) in this "
                f"image have no resolvable address and are not represented "
                f"above")
        return "\n".join(lines)

    # ── lattice ────────────────────────────────────────────────

    def widen(self, other):
        """Join two value sets for the same address, from different writers."""
        if other.kind is Bound.NONE:
            return self
        if self.kind is Bound.NONE:
            return other

        writers = self.writers + other.writers
        unmodeled = self.unmodeled + other.unmodeled
        unresolved = self.unresolved_writes + other.unresolved_writes
        parts = self.parts + other.parts

        # Unmodelled writers dominate and they *accumulate* rather than being
        # replaced. Losing either list is how a union of "I know 1" with "I do
        # not know" came to be reported as unbounded: the second hand-written
        # version merged two epilogue paths and dropped the fact that one of
        # them was never modelled at all.
        if Bound.UNMODELED in (self.kind, other.kind):
            return ValueSet(kind=Bound.UNMODELED, writers=writers,
                            unmodeled=unmodeled, parts=parts,
                            unresolved_writes=unresolved)
        if Bound.UNBOUNDED in (self.kind, other.kind):
            return ValueSet(kind=Bound.UNBOUNDED, writers=writers,
                            parts=parts, unresolved_writes=unresolved)
        if Bound.UNREPRESENTABLE in (self.kind, other.kind):
            separate = tuple(p for p in (self, other)
                             if p.kind is not Bound.UNREPRESENTABLE)
            return ValueSet(kind=Bound.UNREPRESENTABLE, writers=writers,
                            parts=parts + separate,
                            unresolved_writes=unresolved)

        if self.kind is Bound.SET and other.kind is Bound.SET:
            return ValueSet(kind=Bound.SET, values=self.values | other.values,
                            writers=writers, unresolved_writes=unresolved)

        if self.kind is Bound.RANGE and other.kind is Bound.RANGE:
            return ValueSet(kind=Bound.RANGE, lo=min(self.lo, other.lo),
                            hi=max(self.hi, other.hi), writers=writers,
                            unresolved_writes=unresolved)

        # One SET and one RANGE. Representable as one interval only when every
        # value falls inside it; disjoint, and the union genuinely is not one of
        # these forms — a fact about the union, not a gap in the analysis.
        values, interval = ((self, other) if self.kind is Bound.SET
                            else (other, self))
        if all(interval.lo <= v <= interval.hi for v in values.values):
            return ValueSet(kind=Bound.RANGE, lo=interval.lo, hi=interval.hi,
                            writers=writers, unresolved_writes=unresolved)
        return ValueSet(kind=Bound.UNREPRESENTABLE, writers=writers,
                        parts=(values, interval),
                        unresolved_writes=unresolved)


EMPTY = ValueSet()


def writes_to(result, address, include_unresolved_calls=True):
    """(writer_rva, ValueSet) for each decoded write to 'address'.

    A scan of the decode rather than an extension of the sweep's access
    records: those exclude absolute stores by construction — the sweep rejects
    displacements at or beyond the image base, and `base_relative_access` skips
    operands with no base register — so an address named by an absolute operand
    is exactly the case they cannot represent.

    Each writer carries the reason it could not be modelled, so a `mov [addr],
    eax` is *named* rather than assumed not to touch the address. A call whose
    target is unresolved is included on the same footing: it is a writer that
    was not modelled, not one that was assumed harmless.
    """
    decoder = result.decoder
    if decoder is None:
        raise ValueError("this result carries no decoder to ask")

    found = []
    for rva in decoder.decoded_rvas():
        insn = decoder.decode_one(rva)
        if insn is None:
            continue
        value = _write_of(insn, rva, address, result.image)
        if value is not None:
            found.append((rva, value))

    if include_unresolved_calls:
        for site in result.indirect_call_sites():
            found.append((site.rva, ValueSet.of_unmodeled(
                [(site.rva, "call through an unresolved target could write "
                            "this address")])))

    return tuple(found)


def value_set_of(result, address, **kwargs):
    """The join over every writer of 'address' — one object, not a list."""
    writers = writes_to(result, address, **kwargs)
    total = EMPTY
    for _, value in writers:
        total = total.widen(value)
    if total.kind is Bound.NONE:
        return ValueSet(kind=Bound.NONE,
                        unresolved_writes=unresolved_write_count(result))
    return ValueSet(
        kind=total.kind, values=total.values, lo=total.lo, hi=total.hi,
        writers=total.writers, unmodeled=total.unmodeled, parts=total.parts,
        unresolved_writes=unresolved_write_count(result))


def unresolved_write_count(result):
    """Decoded writes whose address this analysis could not resolve.

    The scope of every answer above. A base-relative store is a write to some
    address; whether that address is the one being asked about is not
    statically determinable, so it is neither enumerated as a writer nor
    silently assumed harmless. It is counted, and the count is printed beside
    the answer.
    """
    decoder = result.decoder
    if decoder is None:
        return 0
    image = result.image
    count = 0
    for rva in decoder.decoded_rvas():
        insn = decoder.decode_one(rva)
        if insn is None:
            continue
        for operand in insn.operands:
            if operand.kind != OP_MEM or not (operand.access & ACC_WRITE):
                continue
            if memory_address(insn, operand, image) is None:
                count += 1
    return count


def narrow_by_guards(result, address, base=None):
    """`value_set_of` narrowed by the guards that constrain this address.

    A `cmp [address], k` followed by a conditional branch means the fallthrough
    edge sees a constrained set. Without this, `RANGE` would be a declared form
    with no producer — and a range is the example the gap itself gives ("in
    [-13, -1]"), so a lattice that can never produce one would be missing the
    case it was written for.

    Only the fallthrough direction is modelled, and only when the compared
    value is an immediate. The taken edge yields a complement, which is not an
    interval; this returns the base set unchanged rather than approximating it,
    because an approximation there would be indistinguishable from an answer.
    """
    base = value_set_of(result, address) if base is None else base
    decoder = result.decoder
    if decoder is None:
        raise ValueError("this result carries no decoder to ask")

    guards = []
    for rva in decoder.decoded_rvas():
        insn = decoder.decode_one(rva)
        if insn is None or insn.mnemonic != "cmp":
            continue
        if not _operand_addresses(insn, address, result.image):
            continue
        limit = _immediate_of(insn)
        if limit is None:
            continue
        nxt = decoder.decode_one(rva + insn.size)
        if nxt is None or not nxt.is_cond:
            continue
        bounds = _fallthrough_bounds(nxt.mnemonic, limit)
        if bounds is None:
            continue
        guards.append((rva, rva + insn.size + nxt.size, bounds))

    chain = _single_guard_chain(guards)
    if chain is None:
        return base

    lo = max((b[0] for _, b in chain if b[0] is not None), default=None)
    hi = min((b[1] for _, b in chain if b[1] is not None), default=None)
    evidence = tuple((rva, f"guard: fallthrough implies "
                           f"{_describe(lo, hi)}") for rva, _ in chain)
    writers = base.writers + evidence

    # The guards constrain the value, so this is an intersection, not a join.
    # Joining would union the constrained bound back with the unconstrained
    # writers and report a wider set than the guard allows — an analysis
    # reporting *more* than the code can hold, which reads as a richer answer
    # rather than as a bug. The mirror direction is worse still: it would say a
    # value is impossible when it is not.
    if base.kind is Bound.SET:
        kept = frozenset(v for v in base.values
                         if (lo is None or v >= lo) and (hi is None or v <= hi))
        return ValueSet(kind=Bound.SET, values=kept, writers=writers)
    if base.kind is Bound.RANGE:
        new_lo = base.lo if lo is None else max(base.lo, lo)
        new_hi = base.hi if hi is None else min(base.hi, hi)
        if new_hi < new_lo:
            return ValueSet(kind=Bound.NONE,
                            unresolved_writes=base.unresolved_writes)
        return ValueSet(kind=Bound.RANGE, lo=new_lo, hi=new_hi,
                        writers=writers)
    return base


def _single_guard_chain(guards):
    """The one chain of guards whose fallthroughs are adjacent, or None.

    A chain is the range-check idiom: `cmp/ja` immediately followed by another
    `cmp/ja`, where the second is reached only on the first's fallthrough, so
    both bounds apply to the same path. Guards that are *not* adjacent may sit
    on different paths, and combining their bounds would report a narrower set
    than the code permits — the direction that turns "possible" into
    "impossible" without saying so.

    More than one chain therefore means no answer rather than a guess: the
    caller gets the un-narrowed set, which is a refusal it can see through
    `is_decided()` rather than a narrowed one it cannot.
    """
    if not guards:
        return None
    guards.sort()
    chains = [[guards[0]]]
    for guard in guards[1:]:
        if guard[0] == chains[-1][-1][1]:
            chains[-1].append(guard)
        else:
            chains.append([guard])
    if len(chains) != 1:
        return None
    return [(rva, bounds) for rva, _, bounds in chains[0]]


def _describe(lo, hi):
    if lo is not None and hi is not None:
        return f"0x{lo:X} <= value <= 0x{hi:X}"
    if hi is not None:
        return f"value <= 0x{hi:X}"
    if lo is not None:
        return f"value >= 0x{lo:X}"
    return "nothing"


# What the *fallthrough* edge of each conditional branch implies about the
# compared value, as (lo, hi). Every one of the eight constrains something:
# the taken direction of `jb` is `< limit`, so the fallthrough is `>= limit`.
#
# Only modelling the upper half — which is what a first pass naturally does,
# since `ja` reads like "the guard for too-big" — leaves the range-check idiom
# unrepresentable, and a range is the example the gap itself gives.
_FALLTHROUGH_BOUNDS = {
    "ja": (None, False),      # not taken: <= limit
    "jg": (None, False),
    "jae": (None, True),      # not taken: < limit
    "jge": (None, True),
    "jb": (False, None),      # not taken: >= limit
    "jl": (False, None),
    "jbe": (True, None),      # not taken: > limit
    "jle": (True, None),
}


def _fallthrough_bounds(mnemonic, limit):
    """(lo, hi) the fallthrough edge implies, either of which may be None."""
    shape = _FALLTHROUGH_BOUNDS.get(mnemonic)
    if shape is None:
        return None
    lo_shape, hi_shape = shape
    lo = limit + 1 if lo_shape else (limit if lo_shape is False else None)
    hi = limit - 1 if hi_shape else (limit if hi_shape is False else None)
    return (lo, hi)


def _write_of(insn, rva, address, image):
    """The ValueSet for this instruction's write to 'address', or None."""
    written = None
    for operand in insn.operands:
        if operand.kind != OP_MEM or not (operand.access & ACC_WRITE):
            continue
        if memory_address(insn, operand, image) == address:
            written = operand
            break
    if written is None:
        return None

    def unmodeled(reason, at=rva):
        return ValueSet.of_unmodeled([(at, reason)])

    # Anything that is not a plain store is a read-modify-write: its previous
    # value participates, so the operand is not the value. This is tested by
    # the mnemonic rather than by the destination's read flag because capstone
    # marks a mov destination write-only, which would leave a read-flag test
    # unreachable — and an unreachable branch is a claim that never runs.
    if insn.mnemonic not in _MOV_LIKE:
        return unmodeled(f"{insn.mnemonic}: the previous value participates")

    for operand in insn.operands:
        if operand is written:
            continue
        if operand.kind == OP_IMM:
            return ValueSet.of_value(operand.imm, rva)
        if operand.kind == OP_REG:
            # Not guessed. Reading a register's value needs provenance this
            # module does not build, and a fabricated constant is precisely the
            # defect the whole thing exists to prevent.
            return unmodeled("source register was not determined")
    return unmodeled("written from an operand this module does not model")


def _operand_addresses(insn, address, image):
    """True when some memory operand of 'insn' resolves to 'address'.

    Read or write: a guard reads the address, a writer writes it, and both are
    the same question about the operand's resolution.
    """
    for operand in insn.operands:
        if operand.kind != OP_MEM:
            continue
        if memory_address(insn, operand, image) == address:
            return True
    return False


def _immediate_of(insn):
    for operand in insn.operands:
        if operand.kind == OP_IMM:
            return operand.imm
    return None


def _lowest(value_set):
    if value_set.kind is Bound.SET and value_set.values:
        return min(value_set.values)
    if value_set.kind is Bound.RANGE:
        return value_set.lo
    return None
