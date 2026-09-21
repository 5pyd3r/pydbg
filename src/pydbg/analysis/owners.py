"""Ownership — what an address, or a base register, belongs to.

Three questions get asked constantly and used to be answerable only by writing
a heuristic at the call site, which is the same thing as not answering them:
*which function owns this address*, *is this byte an instruction boundary*, and
*where did this base register come from*. A hand-written answer to any of the
three is indistinguishable from a correct one when it is right and from a
confident one when it is wrong, and the second case is what this module exists
to remove.

The split follows `access.py`'s: what this can say is "the register was loaded
from a slot at 0x2A1F0" or "it was not determined, and here is where the walk
stopped". What it cannot say is "the register holds a TConn". That is not a
missing feature — which register holds which object is not statically
determinable — and there is deliberately no `class_of` here, because a caller
that needs a class must invent that answer itself and should have to write down
that it did.
"""

from dataclasses import dataclass

from ..disasm.engine import (
    ACC_READ, ACC_WRITE, OP_IMM, OP_MEM, OP_REG, DisasmEngine,
)
from .access import STACK_REGISTERS

# What the decode has at one address. Three findings, kept apart because
# folding them collapses the distinction the whole module is about: an address
# no instruction starts at *and no instruction covers* is not the same as one
# covered by somebody's operand.
BOUNDARY_KINDS = ("instruction_start", "instruction_interior", "never_decoded")

# Where a base register's value came from. Six findings; `unknown` is the only
# one that carries no information, and it is never returned in place of a fact
# that was actually established.
RECEIVER_FACTS = ("constant", "loaded_from_slot", "loaded_from_stack",
                  "returned_by_call", "moved_from_register", "unknown")

# The facts that say something. A caller gating an argument on "is this
# determined" gets the answer it needs from this set rather than by comparing
# against the string "unknown", which would silently start returning True the
# day a seventh fact is added.
DETERMINED_FACTS = frozenset(("constant", "loaded_from_slot",
                              "loaded_from_stack", "returned_by_call"))

_OWNER_KINDS = ("start", "body", "gap", "after", "before", "unmapped")

# The register a call leaves its result in, on both Win32 ABIs this package
# analyses. Named rather than derived: capstone does not describe the calling
# convention, and guessing from the instruction's operands is exactly the kind
# of heuristic this module refuses to hide.
_RETURN_REGISTERS = ("eax", "rax")


@dataclass(frozen=True, slots=True)
class Boundary:
    """What the decode has at one RVA.

    'offset' is the distance from the covering instruction's start and is 0
    exactly when the address starts an instruction, which makes it the field to
    test rather than the kind string.

    'owner_kind' comes from `FunctionTable.owner_of` and is the answer that was
    missing: a byte inside a jump table embedded in .text has an owner (the
    function whose span contains it) but is not *claimed* by any instruction
    of that function's body in the way a real instruction's bytes are.
    """

    rva: int
    kind: str
    start: int | None
    size: int
    offset: int
    origin: str | None
    owner: int | None
    owner_kind: str
    reason: str | None = None      # only for 'never_decoded'

    @property
    def is_instruction_start(self):
        return self.kind == "instruction_start"

    def render(self):
        if self.kind == "never_decoded":
            return (f"0x{self.rva:X}: never decoded ({self.reason})")
        return (f"0x{self.rva:X}: {self.kind} of the instruction at "
                f"0x{self.start:X} (size {self.size}, offset {self.offset}, "
                f"origin {self.origin or '?'}); "
                f"owner {'0x%X' % self.owner if self.owner is not None else '-'}"
                f" ({self.owner_kind})")


def boundary_of(result, rva):
    """What the decode has at 'rva'.

    Resolution order is the whole content: an address that starts an
    instruction is not looked any further for; one covered by somebody else's
    operand is reported as interior together with the instruction that covers
    it; and only when neither holds is the address "never decoded", carrying
    the decoder's own reason.

    The reason is not invented here. `InstructionDecoder.failure_reason`
    already separates "outside every mapped section" from "the bytes are there
    and would not decode", and re-deriving that split locally would be the
    third place in this package to guess at it.
    """
    decoder = result.decoder
    if decoder is None:
        raise ValueError("this result carries no decoder to ask")

    # Bounded before anything walks backwards from it: `enclosing_instruction`
    # indexes the decoder's per-byte arrays, and an address outside the image
    # would index past them. An address the image does not map is an answer,
    # not a caller mistake — `never_decoded` with the decoder's own reason.
    inside = 0 <= rva < result.image.span and result.image.is_mapped(rva)

    if inside and decoder.is_decoded(rva):
        start, size, kind = rva, decoder.size_of(rva), "instruction_start"
    elif inside:
        start = decoder.enclosing_instruction(rva)
        if start is None:
            start, size, kind = None, 0, "never_decoded"
        else:
            size, kind = decoder.size_of(start), "instruction_interior"
    else:
        start, size, kind = None, 0, "never_decoded"

    owner, owner_kind = result.functions.owner_of(rva)
    return Boundary(
        rva=rva,
        kind=kind,
        start=start,
        size=size,
        offset=rva - start if start is not None else 0,
        origin=decoder.origin_of(start) if start is not None else None,
        owner=owner,
        owner_kind=owner_kind,
        reason=decoder.failure_reason(rva) if kind == "never_decoded" else None,
    )


@dataclass(frozen=True, slots=True)
class RegionOwnership:
    """Per-kind byte counts over one address range — the denominator.

    A claim like "every byte of this function is owned" is only checkable
    against the counts of the kinds that are *not*, and those counts had no
    home before this: the bytes past everything the analysis claimed
    (`unowned_after`) are exactly the quantity that made a table-resident byte
    invisible inside a coverage figure of 99.9997%.
    """

    start: int
    end: int
    bytes_by_kind: dict            # OWNER_KINDS -> bytes
    boundary_by_kind: dict         # BOUNDARY_KINDS -> bytes
    instruction_starts: int
    scanned: int
    truncated: bool = False        # the limit was reached before 'end'

    @property
    def unowned_after(self):
        return self.bytes_by_kind.get("after", 0)

    def is_fully_owned(self):
        """True only when every scanned byte is a function start or body.

        Deliberately stricter than "no byte is `after`": a gap inside a
        function's span is unowned by any *instruction*, and a range whose
        ownership claim survives that distinction is the one worth reporting.
        """
        if self.truncated:
            return False
        return all(self.bytes_by_kind.get(kind, 0) == 0
                   for kind in _OWNER_KINDS if kind not in ("start", "body"))

    def render(self):
        parts = [f"0x{self.start:X}..0x{self.end:X}: "
                 f"{self.scanned} bytes scanned, "
                 f"{self.instruction_starts} instruction starts"]
        for kind in _OWNER_KINDS:
            count = self.bytes_by_kind.get(kind, 0)
            if count:
                parts.append(f"  owned({kind}): {count}")
        for kind in BOUNDARY_KINDS:
            count = self.boundary_by_kind.get(kind, 0)
            if count:
                parts.append(f"  boundary({kind}): {count}")
        if self.truncated:
            parts.append("  TRUNCATED at the scan limit")
        return "\n".join(parts)


def classify_range(result, start, end, limit=100_000):
    """Ownership and boundary counts over [start, end).

    Walks instruction-wise rather than byte-wise — the per-byte form is
    quadratic in the lookups and this is meant to be called on whole sections.
    A chunk is only taken whole when the ownership kind agrees at both ends of
    it, so an instruction straddling a function boundary cannot have its bytes
    attributed to one side.

    `limit` bounds the work because a caller asking about a section should not
    accidentally ask about an image; a range that hits it reports
    ``truncated``, and `is_fully_owned` refuses to answer True for one.
    """
    counts = {kind: 0 for kind in _OWNER_KINDS}
    boundaries = {kind: 0 for kind in BOUNDARY_KINDS}
    starts = 0
    scanned = 0
    rva = start

    while rva < end and scanned < limit:
        _, kind = result.functions.owner_of(rva)
        boundary = boundary_of(result, rva)
        run = boundary.size if boundary.is_instruction_start else 1
        run = max(1, min(run, end - rva, limit - scanned))
        if run > 1 and result.functions.owner_of(rva + run - 1)[1] != kind:
            run = 1

        counts[kind] += run
        boundaries[boundary.kind] += run
        if boundary.is_instruction_start:
            starts += 1
        scanned += run
        rva += run

    return RegionOwnership(
        start=start, end=end,
        bytes_by_kind=counts, boundary_by_kind=boundaries,
        instruction_starts=starts, scanned=scanned,
        truncated=rva < end,
    )


@dataclass(frozen=True, slots=True)
class ReceiverNote:
    """Where the base register of one access came from.

    'evidencing' is every instruction RVA the walk looked at, in order, so a
    reader can re-derive the answer instead of trusting it. 'stopped_at' is why
    the walk could not go further, and is the field a hand-written
    discriminator does not have — which is precisely why one that is wrong
    reads the same as one that is right.
    """

    rva: int
    base_reg: str
    fact: str
    source_rva: int | None
    evidencing: tuple = ()
    stopped_at: str | None = None
    determined: bool = False

    def render(self):
        where = f" from 0x{self.source_rva:X}" if self.source_rva is not None else ""
        line = f"0x{self.rva:X}: {self.base_reg} = {self.fact}{where}"
        if self.stopped_at:
            line += f" (stopped: {self.stopped_at})"
        return line


def memory_base_registers(insn, engine=None):
    """(base register name, ...) for the `[reg + ...]` operands of 'insn'.

    Stack registers are excluded, matching `access.base_relative_access`: a
    frame pointer bases every local variable and says nothing about which
    object is being reached.
    """
    if insn is None:
        return ()
    engine = engine or DisasmEngine(mode="x86")
    found = []
    for operand in insn.operands:
        if operand.kind != OP_MEM or operand.mem_base == 0:
            continue
        name = engine.reg_name(operand.mem_base)
        if not name or name in STACK_REGISTERS:
            continue
        if name not in found:
            found.append(name)
    return tuple(found)


def receiver_of(result, rva, base_reg=None):
    """Where the base register of the access at 'rva' came from, or None.

    The walk runs through the straight-line run that ends at 'rva', starting
    from the owning function's entry. It stops — reporting `unknown` with a
    reason — at anything that would make a linear reading a guess: a branch, a
    call, or the entry being outside the function's extent. Over-invalidating
    is the safe direction here; the alternative is attributing a value written
    on one path to an access on another, which is the failure this returns
    'unknown' to avoid rather than a gap it papers over.
    """
    decoder = result.decoder
    if decoder is None:
        raise ValueError("this result carries no decoder to ask")

    insn = decoder.decode_one(rva) if decoder.is_decoded(rva) else None
    if insn is None:
        return None
    engine = DisasmEngine(mode=result.image.mode)
    if base_reg is None:
        candidates = memory_base_registers(insn, engine)
        if not candidates:
            return None
        base_reg = candidates[0]

    owner, owner_kind = result.functions.owner_of(rva)
    if owner is None or owner_kind not in ("start", "body"):
        return _unknown(rva, base_reg, "the site is not inside a recovered "
                                       f"function ({owner_kind})")

    facts, source, walked = {}, {}, []
    branched_at = None
    for cursor in _straight_line(decoder, owner, rva):
        walked.append(cursor)
        step = decoder.decode_one(cursor)
        if step is None:
            branched_at = f"0x{cursor:X} would not decode"
            break
        if step.is_call:
            facts.clear()
            source.clear()
            for name in _RETURN_REGISTERS:
                facts[name] = "returned_by_call"
                source[name] = cursor
            continue
        if step.is_jmp or step.is_ret or step.is_cond:
            branched_at = (f"control flow at 0x{cursor:X} makes this not "
                           f"one path")
            break
        _apply(step, cursor, facts, source, engine)

    if branched_at is not None:
        # Whatever was established before the branch was established on a path
        # that may not be the one reaching this site, so it is not an answer.
        return ReceiverNote(rva=rva, base_reg=base_reg, fact="unknown",
                            source_rva=None, evidencing=tuple(walked),
                            stopped_at=branched_at, determined=False)

    fact = facts.get(base_reg, "unknown")
    stopped = source.get((base_reg, "why"))
    if fact == "unknown" and stopped is None:
        stopped = (f"{base_reg} is not written anywhere between the function "
                   f"entry and this site")
    return ReceiverNote(rva=rva, base_reg=base_reg, fact=fact,
                        source_rva=source.get(base_reg),
                        evidencing=tuple(walked),
                        stopped_at=stopped,
                        determined=fact in DETERMINED_FACTS)


def _unknown(rva, base_reg, why):
    return ReceiverNote(rva=rva, base_reg=base_reg, fact="unknown",
                        source_rva=None, evidencing=(), stopped_at=why,
                        determined=False)


def _straight_line(decoder, start, stop):
    """Instruction RVAs from 'start' up to (not including) 'stop'.

    Skips over bytes that start no instruction rather than stopping at them: a
    table embedded in the body leaves holes, and a hole does not end a
    straight-line run.
    """
    cursor = start
    while cursor < stop:
        size = decoder.size_of(cursor)
        if not size:
            cursor += 1
            continue
        yield cursor
        cursor += size


def _apply(insn, rva, facts, source, engine):
    """Record what 'insn' writes into the register-fact maps."""
    for name in _written_registers(insn, engine):
        fact, inherited, why = _written_by(insn, name, engine, facts, source)
        facts[name] = fact
        # The instruction that established the value. For a propagated fact
        # that is wherever it came from, not the copy — reporting the copy
        # would make a chain of moves look like a chain of definitions.
        source[name] = inherited if inherited is not None else rva
        if why is not None:
            source[(name, "why")] = why


def _written_registers(insn, engine):
    names = []
    for operand in insn.operands:
        if operand.kind != OP_REG or not (operand.access & ACC_WRITE):
            continue
        name = engine.reg_name(operand.reg)
        if name and name not in names:
            names.append(name)
    return names


def _written_by(insn, name, engine, facts, source):
    """(fact, inherited_source, reason) for the value 'insn' puts in 'name'.

    'inherited_source' is None when the value originates here, in which case
    the caller records this instruction as the source.
    """
    index = None
    for position, operand in enumerate(insn.operands):
        if (operand.kind == OP_REG and operand.access & ACC_WRITE
                and engine.reg_name(operand.reg) == name):
            index = position
            break
    if index is None:
        return ("unknown", None, f"{name} is not written by this instruction")

    destination = insn.operands[index]
    # A read-modify-write destination produces a value derived from the one it
    # already held, so whatever that was does not survive: `add eax, ecx` does
    # not make eax ecx's value, and propagating the source's fact here is the
    # single easiest way to report a confident wrong answer.
    if destination.access & ACC_READ:
        return ("unknown", None,
                f"0x{'%X' % insn.address} reads {name} to write it")

    # `lea` computes an address and touches no memory, so its memory operand is
    # not a load. Treated as a constant only when the address is absolute:
    # `lea ecx, [esi+0x10]` is a pointer *into* esi's object and says nothing
    # about where that object came from.
    if insn.mnemonic == "lea":
        for operand in insn.operands:
            if operand.kind != OP_MEM:
                continue
            if operand.mem_base == 0 and operand.mem_index == 0:
                return ("constant", None, None)
            return ("unknown", None,
                    "lea of a base-relative address: the value is derived "
                    "from a register this walk did not resolve")

    for position, operand in enumerate(insn.operands):
        if position == index:
            continue
        if operand.kind == OP_IMM:
            return ("constant", None, None)
        if operand.kind == OP_REG:
            other = engine.reg_name(operand.reg)
            if other in facts and facts[other] != "unknown":
                return (facts[other], source.get(other), None)
            return ("moved_from_register", None,
                    f"{other} is not determined")
        if operand.kind == OP_MEM:
            base = (engine.reg_name(operand.mem_base)
                    if operand.mem_base else None)
            if base in STACK_REGISTERS:
                return ("loaded_from_stack", None, None)
            return ("loaded_from_slot", None, None)

    # Written from something this walk does not model, and saying so is the
    # point.
    return ("unknown", None,
            f"0x{'%X' % insn.address} writes {name} from an operand this walk "
            f"does not model")
