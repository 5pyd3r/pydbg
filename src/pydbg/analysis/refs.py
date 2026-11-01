"""Turn one decoded instruction into the references it makes."""

from ..disasm.engine import OP_IMM, OP_MEM
from .consts import address_without_registers
from .model import RefKind


def memory_address(insn, op, image):
    """RVA a memory operand addresses, or None if it is not a fixed address.

    Handles both forms that name a fixed location — [disp] and [rip + disp] —
    which between them are how every direct memory reference appears. Anything
    with a base or an index is a computed address and is not resolved here.

    The address arithmetic lives in consts.address_without_registers, which
    answers in VA space; this is the one conversion that makes it an RVA.
    Two copies of 'rip + size + disp' is the address-space mistake this
    analysis has already made once.
    """
    address = address_without_registers(insn, op)
    if address is None:
        return None
    return image.va_to_rva(address)


def classify_refs(insn, image):
    """References made by 'insn', as (target_rva, RefKind) pairs.

    The window test lives in va_to_rva: only values that actually fall inside
    the image count. Accepting anything below the image span as an RVA is the
    mistake that fills a cross-reference index with noise.
    """
    found = []

    for op in insn.operands:
        if op.kind == OP_IMM:
            rva = image.va_to_rva(op.imm)
            if rva is not None:
                kind = (RefKind.BRANCH if (insn.is_call or insn.is_jmp)
                        else RefKind.IMM)
                found.append((rva, kind))

        elif op.kind == OP_MEM:
            if op.is_table_mem:
                rva = image.va_to_rva(op.mem_disp)
                if rva is not None:
                    found.append((rva, RefKind.TABLE))
                continue
            rva = memory_address(insn, op, image)
            if rva is not None:
                found.append((rva, RefKind.MEM))

    return found


def branch_target(insn, image):
    """The RVA this instruction branches to directly, or None.

    Only immediate operands count. A branch through a register or memory is a
    target this analysis cannot resolve statically, and saying so is the point:
    an incomplete call graph that admits it beats one that looks total.
    """
    if not (insn.is_call or insn.is_jmp):
        return None
    for op in insn.operands:
        if op.kind == OP_IMM:
            return image.va_to_rva(op.imm)
    return None


def is_indirect_branch(insn):
    """True for a branch whose target is not an immediate.

    "Indirect" and "has no immediate operand" are the same statement, so this
    is derived from the operand kinds rather than tracked separately — the two
    cannot drift apart. These edges are dropped by static analysis, and callers
    need to be able to count what was dropped instead of assuming the graph is
    complete: one target's entry point was reachable only through
    `call [esi+0x18]` and appeared nowhere in the call graph.
    """
    if not (insn.is_call or insn.is_jmp):
        return False
    return all(op.kind != OP_IMM for op in insn.operands)
