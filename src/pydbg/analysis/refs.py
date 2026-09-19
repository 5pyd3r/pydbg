"""Turn one decoded instruction into the references it makes."""

from ..disasm.engine import OP_IMM, OP_MEM
from .model import RefKind


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
            if op.is_rip_relative:
                # [rip + disp] addresses relative to the *next* instruction,
                # and this is how x64 reaches data most of the time. Skipping
                # it is why an x64 pass that only looks at absolute operands
                # finds almost nothing.
                target = insn.address + insn.size + op.mem_disp
                rva = image.va_to_rva(target)
                if rva is not None:
                    found.append((rva, RefKind.MEM))
            elif op.is_table_mem:
                rva = image.va_to_rva(op.mem_disp)
                if rva is not None:
                    found.append((rva, RefKind.TABLE))
            elif op.is_absolute_mem and op.mem_disp:
                rva = image.va_to_rva(op.mem_disp)
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
