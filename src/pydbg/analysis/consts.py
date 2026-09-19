"""Lightweight constant propagation, for resolving indirect branches.

`call [esi+0x18]` has no target in the instruction. Sometimes the register was
loaded from a known place a few instructions earlier, and then the slot it
points at can be read — which turns an edge the call graph was missing into a
real one.

This is deliberately the smallest thing that helps. It tracks a register only
while consecutive instructions are forms it recognises, and **forgets
everything on any instruction it does not**. That costs resolutions; it never
costs correctness. A wrong "constant" would produce a call edge to somewhere
the program never calls, and nothing downstream could tell it apart from a
real one — a missing edge is visible, a fabricated one is not.
"""

from ..disasm.engine import OP_IMM, OP_MEM, OP_REG

# capstone spells a 64-bit immediate/moffs load 'movabs'; both it and 'mov'
# put the source value in the destination.
_MOV_LIKE = frozenset(("mov", "movabs"))
# 'lea' differs from 'mov' in using the address of a memory operand rather
# than its contents, and the two are otherwise identical at the operand level.
_LEA_LIKE = frozenset(("lea",))


class ConstantTracker:
    """Which registers hold known values, over one straight-line run."""

    def __init__(self, image):
        self.image = image
        self.regs = {}

    def reset(self):
        self.regs.clear()

    # ── state ──────────────────────────────────────────────────

    def observe(self, insn):
        """Fold 'insn' into the state. Forgets everything if unrecognised."""
        produced = self._produced_constant(insn)
        if produced is None:
            self.reset()
            return
        register, value = produced
        self.regs[register] = value

    def _produced_constant(self, insn):
        """(register, value) this instruction writes, or None."""
        operands = insn.operands
        if len(operands) != 2:
            return None
        destination, source = operands
        if destination.kind != OP_REG:
            return None

        if source.kind == OP_IMM and insn.mnemonic in _MOV_LIKE:
            return destination.reg, source.imm

        if source.kind == OP_MEM:
            # Register-aware: `mov eax, [eax]` chains off a value already
            # known, which is one more indirection than a bare
            # `mov eax, [absolute]`. The address is computed from the state
            # before the write, which is what the instruction does.
            address = self.operand_address(insn, source)
            if address is None:
                return None
            if insn.mnemonic in _LEA_LIKE:
                return destination.reg, address
            if insn.mnemonic in _MOV_LIKE:
                value = self._read_pointer_at(address)
                return None if value is None else (destination.reg, value)

        return None

    # ── reads ──────────────────────────────────────────────────

    def _read_pointer_at(self, va):
        """Pointer stored at an absolute address, or None."""
        rva = self.image.va_to_rva(va)
        if rva is None:
            return None
        return self.image.read_pointer(rva)

    def resolve_branch(self, insn):
        """Target RVA of an indirect branch, or None if it stays unknown.

        The slot's contents must land in executable memory. Without that check
        `call [IAT]` "resolves" in a file image — where the slot holds the RVA
        of the import-name struct, not the imported function — and records a
        call edge to a string. A fabricated edge is worse than a missing one:
        a missing edge shows up as a function with no callers, and a fabricated
        one is indistinguishable from a real call.

        Such a call is genuinely unresolved here anyway: its target lives in
        another module. Against a live process, where the loader has written
        the real address into the slot, this does resolve it.
        """
        for operand in insn.operands:
            if operand.kind != OP_MEM:
                continue
            slot = self.operand_address(insn, operand)
            if slot is None:
                continue
            value = self._read_pointer_at(slot)
            if value is None:
                continue
            rva = self.image.va_to_rva(value)
            if rva is not None and self.image.is_exec(rva):
                return rva
        return None

    def operand_address(self, insn, operand):
        """Where a memory operand points, given what the registers hold.

        Unlike refs.memory_address this also resolves a register-based address
        when that register is a known constant — which is the whole point of
        tracking them. Returns a VA, not an RVA, so that a tracked register
        (which holds a VA) can be added to the displacement before a single
        conversion at the end.
        """
        address = address_without_registers(insn, operand)
        if address is not None:
            return address
        if operand.mem_index == 0 and operand.mem_base in self.regs:
            return self.regs[operand.mem_base] + operand.mem_disp
        if operand.mem_base == 0 and operand.mem_index in self.regs:
            # [reg*scale + disp] with a constant index: the slot the table
            # entry lives in, not the entry's value.
            return (self.regs[operand.mem_index] * operand.mem_scale
                    + operand.mem_disp)
        return None


def address_without_registers(insn, operand):
    """VA a memory operand names using only what is in the encoding.

    A VA rather than an RVA, matching how instructions are decoded: a
    displacement in the encoding is an absolute address, and a RIP-relative
    one is relative to the end of the instruction. That is deliberate and is
    the opposite of refs.memory_address, which answers in RVA space — mixing
    the two is the address-space mistake this analysis has already made once.
    """
    if operand.kind != OP_MEM or operand.mem_segment != 0:
        return None
    if operand.is_rip_relative:
        return insn.address + insn.size + operand.mem_disp
    if operand.is_absolute_mem and operand.mem_disp:
        return operand.mem_disp
    return None
