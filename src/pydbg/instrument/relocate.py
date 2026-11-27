"""The displaced prefix: which instructions a detour takes, and where they run.

A detour at a block entry overwrites five bytes with an `E9 rel32`. Those five
bytes are one long instruction or a few short ones, and they have to keep their
meaning at their new address:

- a RIP-relative operand's `disp32` is relative to the end of *that*
  instruction, so it must be rewritten for the stub (spec §12.3). On a 32-bit
  target there is no RIP-relative addressing at all, so the prefix moves as a
  byte-for-byte copy;
- a relative branch cannot be moved without rewriting its displacement, and the
  spec refuses rel8/rel32 rewriting outright — so a prefix containing one is
  refused rather than copied wrong (§12.6). The criterion is the same on both
  architectures: it is a property of the instruction, not of its operand form.

Everything here is a pure function of decoded instructions and addresses: no
process memory, no threads, no debugger, no `_pydbg`. The plan speaks RVAs
(`BlockPlan.rva`) while a live decoder addresses instructions by VA; the
`address_base` argument carries the offset between the two, so relocation math
keeps using the decoder's addresses and every refusal still names an RVA.
"""

from ..exceptions import PydbgError

# Bytes a detour overwrites: one near JMP (E9 rel32). The encoding is five
# bytes in both 32- and 64-bit mode, so the prefix a plan takes is the same on
# the two architectures.
DETOUR_SIZE = 5

# Where the relocated prefix starts inside a stub: the assembled prologue's
# exact length, per architecture. The relocation math below addresses the moved
# instruction as `stub_address + stub_prologue_size(arch) + ...`, so this is a
# contract with `stub.build_stub`, which asserts its assembled prologue is
# exactly this long. It lives here because the relocation is the half that
# needs the number; `stub.py` re-exports it.
STUB_PROLOGUE_SIZES = {32: 88, 64: 112}

# The x64 length under the name existing callers import. A caller whose target
# may be WOW64 asks `stub_prologue_size(arch)` instead.
STUB_PROLOGUE_SIZE = STUB_PROLOGUE_SIZES[64]


def stub_prologue_size(arch):
    """The stub prologue's length for `arch` (32 or 64)."""
    return STUB_PROLOGUE_SIZES[32 if arch == 32 else 64]


_DISP32 = 4
# Encoded widths a trailing immediate can have after a RIP-relative disp32:
# imm8, imm16, imm32. There is no `mov m64, imm64`, so 8 never occurs.
_IMMEDIATE_WIDTHS = (0, 1, 2, 4)
# ModRM for RIP-relative addressing: mod=00 (no second displacement) and
# rm=101 (RIP). The reg field is free, hence the mask.
_MODRM_RIP = 0x05
_MODRM_MASK = 0xC7


class UnsupportedInstruction(PydbgError):
    """A refusal: this block cannot host a detour, and here is which instruction.

    Both halves matter. The address is what the caller needs to refuse one block
    and keep installing the rest; the mnemonic is what makes a log line
    actionable without re-decoding the image. `mnemonic` is '' when the refusal
    is about the block rather than one instruction (a block shorter than the
    detour, say).

    `rva` is a module-relative address, the same domain as `BlockPlan.rva` and
    the record the stub writes — not the decoder's VA. The pure functions take
    the decoder's RVA -> address offset as `address_base` so their refusals can
    stay in this domain; tests that decode at an RVA-shaped address leave it 0.
    """

    def __init__(self, rva, mnemonic='', reason=''):
        self.rva = rva
        self.mnemonic = mnemonic
        self.reason = reason
        who = f"{mnemonic} " if mnemonic else ""
        super().__init__(f"unsupported {who}at rva 0x{rva:X}: {reason}")


def take_prefix(insns, block_rva, need=DETOUR_SIZE, *, address_base=0):
    """The shortest run of whole instructions at `block_rva` covering `need` bytes.

    A detour may only overwrite whole instructions: splitting one would leave
    half of it to be executed twice or not at all. So the prefix is accumulated
    instruction by instruction and stops at the first instruction that reaches
    the byte budget.

    Args:
        insns: decoded instructions. The decoder addresses them at
            `address_base + rva` — a live `InstructionDecoder` decodes by VA,
            while the plan and the CFG speak RVAs.
        block_rva: the block entry, an RVA (the plan's domain).
        need: bytes the detour must cover.
        address_base: the decoder's RVA -> address offset. 0 when it already
            addresses by RVA (the fakes); the module base on a live image.
            Refusals name RVAs, never the decoder's addresses.

    Raises:
        UnsupportedInstruction: the instructions do not start at `block_rva`,
            are not contiguous, or do not reach `need` bytes at all.
    """
    insns = tuple(insns)
    if not insns:
        raise UnsupportedInstruction(block_rva, '', 'no decoded instructions')

    first = insns[0]
    if first.address != block_rva + address_base:
        raise UnsupportedInstruction(
            block_rva, first.mnemonic,
            f'the first instruction is at rva '
            f'0x{first.address - address_base:X}, '
            f'not the block entry 0x{block_rva:X}')

    taken = []
    covered = 0
    for insn in insns:
        if taken:
            previous = taken[-1]
            expected = previous.address + previous.size
            if insn.address != expected:
                raise UnsupportedInstruction(
                    insn.address - address_base, insn.mnemonic,
                    f'instruction does not follow rva '
                    f'0x{previous.address - address_base:X} '
                    f'({previous.size} bytes)')
        taken.append(insn)
        covered += insn.size
        if covered >= need:
            return tuple(taken)

    raise UnsupportedInstruction(
        block_rva, '',
        f'block is {covered} bytes, need {need} to cover a detour')


def prefix_is_relocatable(insns):
    """Whether the whole prefix can be executed from the stub unchanged.

    Any branch or return is refused: its displacement is relative to where it
    sits, and rewriting rel8/rel32 is explicitly out of scope (§12.6). The
    engine already folds `call`/`jmp`/`jcc` into `is_call`/`is_jmp` and the loop
    family into `is_jmp`, so this is a property lookup, not a mnemonic list that
    can drift from capstone's classification.
    """
    return all(not (insn.is_call or insn.is_jmp or insn.is_ret)
               for insn in insns)


def decoder_address_base(instruction_rvas, instructions):
    """The offset between the decoder's addresses and RVAs.

    `InstructionDecoder.decode_one()` decodes at the instruction's virtual
    address — that is what makes a branch target and `address + size + disp`
    meaningful — while a `BlockPlan` and the CFG speak RVAs. The offset is a
    property of the decoder, recovered from the first instruction it returned
    for the block's first RVA; a caller with no decoded run gets 0 and lets
    `take_prefix()` refuse the block.

    `take_prefix()` and `relocate_prefix()` take it as `address_base`: the
    decoder's addresses stay VAs (relocation needs them), and every refusal
    still names an RVA, the domain `BlockPlan` speaks.
    """
    if not instructions or not instruction_rvas:
        return 0
    return instructions[0].address - instruction_rvas[0]


def _disp32_offset(insn, disp, address_base=0):
    """Index of the RIP-relative disp32 inside `insn.raw_bytes`.

    The displacement is followed only by the instruction's immediate, if there
    is one, and the operand's `size` is not the encoded width: `add qword ptr
    [rip+x], 1` reports an 8-byte immediate but encodes it as one byte. So the
    width is searched (0, 1, 2, 4), and a candidate must satisfy two
    independent facts:

    - the four bytes equal the displacement capstone decoded, and
    - the byte before them is the ModRM byte for RIP+disp32 (`mod=00 rm=101`).

    A hand-built `Instruction` whose bytes and operands disagree has no
    candidate, and `len(matches) != 1` makes this refuse rather than guess —
    guessing here writes four wrong bytes into the target.
    """
    raw = insn.raw_bytes
    wanted = disp & 0xFFFFFFFF
    matches = []
    for width in _IMMEDIATE_WIDTHS:
        pos = len(raw) - _DISP32 - width
        if pos < 1 or pos + _DISP32 > len(raw):
            continue
        if int.from_bytes(raw[pos:pos + _DISP32], 'little') != wanted:
            continue
        if (raw[pos - 1] & _MODRM_MASK) != _MODRM_RIP:
            continue
        matches.append(pos)
    if len(matches) != 1:
        raise UnsupportedInstruction(
            insn.address - address_base, insn.mnemonic,
            f'the RIP-relative displacement was found in {len(matches)} places '
            f'in {raw.hex()}, not one')
    return matches[0]


def relocate_prefix(insns, stub_address, *, address_base=0, arch=64):
    """The prefix's bytes, rewritten to run at `stub_address + <prologue>`.

    A RIP-relative operand keeps addressing the same memory: the original
    target is `insn.address + insn.size + disp`, and the new displacement is
    that target minus the end of the instruction in the stub. Everything else
    is copied byte for byte — and on a 32-bit target that is every instruction,
    because x86 has no RIP-relative addressing.

    `stub_address` is the start of the stub `build_stub` will emit, not the
    start of the relocated bytes — the caller has one address (where it will
    write the stub) and the prologue sits in front.

    Args:
        insns: decoded instructions, addressed at `address_base + rva`.
        stub_address: where the stub will be written (a VA).
        address_base: the decoder's RVA -> address offset, used only to keep
            refusals in the RVA domain (`BlockPlan.rva`); 0 for a decoder that
            already addresses by RVA.
        arch: the target's architecture (32 or 64). Only the prologue's length
            depends on it; both architectures refuse the same branches.

    Raises:
        UnsupportedInstruction: a branch or return is in the prefix, a
            displacement would not fit int32, or the decoded bytes disagree
            with the operands.
    """
    insns = tuple(insns)
    for insn in insns:
        if not prefix_is_relocatable((insn,)):
            raise UnsupportedInstruction(
                insn.address - address_base, insn.mnemonic,
                'a relative branch cannot be moved without rewriting rel8/rel32')

    relocated = bytearray()
    for insn in insns:
        raw = insn.raw_bytes
        if len(raw) != insn.size:
            raise UnsupportedInstruction(
                insn.address - address_base, insn.mnemonic,
                f'decoded {len(raw)} bytes but the instruction is '
                f'{insn.size} bytes long')
        raw = bytearray(raw)
        rip_relative = [op for op in insn.operands if op.is_rip_relative]
        if len(rip_relative) > 1:
            raise UnsupportedInstruction(
                insn.address - address_base, insn.mnemonic,
                'more than one RIP-relative operand')
        if rip_relative:
            operand = rip_relative[0]
            target = insn.address + insn.size + operand.mem_disp
            moved_to = stub_address + stub_prologue_size(arch) + len(relocated)
            disp = target - (moved_to + insn.size)
            if not -(1 << 31) <= disp < (1 << 31):
                raise UnsupportedInstruction(
                    insn.address - address_base, insn.mnemonic,
                    f'RIP-relative target 0x{target:X} is out of ±2GB range '
                    f'of the stub at 0x{moved_to:X}')
            pos = _disp32_offset(insn, operand.mem_disp, address_base)
            raw[pos:pos + _DISP32] = (disp & 0xFFFFFFFF).to_bytes(_DISP32, 'little')
        relocated += raw
    return bytes(relocated)
