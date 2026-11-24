"""Basic-block detours: the 5 bytes that get displaced, and the stub that runs them.

A detour at a block entry overwrites five bytes with an `E9 rel32`. Those five
bytes are one long instruction or a few short ones, and they have to keep their
meaning at their new address:

- a RIP-relative operand's `disp32` is relative to the end of *that*
  instruction, so it must be rewritten for the stub (spec §12.3);
- a relative branch cannot be moved without rewriting its displacement, and the
  spec refuses rel8/rel32 rewriting outright — so a prefix containing one is
  refused rather than copied wrong (§12.6).

Everything in this module is a pure function of decoded instructions and
addresses: no process memory, no threads, no debugger. `build_stub` assembles
its prologue with keystone (an optional extra); the relocation half is pure
Python plus capstone-produced `Instruction` objects.
"""

import struct

from ..exceptions import PydbgError
from ..patch.assembler import Assembler

# keystone is a `patch` extra; the relocation half does not need it, and the
# stub builder says so rather than failing somewhere inside the assembler.
try:
    import keystone
except ImportError:                      # pragma: no cover - environment
    keystone = None

# Bytes a detour overwrites: one near JMP (E9 rel32).
DETOUR_SIZE = 5

# The v1 record the stub appends (trace/format.py `_RECORD`). The struct is
# spelled out here because this module must not import `pydbg.trace`, whose
# package __init__ needs the extension.
_RECORD = struct.Struct("<B3xIIQQQ")
RECORD_SIZE = _RECORD.size
# Field offsets, taken from the format itself. `'<'` means standard sizes with
# no alignment padding, so ts follows rva at 12 rather than at the next 8-byte
# boundary; assuming 16 would put a at 24 and run b off the end of the slot.
_RVA_OFFSET = struct.calcsize("<B3xI")        # 8
_TS_OFFSET = struct.calcsize("<B3xII")        # 12
_COUNT_OFFSET = _TS_OFFSET + 8                # 20
_B_OFFSET = _COUNT_OFFSET + 8                 # 28

# Where the relocated prefix starts inside a stub: build_stub emits its fixed
# prologue first and asserts it is exactly this long, so a keystone encoding
# change cannot silently shift the bytes this offset was computed for.
STUB_PROLOGUE_SIZE = 112

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
    """

    def __init__(self, rva, mnemonic='', reason=''):
        self.rva = rva
        self.mnemonic = mnemonic
        self.reason = reason
        who = f"{mnemonic} " if mnemonic else ""
        super().__init__(f"unsupported {who}at rva 0x{rva:X}: {reason}")


def take_prefix(insns, block_rva, need=DETOUR_SIZE):
    """The shortest run of whole instructions at `block_rva` covering `need` bytes.

    A detour may only overwrite whole instructions: splitting one would leave
    half of it to be executed twice or not at all. So the prefix is accumulated
    instruction by instruction and stops at the first instruction that reaches
    the byte budget.

    Raises:
        UnsupportedInstruction: the instructions do not start at `block_rva`,
            are not contiguous, or do not reach `need` bytes at all.
    """
    insns = tuple(insns)
    if not insns:
        raise UnsupportedInstruction(block_rva, '', 'no decoded instructions')

    first = insns[0]
    if first.address != block_rva:
        raise UnsupportedInstruction(
            block_rva, first.mnemonic,
            f'the first instruction is at 0x{first.address:X}, '
            f'not the block entry')

    taken = []
    covered = 0
    for insn in insns:
        if taken:
            previous = taken[-1]
            expected = previous.address + previous.size
            if insn.address != expected:
                raise UnsupportedInstruction(
                    insn.address, insn.mnemonic,
                    f'instruction does not follow 0x{previous.address:X} '
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


def _disp32_offset(insn, disp):
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
            insn.address, insn.mnemonic,
            f'the RIP-relative displacement was found in {len(matches)} places '
            f'in {raw.hex()}, not one')
    return matches[0]


def relocate_prefix(insns, stub_address):
    """The prefix's bytes, rewritten to run at `stub_address + STUB_PROLOGUE_SIZE`.

    A RIP-relative operand keeps addressing the same memory: the original
    target is `insn.address + insn.size + disp`, and the new displacement is
    that target minus the end of the instruction in the stub. Everything else
    is copied byte for byte.

    `stub_address` is the start of the stub `build_stub` will emit, not the
    start of the relocated bytes — the caller has one address (where it will
    write the stub) and the prologue sits in front.

    Raises:
        UnsupportedInstruction: a branch or return is in the prefix, a
            displacement would not fit int32, or the decoded bytes disagree
            with the operands.
    """
    insns = tuple(insns)
    for insn in insns:
        if not prefix_is_relocatable((insn,)):
            raise UnsupportedInstruction(
                insn.address, insn.mnemonic,
                'a relative branch cannot be moved without rewriting rel8/rel32')

    relocated = bytearray()
    for insn in insns:
        raw = insn.raw_bytes
        if len(raw) != insn.size:
            raise UnsupportedInstruction(
                insn.address, insn.mnemonic,
                f'decoded {len(raw)} bytes but the instruction is '
                f'{insn.size} bytes long')
        raw = bytearray(raw)
        rip_relative = [op for op in insn.operands if op.is_rip_relative]
        if len(rip_relative) > 1:
            raise UnsupportedInstruction(
                insn.address, insn.mnemonic,
                'more than one RIP-relative operand')
        if rip_relative:
            operand = rip_relative[0]
            target = insn.address + insn.size + operand.mem_disp
            moved_to = stub_address + STUB_PROLOGUE_SIZE + len(relocated)
            disp = target - (moved_to + insn.size)
            if not -(1 << 31) <= disp < (1 << 31):
                raise UnsupportedInstruction(
                    insn.address, insn.mnemonic,
                    f'RIP-relative target 0x{target:X} is out of ±2GB range '
                    f'of the stub at 0x{moved_to:X}')
            pos = _disp32_offset(insn, operand.mem_disp)
            raw[pos:pos + _DISP32] = (disp & 0xFFFFFFFF).to_bytes(_DISP32, 'little')
        relocated += raw
    return bytes(relocated)


# `jmp qword ptr [rip+0]`: the address follows the instruction, so the stub is
# position-independent and build_stub never needs to know where it will live.
_ABSOLUTE_JUMP = b"\xff\x25\x00\x00\x00\x00"


def _assemble(code):
    """Assemble x64 Intel syntax, or say which optional dependency is missing."""
    if keystone is None:
        raise PydbgError("keystone-engine not installed")
    return Assembler("x64").assemble(code)


def _prologue_source(sink, block_rva, count):
    """The fixed prologue, as keystone source.

    Every statement is written in a form whose length does not depend on its
    value -- `movabs` for absolute addresses, `mov r32, imm32` for the ring
    parameters -- because the relocated prefix was addressed for
    `STUB_PROLOGUE_SIZE` and build_stub checks the assembled length against it.
    """
    return "; ".join([
        # Everything the stub clobbers, and the flags `lock xadd` would change.
        "pushfq",
        "push rax", "push rcx", "push rdx",
        "push r8", "push r9", "push r10", "push r11",
        # count = the slot counter's old value, atomically.
        "mov eax, 1",
        f"movabs r8, 0x{sink.head_address:X}",
        "lock xadd dword ptr [r8], eax",
        # slot = slot_area + (count & (capacity - 1)) * slot_size
        "mov ecx, eax",
        f"mov edx, 0x{sink.capacity - 1:X}",
        "and ecx, edx",
        f"mov edx, 0x{sink.slot_size:X}",
        "imul ecx, edx",
        f"movabs rdx, 0x{sink.address:X}",
        "add rcx, rdx",
        # One v1 BLOCK record: kind, tid, rva, ts, a, b. tid and ts are not
        # available in the target, so both are zero (spec §12.1).
        "mov qword ptr [rcx], 1",
        f"mov dword ptr [rcx + {_RVA_OFFSET}], 0x{block_rva:X}",
        f"mov qword ptr [rcx + {_TS_OFFSET}], 0",
        f"mov qword ptr [rcx + {_COUNT_OFFSET}], 0x{count:X}",
        f"mov qword ptr [rcx + {_B_OFFSET}], 0",
        "pop r11", "pop r10", "pop r9", "pop r8",
        "pop rdx", "pop rcx", "pop rax",
        "popfq",
    ])


def _check_stub_arguments(sink, block_rva, count, resume_rva):
    """Refuse arguments whose stub would be wrong, before assembling anything."""
    if not 0 <= block_rva <= 0xFFFFFFFF:
        raise PydbgError(
            f"block rva {block_rva!r} does not fit the record's u32 field")
    # `mov qword ptr [rcx + a], imm32` sign-extends, so a count above 2^31-1
    # would be written as a negative u64.
    if not 0 <= count < (1 << 31):
        raise PydbgError(f"instruction count {count!r} does not fit imm32")
    if not 0 <= resume_rva <= 0xFFFFFFFFFFFFFFFF:
        raise PydbgError(f"resume address {resume_rva!r} is not a u64")
    if not 0 <= sink.head_address <= 0xFFFFFFFFFFFFFFFF:
        raise PydbgError(f"head address {sink.head_address!r} is not a u64")
    if not 0 <= sink.address <= 0xFFFFFFFFFFFFFFFF:
        raise PydbgError(f"slot area {sink.address!r} is not a u64")
    if sink.capacity < 1 or sink.capacity & (sink.capacity - 1):
        raise PydbgError(
            f"ring capacity must be a power of two, got {sink.capacity!r}")
    if sink.slot_size < RECORD_SIZE:
        raise PydbgError(
            f"slot size {sink.slot_size!r} cannot hold a {RECORD_SIZE}-byte "
            f"record")


def build_stub(sink, block_rva, count, relocated, resume_rva):
    """A target-side detour stub that appends one BLOCK event per hit.

    Layout: save rax/rcx/rdx/r8-r11 and the flags -> `lock xadd` the slot
    counter -> write a 36-byte v1 record -> restore -> run `relocated` -> jump
    to `resume_rva`.

    Args:
        sink: the event buffer layout -- `address` (slot area), `head_address`
            (u32 counter), `capacity` (power of two) and `slot_size` (>= the
            record). EventBuffer (P31) is the real one.
        block_rva: the block start, written to the record's `rva` field as an
            RVA, not an address.
        count: the block's instruction count, written to `a`.
        relocated: the 5-byte prefix run from `relocate_prefix`, already
            rewritten for `STUB_PROLOGUE_SIZE` bytes into this stub.
        resume_rva: the address to jump back to -- module base + block_rva + 5.
            It is named for what the caller derives it from, but the stub needs
            the absolute address: it was built without knowing where it lives,
            and the jump-back is `jmp qword ptr [rip+0]` with the value inlined.

    Raises:
        PydbgError: keystone is missing, or the arguments cannot be encoded
            into the stub without changing its shape.
    """
    _check_stub_arguments(sink, block_rva, count, resume_rva)
    prologue = _assemble(_prologue_source(sink, block_rva, count))
    if len(prologue) != STUB_PROLOGUE_SIZE:
        raise PydbgError(
            f"keystone encoded the stub prologue in {len(prologue)} bytes, not "
            f"the {STUB_PROLOGUE_SIZE} the relocated prefix was addressed for")
    return prologue + bytes(relocated) + _ABSOLUTE_JUMP + struct.pack(
        "<Q", resume_rva)
