"""The target-side stub: save, append one BLOCK record, run the prefix, jump back.

`build_stub` assembles a fixed prologue with keystone (an optional extra), then
glues on the relocated prefix and an absolute jump back. The record it writes is
the trace v1 record, and its field offsets come from `trace.format` rather than
a local copy, so the writer and the trace reader cannot drift.

On x64 the stub is position-independent: the jump back is `jmp qword ptr
[rip+0]` with the target inlined, so `build_stub` never needs to know where it
will live. A 32-bit target has no RIP-relative form, so its jump back is
`jmp dword ptr [abs]` and the pointer it names is inline — that makes the stub
address part of the 32-bit contract (spec §12.1's three boundary differences).

Importing this module stays extension-free (ADR-0001): `trace.format` is pure
Python and keystone is optional (the assembler says which extra is missing).
"""

import struct

from ..exceptions import PydbgError
from ..patch.assembler import Assembler
from ..trace.format import (
    RECORD_A_OFFSET,
    RECORD_B_OFFSET,
    RECORD_RVA_OFFSET,
    RECORD_SIZE,
    RECORD_TID_OFFSET,
    RECORD_TS_OFFSET,
)
# The number the relocated prefix was addressed for; `build_stub` is the other
# side of that contract, so it checks the assembled prologue against it.
from .relocate import STUB_PROLOGUE_SIZE, stub_prologue_size

# keystone is a `patch` extra; the relocation half does not need it, and the
# stub builder says so rather than failing somewhere inside the assembler.
try:
    import keystone
except ImportError:                      # pragma: no cover - environment
    keystone = None

__all__ = [
    'STUB_JUMP_SIZE', 'STUB_JUMP_SIZES', 'STUB_PROLOGUE_SIZE', 'build_stub',
    'keystone', 'stub_jump_size', 'stub_prologue_size',
]

# `jmp qword ptr [rip+0]` on x64: the address follows the instruction, so the
# stub is position-independent. The same opcode in 32-bit mode is `jmp dword
# ptr [disp32]`, where the operand is absolute, so the four bytes after it name
# the inline pointer itself and the stub has to know where it lives.
_INDIRECT_JUMP = b"\xff\x25"
_ABSOLUTE_JUMP = _INDIRECT_JUMP + b"\x00\x00\x00\x00"
# What the jump-back occupies at the end of every stub: the indirect jump plus
# its inlined target -- eight bytes on x64, four on x86 (the x86 instruction's
# disp32 is the pointer's address, not extra bytes after it). Callers that size
# a stub region ask `stub_jump_size(arch)` instead of re-deriving the tail.
STUB_JUMP_SIZES = {32: len(_INDIRECT_JUMP) + 8, 64: len(_ABSOLUTE_JUMP) + 8}

# The x64 length under the name the frozen BBL path and its tests import.
STUB_JUMP_SIZE = STUB_JUMP_SIZES[64]


def stub_jump_size(arch):
    """The jump-back's length for `arch` (32 or 64)."""
    return STUB_JUMP_SIZES[32 if arch == 32 else 64]


def _assemble(code, arch):
    """Assemble for the target's architecture, or name the missing extra."""
    if keystone is None:
        raise PydbgError("keystone-engine not installed")
    return Assembler("x64" if arch == 64 else "x86").assemble(code)


def _prologue_source_x64(sink, block_rva, count):
    """The x64 prologue, as keystone source.

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
        f"mov dword ptr [rcx + {RECORD_RVA_OFFSET}], 0x{block_rva:X}",
        f"mov qword ptr [rcx + {RECORD_TS_OFFSET}], 0",
        f"mov qword ptr [rcx + {RECORD_A_OFFSET}], 0x{count:X}",
        f"mov qword ptr [rcx + {RECORD_B_OFFSET}], 0",
        "pop r11", "pop r10", "pop r9", "pop r8",
        "pop rdx", "pop rcx", "pop rax",
        "popfq",
    ])


def _prologue_source_x86(sink, block_rva, count):
    """The x86 prologue: the x64 shape with 32-bit registers and stores.

    The same rule applies for a different reason: a 32-bit target has no
    `movabs`, so `mov r32, imm32` (always five bytes) is the value-independent
    form, and the record's 64-bit fields are written as two 32-bit stores. The
    immediates that do stay absolute (rva and count) use `mov dword ptr
    [ecx + disp], imm32`, whose encoding has no shorter form.

    Registers used: eax (count, xadd operand), ebx (head pointer), ecx (slot),
    edx (scratch and a zero source). All are saved and restored, with the flags.
    """
    return "; ".join([
        # The flags `lock xadd` changes, and everything the stub clobbers.
        "pushfd",
        "push eax", "push ebx", "push ecx", "push edx",
        # count = the slot counter's old value, atomically.
        "mov eax, 1",
        f"mov ebx, 0x{sink.head_address:X}",
        "lock xadd dword ptr [ebx], eax",
        # slot = slot_area + (count & (capacity - 1)) * slot_size
        "mov ecx, eax",
        f"mov edx, 0x{sink.capacity - 1:X}",
        "and ecx, edx",
        f"mov edx, 0x{sink.slot_size:X}",
        "imul ecx, edx",
        f"mov edx, 0x{sink.address:X}",
        "add ecx, edx",
        "xor edx, edx",
        # One v1 BLOCK record, field by field: kind/tid, rva, ts, a, b. tid and
        # ts are not available in the target, so both are zero (spec §12.1).
        "mov dword ptr [ecx], 1",
        f"mov dword ptr [ecx + {RECORD_TID_OFFSET}], edx",
        f"mov dword ptr [ecx + {RECORD_RVA_OFFSET}], 0x{block_rva:X}",
        f"mov dword ptr [ecx + {RECORD_TS_OFFSET}], edx",
        f"mov dword ptr [ecx + {RECORD_TS_OFFSET + 4}], edx",
        f"mov dword ptr [ecx + {RECORD_A_OFFSET}], 0x{count:X}",
        f"mov dword ptr [ecx + {RECORD_A_OFFSET + 4}], edx",
        f"mov dword ptr [ecx + {RECORD_B_OFFSET}], edx",
        f"mov dword ptr [ecx + {RECORD_B_OFFSET + 4}], edx",
        "pop edx", "pop ecx", "pop ebx", "pop eax",
        "popfd",
    ])


def _prologue_source(sink, block_rva, count, arch):
    """The fixed prologue for `arch`, as keystone source."""
    if arch == 32:
        return _prologue_source_x86(sink, block_rva, count)
    return _prologue_source_x64(sink, block_rva, count)


def _check_stub_arguments(sink, block_rva, count, resume_rva, arch,
                          stub_address):
    """Refuse arguments whose stub would be wrong, before assembling anything."""
    if not 0 <= block_rva <= 0xFFFFFFFF:
        raise PydbgError(
            f"block rva {block_rva!r} does not fit the record's u32 field")
    # `mov qword ptr [rcx + a], imm32` sign-extends, so a count above 2^31-1
    # would be written as a negative u64.
    if not 0 <= count < (1 << 31):
        raise PydbgError(f"instruction count {count!r} does not fit imm32")
    if arch == 32:
        # A 32-bit target's addresses are 32-bit values in the stub's
        # immediates: anything wider would be silently truncated by keystone.
        for name, value in (("resume address", resume_rva),
                            ("head address", sink.head_address),
                            ("slot area", sink.address)):
            if not 0 <= value <= 0xFFFFFFFF:
                raise PydbgError(
                    f"{name} {value!r} is not a u32 for a 32-bit target")
        if stub_address is None:
            raise PydbgError(
                "a 32-bit stub needs its own address: its return jump reaches "
                "an absolute inline pointer and there is no RIP-relative form")
        if not 0 <= stub_address <= 0xFFFFFFFF:
            raise PydbgError(
                f"stub address {stub_address!r} is not a u32 for a 32-bit target")
    else:
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


def _return_jump(resume_rva, arch, stub_address, relocated_size):
    """The absolute jump back to `resume_rva`, in `arch`'s encoding.

    x64 inlines the target after `jmp qword ptr [rip+0]`, so it needs no
    address. x86's `jmp dword ptr [abs]` reads a pointer from an absolute
    address, so the inline dword is named by the stub's own address; the caller
    passes the address it is about to write the stub at.
    """
    if arch != 32:
        return _ABSOLUTE_JUMP + struct.pack("<Q", resume_rva)
    pointer = (stub_address + stub_prologue_size(arch) + relocated_size
               + len(_INDIRECT_JUMP) + 4)
    if not 0 <= pointer <= 0xFFFFFFFF:
        raise PydbgError(
            f"the 32-bit return jump's pointer at 0x{pointer:X} is not a u32")
    return (_INDIRECT_JUMP + struct.pack("<I", pointer)
            + struct.pack("<I", resume_rva))


def build_stub(sink, block_rva, count, relocated, resume_rva, *, arch=64,
               stub_address=None):
    """A target-side detour stub that appends one BLOCK event per hit.

    Layout: save the scratch registers and the flags -> `lock xadd` the slot
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
            rewritten for this stub's prologue.
        resume_rva: the absolute address to jump back to -- module base +
            block_rva + 5. The x64 stub inlines it and never needs to know
            where it lives; the 32-bit one cannot, see `stub_address`.
        arch: the target's architecture (32 or 64). It selects the prologue's
            registers and the jump-back's width (spec §12.1).
        stub_address: where the caller will write this stub. Required for a
            32-bit target, because its return jump names the inline pointer by
            absolute address; ignored on x64.

    Raises:
        PydbgError: keystone is missing, or the arguments cannot be encoded
            into the stub without changing its shape.
    """
    _check_stub_arguments(sink, block_rva, count, resume_rva, arch,
                          stub_address)
    prologue = _assemble(
        _prologue_source(sink, block_rva, count, arch), arch)
    expected = stub_prologue_size(arch)
    if len(prologue) != expected:
        raise PydbgError(
            f"keystone encoded the {arch}-bit stub prologue in "
            f"{len(prologue)} bytes, not the {expected} the relocated prefix "
            f"was addressed for")
    return (prologue + bytes(relocated)
            + _return_jump(resume_rva, arch, stub_address, len(relocated)))
