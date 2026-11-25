"""The target-side stub: save, append one BLOCK record, run the prefix, jump back.

`build_stub` assembles a fixed prologue with keystone (an optional extra), then
glues on the relocated prefix and an absolute jump back. The record it writes is
the trace v1 record, and its field offsets come from `trace.format` rather than
a local copy, so the writer and the trace reader cannot drift.

The stub is position-independent: the jump back is `jmp qword ptr [rip+0]` with
the target inlined, so `build_stub` never needs to know where it will live.

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
    RECORD_TS_OFFSET,
)
# The number the relocated prefix was addressed for; `build_stub` is the other
# side of that contract, so it checks the assembled prologue against it.
from .relocate import STUB_PROLOGUE_SIZE

# keystone is a `patch` extra; the relocation half does not need it, and the
# stub builder says so rather than failing somewhere inside the assembler.
try:
    import keystone
except ImportError:                      # pragma: no cover - environment
    keystone = None

# `jmp qword ptr [rip+0]`: the address follows the instruction, so the stub is
# position-independent and build_stub never needs to know where it will live.
_ABSOLUTE_JUMP = b"\xff\x25\x00\x00\x00\x00"
# What the jump-back occupies at the end of every stub: the six-byte indirect
# jump plus its inlined eight-byte target. Callers that size a stub region use
# this instead of re-deriving the tail.
STUB_JUMP_SIZE = len(_ABSOLUTE_JUMP) + 8


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
        f"mov dword ptr [rcx + {RECORD_RVA_OFFSET}], 0x{block_rva:X}",
        f"mov qword ptr [rcx + {RECORD_TS_OFFSET}], 0",
        f"mov qword ptr [rcx + {RECORD_A_OFFSET}], 0x{count:X}",
        f"mov qword ptr [rcx + {RECORD_B_OFFSET}], 0",
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
