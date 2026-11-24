"""Basic-block detours: the 5 bytes that get displaced, and the stub that runs them.

A detour at a block entry overwrites five bytes with an `E9 rel32`. Those five
bytes are one long instruction or a few short ones, and they have to keep their
meaning at their new address:

- a RIP-relative operand's `disp32` is relative to the end of *that*
  instruction, so it must be rewritten for the stub (spec §12.3);
- a relative branch cannot be moved without rewriting its displacement, and the
  spec refuses rel8/rel32 rewriting outright — so a prefix containing one is
  refused rather than copied wrong (§12.6).

The relocation half is a pure function of decoded instructions and addresses:
no process memory, no threads, no debugger. `build_stub` assembles its prologue
with keystone (an optional extra). The install half (`install_patch`,
`uninstall_patch`) does touch a live target, but only through the debugger
facade it is handed — this module never imports `_pydbg`, so importing it stays
extension-free (ADR-0001).
"""

import struct
from dataclasses import dataclass

from ..exceptions import PydbgError
from ..patch.assembler import Assembler
from ..patch.encoding import build_abs_jmp

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


# ── thread-safe install / uninstall ─────────────────────────────
#
# The target is live: between "the block plan says this block is ours" and "the
# five bytes are written", another thread can be executing inside those same
# bytes, and a torn instruction is not recoverable. The protocol is the one
# spec §12.4 names: suspend every target thread, check each RIP, then write --
# and resume every thread that was suspended on every path, refusal included.

# The protection a code page is made writable with for the length of a write.
_PAGE_EXECUTE_READWRITE = 0x40

# What each install wrote, kept on the debugger it wrote through:
# `uninstall_patch` is handed only the bytes to restore, so without this it
# could not tell "still our detour" from "someone rewrote the bytes under us".
# The ticket's signature is kept; the record lives on the caller's debugger and
# goes away with it. The name is private to this module.
_RECORDS_ATTR = '_bbl_installed_patches'


def _records_for(dbg):
    """The `{address: patch bytes}` record for `dbg`, created on first use.

    Returns None for a debugger-shaped object that refuses attributes: install
    still works, and uninstall falls back to only the provable no-op case.
    """
    records = getattr(dbg, _RECORDS_ATTR, None)
    if records is None:
        records = {}
        try:
            setattr(dbg, _RECORDS_ATTR, records)
        except (AttributeError, TypeError):
            return None
    return records


def _installed_at(dbg, rva):
    """What install recorded for `rva`, or None when there is no record."""
    records = getattr(dbg, _RECORDS_ATTR, None)
    return None if records is None else records.get(rva)


class TargetBusy(PydbgError):
    """The patch window is not safe to rewrite right now.

    Refusing is the point: a thread whose RIP is inside the bytes about to
    change would execute a torn instruction, and stepping it out of the way is
    guesswork the spec refuses. The same answer covers a thread that cannot be
    suspended or whose context cannot be read -- without its RIP there is no
    way to prove the window is clear.

    Attributes:
        rva: the patch address the caller asked for (named per the ticket; it
            is an absolute target address, because that is what RIP is).
        tid: the thread responsible, when one is known.
        warnings: cleanup failures collected while unwinding, so a caller that
            catches this still gets an honest report of unresolved resumes.
    """

    def __init__(self, message, rva=None, tid=None):
        self.rva = rva
        self.tid = tid
        self.warnings = ()
        super().__init__(message)


def _thread_ids(dbg):
    """The target's current thread ids.

    Enumeration failure propagates: an empty list would silently turn the
    window check off, which is the one thing this protocol must not do.
    """
    return [thread['tid'] for thread in dbg.enumerate_threads()]


def _open_thread(dbg, tid, rva):
    """Open a thread for suspension, or refuse with `TargetBusy`."""
    try:
        return dbg.open_thread(tid)
    except (PydbgError, OSError) as exc:
        raise TargetBusy(
            f"target busy: cannot open tid={tid}: {exc}", rva=rva, tid=tid)


def _close_thread(dbg, handle):
    """Close a thread handle, ignoring a failed close of a dead thread."""
    try:
        dbg.close_handle(handle)
    except (PydbgError, OSError):
        pass


def _suspend_all(dbg, rva, suspended):
    """Suspend every target thread, appending `(tid, handle)` to `suspended`.

    A suspend that fails refuses the patch: continuing with fewer suspended
    threads would check a window that other threads can still walk into. The
    handle opened for the failing thread is closed here; every earlier
    suspension is in `suspended` and is resumed by the caller's `finally`.
    """
    for tid in _thread_ids(dbg):
        handle = _open_thread(dbg, tid, rva)
        try:
            dbg.suspend_thread(handle)
        except (PydbgError, OSError) as exc:
            _close_thread(dbg, handle)
            raise TargetBusy(
                f"target busy: cannot suspend tid={tid}: {exc}",
                rva=rva, tid=tid)
        suspended.append((tid, handle))


def _check_window(dbg, rva, size, suspended):
    """Refuse when a suspended thread's RIP is inside `[rva, rva + size)`.

    Every thread is suspended before any context is read, so a thread cannot
    move into the window between its own check and the write.
    """
    end = rva + size
    for tid, handle in suspended:
        try:
            context = dbg.get_registers(handle)
        except (PydbgError, OSError) as exc:
            raise TargetBusy(
                f"target busy: cannot read the context of tid={tid}: {exc}",
                rva=rva, tid=tid)
        rip = context.get('rip')
        if rip is None:
            # x64 only (§12.1): a context without RIP cannot be proved clear.
            raise TargetBusy(
                f"target busy: tid={tid} has no RIP to check", rva=rva, tid=tid)
        if rva <= rip < end:
            raise TargetBusy(
                f"target busy: thread {tid} is at 0x{rip:X}, inside "
                f"[0x{rva:X}, 0x{end:X})", rva=rva, tid=tid)


def _write_protected(dbg, rva, data):
    """Write `data` at `rva`, restoring the page protection whatever happens.

    Same pattern as `breakpoint/software.py:_write_protected`: the restore is
    attempted on the write's failure path too, so a failed write cannot leave
    the page writable, and a restore that fails after a successful write is
    returned as a warning rather than raised -- the bytes are in, and the
    caller should know the page is still writable without losing that fact.

    Returns:
        str | None: a warning when the write landed but the protection did not
        come back; None when both succeeded.

    Raises:
        PydbgError: the write itself failed.
    """
    old_protect = dbg.protect_memory(rva, len(data), _PAGE_EXECUTE_READWRITE)
    try:
        dbg.write_memory(rva, data)
    except BaseException:
        try:
            dbg.protect_memory(rva, len(data), old_protect)
        except (PydbgError, OSError):
            pass
        raise
    try:
        dbg.protect_memory(rva, len(data), old_protect)
    except (PydbgError, OSError) as exc:
        return f"page protection at 0x{rva:X}: {exc}"
    return None


def _resume_all(dbg, suspended, warnings):
    """Resume, in reverse, every thread this call suspended.

    A failed resume is not swallowed: the thread stays suspended, and a target
    with a frozen thread is not "patched successfully". It becomes a warning
    because the other threads still resume and the write already succeeded.
    """
    for tid, handle in reversed(suspended):
        try:
            dbg.resume_thread(handle)
        except (PydbgError, OSError) as exc:
            warnings.append(f"thread {tid}: {exc}")
        finally:
            _close_thread(dbg, handle)


def _run_suspended(dbg, rva, size, action):
    """Suspend all threads, check the window, run `action`, resume all.

    The resume sits in a `finally` *inside* the outer `except`, so it runs on
    every path; the outer handler then attaches the cleanup warnings to a
    `TargetBusy` before re-raising it with its original traceback.
    """
    warnings = []
    suspended = []
    try:
        try:
            _suspend_all(dbg, rva, suspended)
            _check_window(dbg, rva, size, suspended)
            warning = action()
            if warning is not None:
                warnings.append(warning)
        finally:
            _resume_all(dbg, suspended, warnings)
    except TargetBusy as exc:
        exc.warnings = tuple(warnings)
        raise
    return tuple(warnings)


def install_patch(dbg, rva, patch):
    """Write `patch` at `rva`, with every other thread provably out of the way.

    `rva` is the block's absolute address in the target (module base plus the
    block RVA): the RIP window it opens is absolute, so the caller derives it
    from the plan's RVA rather than passing the module-relative value.

    What was written is recorded on `dbg` under a private attribute, keyed by
    address. `uninstall_patch` uses that record to prove the bytes it finds are
    still this detour before restoring the originals; the record is dropped by
    a successful uninstall.

    Returns:
        tuple[str, ...]: cleanup warnings, empty on a clean install. A failed
        resume is reported as `"thread <tid>: <reason>"` rather than raised,
        because the write may already have succeeded and the other threads
        were resumed.

    Raises:
        TargetBusy: a thread is inside `[rva, rva + len(patch))`, or the
            threads could not be enumerated/suspended/read. Its `tid` names
            the blocker, and its `warnings` holds any cleanup failures.
        PydbgError: the write (or the protection change around it) failed.
    """
    patch = bytes(patch)
    if not patch:
        raise PydbgError("cannot install an empty patch")
    records = _records_for(dbg)

    def write():
        warning = _write_protected(dbg, rva, patch)
        if records is not None:
            records[rva] = patch
        return warning

    return _run_suspended(dbg, rva, len(patch), write)


def uninstall_patch(dbg, rva, original):
    """Restore `original` at `rva`, but only when the bytes are still ours.

    The bytes are read back and compared *before* anything is suspended or
    written. "Ours" means the patch `install_patch` recorded for this address:
    the caller passes the bytes to restore (`original`), not the patch, so the
    installed bytes come from that record. A mismatch -- another owner, or the
    target itself, wrote over the detour -- is reported as a warning beginning
    `"bytes changed under us"` and nothing is written, because restoring
    blindly would erase that change.

    Without a record (a direct call, or a new debugger) the only provable
    state is "the bytes already are `original`": that returns no warnings and
    writes nothing. Anything else is reported as "bytes changed under us"
    rather than overwritten.

    When the bytes still match, the restore runs through the same
    suspend-all/check-RIP/write/resume protocol as `install_patch`, because a
    thread can be executing inside the bytes about to be restored.

    Returns:
        tuple[str, ...]: cleanup warnings, empty on a clean restore. A changed
        byte returns one `"bytes changed under us ..."` warning and writes
        nothing; thread resume and protection failures are reported as on
        install.

    Raises:
        TargetBusy: a thread is inside `[rva, rva + len(original))`, or the
            threads could not be suspended or read. `warnings` holds cleanup
            failures.
        PydbgError: the read-back or the write failed.
    """
    original = bytes(original)
    if not original:
        raise PydbgError("cannot uninstall an empty patch")
    current = bytes(dbg.read_memory(rva, len(original)))
    expected = _installed_at(dbg, rva)
    if expected is None:
        expected = original
    # The install may have written fewer bytes than `original` covers (a
    # one-byte placeholder over five original bytes): the installed prefix
    # must still be there, and the untouched tail must still be `original`'s.
    if len(original) < len(expected):
        return (f"bytes changed under us at 0x{rva:X}: the recorded patch is "
                f"{len(expected)} bytes but only {len(original)} could be read",)
    expected_run = expected + original[len(expected):]
    if current != expected_run:
        return (f"bytes changed under us at 0x{rva:X}: expected "
                f"{expected_run.hex()}, found {current.hex()}",)
    if current == original:
        return ()                 # already restored; nothing to write
    records = getattr(dbg, _RECORDS_ATTR, None)

    def restore():
        warning = _write_protected(dbg, rva, original)
        if records is not None:
            records.pop(rva, None)
        return warning

    return _run_suspended(dbg, rva, len(original), restore)


# ── orchestration ───────────────────────────────────────────────
#
# The plan is a record, not a live object: it says where a block is, how far it
# runs, which instructions it holds and whether the bytes a detour would
# displace can be executed from the stub. `install()` re-reads the same facts
# from the decoder rather than trusting a plan someone may have edited, which
# is why a block that was planned as unrelocatable still gets its exact reason
# from `relocate_prefix` instead of a generic "not planned".

# A ceiling on the instructions one explicit block start may decode. A block
# ends at a branch or a return, so this only trips on a decoder that never
# terminates; refusing to loop forever is worth more than the exact number.
_MAX_BLOCK_INSTRUCTIONS = 4096

# How far from the module a stub may land. A 5-byte E9 is a rel32 jump, so the
# stub has to be within ±2GB; the scan window is the frozen instrumenter's.
_RELOC_WINDOW = 0x7F000000
# VirtualAllocEx rounds a hint down to the allocation granularity, so a hint
# inside an occupied page fails with ERROR_INVALID_ADDRESS; round up instead.
_ALLOC_GRANULARITY = 0x10000
_MEM_FREE = 0x10000
_MEM_COMMIT_RESERVE = 0x3000


def _stub_hint(region, near, size):
    """The allocation hint inside `region` for `size` bytes, or None.

    Kept separate from the Win32 call so the placement rule -- aligned to the
    allocation granularity, inside the free region, inside ±2GB of the module
    -- can be tested without a target. `region` is a `regions_handle` dict.
    """
    base = region.get('base_address', 0)
    span = region.get('region_size', 0)
    if span < size:
        return None
    hint = (base + _ALLOC_GRANULARITY - 1) & ~(_ALLOC_GRANULARITY - 1)
    high = near + _RELOC_WINDOW
    if hint + size > high:
        # The window is the hard limit: pull the hint back, even if that
        # makes it unaligned (VirtualAllocEx rounds the hint down itself).
        hint = high - size
        if hint < base:
            return None
    if hint + size > base + span:
        return None
    return hint


def alloc_near(dbg, near, size):
    """Allocate `size` RWX bytes within ±2GB of `near`; return the address.

    Reimplemented here rather than reusing the frozen
    `Instrumenter._alloc_near` (§12.1): the frozen one allocates for the LLVM
    trampoline and must not be modified. The scan is the same idea — walk the
    target's regions, take the first MEM_FREE one large enough, and ask for a
    64KB-aligned hint inside it — because that is the placement rule the E9
    detour requires.

    `_pydbg` is imported lazily so importing this module stays extension-free
    (ADR-0001); only a caller with a live target reaches this function.

    Raises:
        PydbgError: the region walk failed, or no free region inside the
            window could satisfy the allocation.
    """
    from .. import _pydbg

    handle = dbg._session.process_handle
    low = (near - _RELOC_WINDOW) & ~(_ALLOC_GRANULARITY - 1)
    if low < _ALLOC_GRANULARITY:
        low = _ALLOC_GRANULARITY
    high = near + _RELOC_WINDOW
    try:
        regions = dbg.memory.regions_handle(handle, low, high)
    except (PydbgError, OSError) as exc:
        raise PydbgError(
            f"cannot scan for stub memory near 0x{near:X}: {exc}") from exc

    for region in regions:
        if region.get('state') != _MEM_FREE:
            continue
        hint = _stub_hint(region, near, size)
        if hint is None:
            continue
        try:
            result = _pydbg.virtual_alloc_ex(
                handle, hint, size, _MEM_COMMIT_RESERVE,
                _PAGE_EXECUTE_READWRITE)
        except OSError:
            continue
        address = result.get('base_address', 0)
        if address:
            return address

    raise PydbgError(
        f"no free region within ±2GB of 0x{near:X} for {size} bytes")


def _ring_capacity(max_events):
    """The smallest power of two that can hold `max_events` records.

    EventBuffer indexes slots with `count & (capacity - 1)`, so the capacity
    must be a power of two. Sizing it from `max_events` means a single
    `events()` call can return the whole budget without the ring wrapping
    first; `events()` still truncates to exactly `max_events`.
    """
    if max_events is None or max_events < 1:
        return 1
    return 1 << (max_events - 1).bit_length()


@dataclass(frozen=True)
class BlockPlan:
    """One block a detour would be placed on, and how much it would displace.

    Attributes:
        rva: the block entry, module-relative.
        span: bytes from `rva` to the end of the last instruction the decoder
            gave for the block. 0 when nothing decoded there.
        instruction_rvas: the block's instruction addresses, module-relative,
            ascending. The record's `a` field carries the length of this tuple.
        prefix_size: bytes the detour displaces -- the shortest run of whole
            instructions covering `DETOUR_SIZE` bytes. 0 means the block is
            shorter than a detour (or nothing decoded), so there is no prefix
            to take; such a block is still planned and refused at install time.
        relocatable: whether `prefix_size` bytes can run from the stub
            unchanged. False when there is no prefix, or when a branch/return
            sits in it (rewriting rel8/rel32 is out of scope, spec §12.6).
    """

    rva: int
    span: int
    instruction_rvas: tuple
    prefix_size: int
    relocatable: bool


@dataclass(frozen=True)
class InstallReport:
    """What one `BblInstrumenter.install()` managed to place.

    `installed` holds the RVAs of the blocks whose detour is in the target;
    `refused` holds `(rva, reason)` for every other planned block, so
    `len(installed) + len(refused)` is the plan size and no block is silently
    skipped. `warnings` collects cleanup that did not raise -- a thread that
    could not be resumed, a page protection that stayed writable, an event
    buffer released while some detours remain.
    """

    installed: tuple = ()
    refused: tuple = ()
    warnings: tuple = ()


class BblInstrumenter:
    """Plan, install, read and remove BBL detours in one module.

    The sequence (the target should be paused while `plan()` reads its image)::

        instrumenter = BblInstrumenter(dbg)
        instrumenter.plan()               # () means "not analysable"
        report = instrumenter.install()   # per-block success and refusals
        dbg.continue_event(...)           # let the target run
        ...                               # stop it again at any debug event
        events = instrumenter.events()    # drain the target-side ring
        warnings = instrumenter.uninstall()

    Nothing is automatic. The stub appends to a target-side ring, so events can
    only be drained at a stop point; `events()` does not stop the target and
    `uninstall()` does not disarm it. The caller decides when the target is
    quiet, reads, and then restores. `uninstall()` leaves the detours in place
    when a thread is parked inside one, because freeing the stub region under a
    live detour would turn a refused cleanup into a crash.

    Only x64 is supported (spec §12.1): the thread window check needs RIP.
    """

    def __init__(self, dbg, module=None, *, result=None, blocks=None,
                 max_blocks=4096, max_events=100_000):
        """Bind the instrumenter to a debugger and one module.

        Args:
            dbg: A `Debugger` with a target created or attached.
            module: A module dict from `dbg.enum_modules()`, a
                `(base_address, size)` tuple, or None for the main module.
            result: A precomputed `AnalysisResult`. None analyzes the module
                with `analyze_process` on first `plan()`; a caller that
                already has the result avoids a second sweep.
            blocks: An explicit iterable of block-start RVAs. When given it
                replaces the CFG-derived block list; the analysis (or
                `result`) is still used to decode each block and to discard
                starts outside an executable section.
            max_blocks: Never plan more block starts than this.
            max_events: The most events `events()` returns per call. The ring
                is sized to the next power of two at or above it, so a burst
                between two reads is retained up to that size.
        """
        self.dbg = dbg
        self.module = module
        self.max_blocks = max_blocks
        self.max_events = max_events
        self._result = result
        self._block_starts = None if blocks is None else tuple(blocks)
        self._analysis = None
        self._base = None
        self._plans = None
        self._buffer = None
        self._stub_region = None
        self._report = None
        # absolute address -> the original bytes install displaced, in install
        # order. uninstall_patch needs those bytes; it restores only when the
        # detour is still what it finds.
        self._originals = {}

    # ── planning ───────────────────────────────────────────────

    def plan(self):
        """The blocks this instrumenter would detour, sorted by RVA.

        The block starts come from the same CFG walk as `BblTracer.plan()`:
        every recovered function's `cfg_of`, blocks with instructions, filtered
        to executable sections and capped by `max_blocks`. What the tracer threw
        away -- the block's span, its instruction list, the detour prefix and
        whether that prefix can move -- is kept here, because install needs it.

        `blocks=` replaces the block starts with an explicit list; the analysis
        is still consulted for decoding and the exec filter. Duplicates are
        collapsed and the result is sorted.

        A module whose analysis fails is not an exception: the answer is `()`,
        "nothing can be planned here", the same contract `BblTracer.plan()`
        offers. The plan is computed once; later calls return the same tuple.
        """
        if self._plans is not None:
            return self._plans
        result = self._analysis_of()
        if result is None:
            self._plans = ()
            return self._plans

        plans = {}
        if self._block_starts is not None:
            for start in self._block_starts:
                if len(plans) >= self.max_blocks:
                    break
                if start in plans or not result.image.is_exec(start):
                    continue
                instruction_rvas, instructions = self._decode_block(result, start)
                plans[start] = self._make_plan(
                    start, instruction_rvas, instructions)
        else:
            from ..analysis.cfg import cfg_of

            for function in result.functions.functions():
                if len(plans) >= self.max_blocks:
                    break
                cfg = cfg_of(result, function.rva)
                if cfg is None:
                    continue
                for block in cfg.blocks.values():
                    if len(plans) >= self.max_blocks:
                        break
                    if block.rva in plans or not block.instructions:
                        continue        # undecodable: nothing to displace
                    if not result.image.is_exec(block.rva):
                        continue        # data, not code
                    instructions = self._decode_rvas(result, block.instructions)
                    plans[block.rva] = self._make_plan(
                        block.rva, block.instructions, instructions)

        self._plans = tuple(plans[rva] for rva in sorted(plans))
        return self._plans

    def _analysis_of(self):
        """The analysis result, running one if the caller did not supply it."""
        if self._analysis is not None:
            return self._analysis
        if self._result is not None:
            self._analysis = self._result
            return self._analysis

        from ..analysis import analyze_process
        from ..trace import _shared

        module = _shared.find_module(self.dbg, self.module)
        if module is None:
            return None
        base, _ = _shared.module_region(module)
        if not base:
            return None
        self._base = base
        module_size = _shared.module_size(self.dbg, module)
        try:
            self._analysis = analyze_process(
                self.dbg._session, base, module_size=module_size)
        except (PydbgError, OSError, ValueError, struct.error):
            self._analysis = None
        return self._analysis

    @staticmethod
    def _decode_rvas(result, instruction_rvas):
        """Decode known instruction addresses, stopping at the first gap."""
        decoded = []
        for rva in instruction_rvas:
            instruction = result.decoder.decode_one(rva)
            if instruction is None:
                break
            decoded.append(instruction)
        return tuple(decoded)

    @staticmethod
    def _decode_block(result, start):
        """(instruction_rvas, instructions) for a block starting at `start`.

        Used for an explicit `blocks=` list, where the CFG does not already
        name the block's instructions. A call falls through (it returns); a
        branch or a return ends the block, which is the same rule
        `build_function_cfg` applies.
        """
        instruction_rvas = []
        instructions = []
        address = start
        while len(instructions) < _MAX_BLOCK_INSTRUCTIONS:
            instruction = result.decoder.decode_one(address)
            if instruction is None or instruction.size <= 0:
                break
            instruction_rvas.append(address)
            instructions.append(instruction)
            if instruction.is_ret or instruction.is_jmp:
                break
            address += instruction.size
        return tuple(instruction_rvas), tuple(instructions)

    @staticmethod
    def _make_plan(rva, instruction_rvas, instructions):
        """One BlockPlan from the decoded run at `rva`."""
        span = 0
        if instructions:
            last = instructions[-1]
            span = last.address + last.size - rva
        prefix_size = 0
        relocatable = False
        try:
            prefix = take_prefix(instructions, rva)
        except UnsupportedInstruction:
            pass                      # no prefix: planned, refused at install
        else:
            prefix_size = sum(instruction.size for instruction in prefix)
            relocatable = prefix_is_relocatable(prefix)
        return BlockPlan(rva=rva, span=span,
                         instruction_rvas=tuple(instruction_rvas),
                         prefix_size=prefix_size, relocatable=relocatable)

    # ── installing ─────────────────────────────────────────────

    def install(self):
        """Write one detour and one stub per relocatable block.

        The event ring and the stub region are allocated once for the whole
        instrumenter, not per block: every stub embeds the same ring addresses,
        and every detour has to reach its stub through a 5-byte E9.

        Each block is installed independently. A refused block -- a thread
        parked inside its window, a branch in its prefix, a block shorter than
        the detour, a thread enumeration that fails -- goes into
        `InstallReport.refused` with the exception's message, and the remaining
        blocks are still attempted. `len(installed) + len(refused)` is exactly
        the plan size. Failures of a shared resource (the ring, the stub
        region, a missing keystone) become one reason per block for the same
        reason: no planned block may be silently skipped.

        For each block, the displaced prefix is first copied out of the target
        (`read_memory`) and then overwritten with `E9 rel32` plus NOP padding
        up to the prefix length. The NOP padding matters: the stub resumes at
        `block + 5` (the record's shape), so the pad bytes are what carry
        execution across whatever remains of a multi-byte displaced instruction
        to `block + prefix_size`.

        Calling it twice returns the first report and writes nothing; call
        `uninstall()` between installs.

        Raises:
            PydbgError: only if a shared step fails in a way this method
                cannot describe per block; normally every failure is reported.
        """
        if self._report is not None:
            return self._report
        plans = self.plan()
        if not plans:
            self._report = InstallReport()
            return self._report

        refusals = {}
        base = self._module_base()
        if not base:
            for plan in plans:
                refusals[plan.rva] = (
                    f"no module base address for rva 0x{plan.rva:X}")
            return self._finish_report(plans, (), (), refusals)

        candidates = [plan for plan in plans if plan.relocatable]
        sink = None
        region = None
        warnings = []
        if candidates:
            if keystone is None:
                for plan in candidates:
                    refusals[plan.rva] = (
                        "keystone-engine is not installed: a BBL stub cannot "
                        "be assembled")
            else:
                from .event_buffer import EventBuffer

                try:
                    sink = EventBuffer(
                        self.dbg, capacity=_ring_capacity(self.max_events))
                except (PydbgError, OSError, ValueError) as exc:
                    for plan in plans:
                        refusals[plan.rva] = (
                            f"cannot allocate the event buffer: {exc}")
                    return self._finish_report(plans, (), (), refusals)

                stub_size = sum(STUB_PROLOGUE_SIZE + plan.prefix_size
                                + len(_ABSOLUTE_JUMP) + 8
                                for plan in candidates)
                try:
                    region = alloc_near(self.dbg, base, stub_size)
                except (PydbgError, OSError) as exc:
                    self._release_setup(sink, None, warnings)
                    for plan in plans:
                        refusals[plan.rva] = (
                            f"cannot allocate stub memory near the module: "
                            f"{exc}")
                    return self._finish_report(plans, (), warnings, refusals)

        installed = []
        originals = {}
        cursor = region
        for plan in plans:
            if plan.rva in refusals:
                continue
            try:
                instructions = self._decode_rvas(
                    self._analysis, plan.instruction_rvas)
                prefix = take_prefix(instructions, plan.rva)
                if not plan.relocatable:
                    # Let relocate_prefix name the branch and its RVA; its
                    # first check is the branch/return refusal. A plan that
                    # says "not relocatable" for another reason still refuses.
                    relocate_prefix(prefix, base)
                    raise UnsupportedInstruction(
                        plan.rva, '', 'the planned prefix cannot be relocated')
                if sink is None or cursor is None:
                    raise PydbgError(
                        'the event buffer or stub region was not allocated')
                stub_address = cursor
                relocated = relocate_prefix(prefix, stub_address)
                stub = build_stub(
                    sink, plan.rva, len(plan.instruction_rvas), relocated,
                    base + plan.rva + DETOUR_SIZE)
                self.dbg.write_memory(stub_address, stub)
                absolute = base + plan.rva
                original = bytes(self.dbg.read_memory(
                    absolute, len(relocated)))
                patch = build_abs_jmp(absolute, stub_address) + (
                    b"\x90" * (len(relocated) - DETOUR_SIZE))
                warnings.extend(install_patch(self.dbg, absolute, patch))
                installed.append(plan.rva)
                originals[absolute] = original
                cursor += len(stub)
            except (PydbgError, OSError) as exc:
                refusals[plan.rva] = str(exc) or exc.__class__.__name__
                warnings.extend(getattr(exc, 'warnings', ()))

        if not installed and (sink is not None or region is not None):
            # Nothing points at the shared allocations, so releasing them now
            # is safer than leaving a failed install holding target memory.
            self._release_setup(sink, region, warnings)
            self._originals = {}
            return self._finish_report(plans, (), warnings, refusals)

        self._buffer = sink
        self._stub_region = region
        self._originals = originals
        return self._finish_report(plans, installed, warnings, refusals)

    def _release_setup(self, sink, region, warnings):
        """Release the ring then the stub region, keeping what could not go.

        A failed release is not forgotten: the live object (or address) is
        stored back on `self` so `uninstall()` retries it, and the warning
        names it. On success the attribute is cleared, which is also how
        `uninstall()` decides whether the lifecycle is over.
        """
        if sink is not None:
            freed = sink.free()
            warnings.extend(f"{what}: {why}" for what, why in freed)
            self._buffer = None if not freed else sink
        if region is not None:
            try:
                self.dbg.memory.free_remote(region)
            except (PydbgError, OSError) as exc:
                warnings.append(f"stub region at 0x{region:X}: {exc}")
                self._stub_region = region
            else:
                self._stub_region = None

    def _finish_report(self, plans, installed, warnings, refusals):
        """Build the report in plan order and remember it."""
        refused = tuple((plan.rva, refusals[plan.rva])
                        for plan in plans if plan.rva in refusals)
        self._report = InstallReport(
            installed=tuple(installed),
            refused=refused,
            warnings=tuple(warnings))
        return self._report

    def _module_base(self):
        """The module's runtime base, or None when it cannot be resolved."""
        if self._base:
            return self._base
        from ..trace import _shared

        module = _shared.find_module(self.dbg, self.module)
        if module is None:
            return None
        base, _ = _shared.module_region(module)
        self._base = base or None
        return self._base

    # ── events and teardown ────────────────────────────────────

    def events(self):
        """The BLOCK records written since the previous call, oldest first.

        Drains `EventBuffer.read()` and truncates it to `max_events`. The
        records are returned as the v1 `TraceEvent`s the stub wrote: `kind` is
        BLOCK, `rva` the block start, `a` its instruction count, and `tid`/`ts`
        are 0 because the target-side stub cannot know either (spec §12.1).
        Callers must not read 0 as a real thread id.

        The target has to be stopped for this to be trustworthy: a running
        target can advance the ring's head between the header read and the slot
        read. Nothing here stops it.

        A budget of 0 returns nothing and leaves the ring untouched; after
        `uninstall()` the buffer is gone and the answer is `()`.
        """
        if self._buffer is None or self.max_events <= 0:
            return ()
        return tuple(self._buffer.read()[:self.max_events])

    def uninstall(self):
        """Restore the displaced bytes and release the shared allocations.

        Blocks are restored in install order. A block whose restore is refused
        (a thread inside its window, an unreadable thread context) keeps its
        detour and its original bytes, so a later call retries it; the stub
        region and the event ring are then NOT released, because every
        remaining detour still points into them. That warning is the last one,
        and it says the memory was kept.

        When every detour is gone the ring is freed and then the stub region.
        A failed release is reported as a warning and retried by a later call,
        never silently forgotten: the instrumenter still holds the address.

        Returns:
            tuple[str, ...]: cleanup warnings, in a stable order -- block
            warnings first (in install order), then the ring, then the stub
            region, then the "kept" notice. Empty when everything was clean.
        """
        if (not self._originals and self._buffer is None
                and self._stub_region is None):
            return ()

        warnings = []
        for absolute in list(self._originals):
            try:
                block_warnings = uninstall_patch(
                    self.dbg, absolute, self._originals[absolute])
            except (PydbgError, OSError) as exc:
                warnings.append(f"0x{absolute:X}: {exc}")
                warnings.extend(getattr(exc, 'warnings', ()))
                continue
            warnings.extend(block_warnings)
            del self._originals[absolute]

        if self._originals:
            warnings.append(
                'detours remain installed: stub region and event buffer kept')
            return tuple(warnings)

        self._release_setup(self._buffer, self._stub_region, warnings)
        if self._buffer is None and self._stub_region is None:
            # A later install() starts a fresh lifecycle.
            self._report = None
        return tuple(warnings)
