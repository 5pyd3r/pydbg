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
