"""Thread-safe patching: swing the target's threads, then write the bytes.

The target is live: between "the block plan says this block is ours" and "the
bytes are written", another thread can be executing inside those same bytes, and
a torn instruction is not recoverable. The protocol is the one spec §12.4 names:
suspend every target thread, check each RIP, then write -- and resume every
thread that was suspended on every path, refusal included.

`install_patch` hands back an `InstalledPatch` record and `uninstall_patch`
consumes it. The record, not state hidden on the debugger, is what says which
bytes are ours: installing over a changed pre-image is refused, and a patch
whose bytes changed under us is reported on uninstall, never overwritten.

Everything reaches the target through the debugger facade the caller passes;
this module never imports `_pydbg`.
"""

from dataclasses import dataclass

from ..exceptions import PydbgError


# The protection a code page is made writable with for the length of a write.
_PAGE_EXECUTE_READWRITE = 0x40

# The prefix of the warning a changed byte produces. A caller that treats
# "still installed" differently from "restored" keys on this, because the bytes
# may still be a detour that points into the stub region.
BYTES_CHANGED = "bytes changed under us"

# What one install wrote and displaced. The record travels from
# `install_patch` to `uninstall_patch`, so uninstall needs no hidden state on
# the debugger and no "same debugger object" contract (ticket 35 item 2).


@dataclass(frozen=True)
class InstalledPatch:
    """One patch known to be in the target.

    Attributes:
        address: where the patch was written, an absolute address (the window
            it opens is absolute even though the plan speaks RVAs).
        patch: the bytes installed.
        original: the full pre-image the patch displaced; restoring it puts
            every byte back, including the tail a short patch never touched.
        warnings: cleanup failures from the install (a thread that could not be
            resumed, a page protection that stayed writable). The write landed;
            these are what did not.
    """

    address: int
    patch: bytes
    original: bytes
    warnings: tuple = ()


class TargetBusy(PydbgError):
    """The patch window is not safe to rewrite right now.

    Refusing is the point: a thread whose RIP is inside the bytes about to
    change would execute a torn instruction, and stepping it out of the way is
    guesswork the spec refuses. The same answer covers a thread that cannot be
    suspended or whose context cannot be read -- without its RIP there is no
    way to prove the window is clear -- and a pre-image the target no longer
    has, because the bytes belong to someone else.

    Attributes:
        address: the patch address the caller asked for. It is an absolute
            target address, because that is what RIP is; a block plan speaks
            RVAs, and the caller converts once, at the install boundary.
        tid: the thread responsible, when one is known.
        warnings: cleanup failures collected while unwinding, so a caller that
            catches this still gets an honest report of unresolved resumes.
    """

    def __init__(self, message, address=None, tid=None):
        self.address = address
        self.tid = tid
        self.warnings = ()
        super().__init__(message)


def _thread_ids(dbg):
    """The target's current thread ids.

    Enumeration failure propagates: an empty list would silently turn the
    window check off, which is the one thing this protocol must not do.
    """
    return [thread['tid'] for thread in dbg.enumerate_threads()]


def _open_thread(dbg, tid, address):
    """Open a thread for suspension, or refuse with `TargetBusy`."""
    try:
        return dbg.open_thread(tid)
    except (PydbgError, OSError) as exc:
        raise TargetBusy(
            f"target busy: cannot open tid={tid}: {exc}",
            address=address, tid=tid)


def _close_thread(dbg, handle):
    """Close a thread handle, ignoring a failed close of a dead thread."""
    try:
        dbg.close_handle(handle)
    except (PydbgError, OSError):
        pass


def _suspend_all(dbg, address, suspended):
    """Suspend every target thread, appending `(tid, handle)` to `suspended`.

    A suspend that fails refuses the patch: continuing with fewer suspended
    threads would check a window that other threads can still walk into. The
    handle opened for the failing thread is closed here; every earlier
    suspension is in `suspended` and is resumed by the caller's `finally`.
    """
    for tid in _thread_ids(dbg):
        handle = _open_thread(dbg, tid, address)
        try:
            dbg.suspend_thread(handle)
        except (PydbgError, OSError) as exc:
            _close_thread(dbg, handle)
            raise TargetBusy(
                f"target busy: cannot suspend tid={tid}: {exc}",
                address=address, tid=tid)
        suspended.append((tid, handle))


def _check_window(dbg, address, size, suspended):
    """Refuse when a suspended thread's RIP is inside `[address, address+size)`.

    Every thread is suspended before any context is read, so a thread cannot
    move into the window between its own check and the write.
    """
    end = address + size
    for tid, handle in suspended:
        try:
            context = dbg.get_registers(handle)
        except (PydbgError, OSError) as exc:
            raise TargetBusy(
                f"target busy: cannot read the context of tid={tid}: {exc}",
                address=address, tid=tid)
        rip = context.get('rip')
        if rip is None:
            # x64 only (§12.1): a context without RIP cannot be proved clear.
            raise TargetBusy(
                f"target busy: tid={tid} has no RIP to check",
                address=address, tid=tid)
        if address <= rip < end:
            raise TargetBusy(
                f"target busy: thread {tid} is at 0x{rip:X}, inside "
                f"[0x{address:X}, 0x{end:X})", address=address, tid=tid)


def _write_protected(dbg, address, data):
    """Write `data` at `address`, restoring the page protection whatever happens.

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
    old_protect = dbg.protect_memory(
        address, len(data), _PAGE_EXECUTE_READWRITE)
    try:
        dbg.write_memory(address, data)
    except BaseException:
        try:
            dbg.protect_memory(address, len(data), old_protect)
        except (PydbgError, OSError):
            pass
        raise
    try:
        dbg.protect_memory(address, len(data), old_protect)
    except (PydbgError, OSError) as exc:
        return f"page protection at 0x{address:X}: {exc}"
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


def _run_suspended(dbg, address, size, action):
    """Suspend all threads, check the window, run `action`, resume all.

    The resume sits in a `finally` *inside* the outer `except`, so it runs on
    every path; the outer handler then attaches the cleanup warnings to a
    `TargetBusy` before re-raising it with its original traceback.
    """
    warnings = []
    suspended = []
    try:
        try:
            _suspend_all(dbg, address, suspended)
            _check_window(dbg, address, size, suspended)
            warning = action()
            if warning is not None:
                warnings.append(warning)
        finally:
            _resume_all(dbg, suspended, warnings)
    except TargetBusy as exc:
        exc.warnings = tuple(warnings)
        raise
    return tuple(warnings)


def install_patch(dbg, address, patch, *, original):
    """Write `patch` at `address`, if `original` is still what is there.

    `address` is the block's absolute address in the target (module base plus
    the block RVA): a block plan speaks RVAs, an install is a VA, because the
    RIP window it opens is absolute.

    `original` is the pre-image the caller expects: the bytes this patch is
    allowed to replace. The bytes are read back under the suspended window and
    compared with it; a mismatch is refused with `TargetBusy`, never written
    over, because it may be another owner's detour or breakpoint (ticket 32).
    A patch longer than its pre-image is refused too: the record could not
    restore what it displaced.

    What was written comes back as an `InstalledPatch`. The record, not state
    hidden on the debugger, is what `uninstall_patch` verifies against.

    Returns:
        InstalledPatch: the record of a completed write. Its `warnings` holds
        cleanup failures -- a thread that could not be resumed, a page
        protection that stayed writable -- reported rather than raised because
        the bytes are already in.

    Raises:
        TargetBusy: a thread is inside `[address, address + len(patch))`, the
            threads could not be enumerated/suspended/read, or the pre-image
            changed. Its `tid` names the blocker (when known), and its
            `warnings` holds any cleanup failures.
        PydbgError: the write (or the protection change around it) failed, or
            the patch/pre-image arguments cannot be honoured.
    """
    patch = bytes(patch)
    original = bytes(original)
    if not patch:
        raise PydbgError("cannot install an empty patch")
    if not original:
        raise PydbgError("cannot install over an empty pre-image")
    if len(patch) > len(original):
        raise PydbgError(
            f"patch is {len(patch)} bytes but its pre-image is only "
            f"{len(original)}; a restore could not cover it")

    def write():
        current = bytes(dbg.read_memory(address, len(original)))
        if current != original:
            raise TargetBusy(
                f"{BYTES_CHANGED} at 0x{address:X}: expected "
                f"{original.hex()}, found {current.hex()}", address=address)
        return _write_protected(dbg, address, patch)

    warnings = _run_suspended(dbg, address, len(patch), write)
    return InstalledPatch(address=address, patch=patch, original=original,
                          warnings=warnings)


def uninstall_patch(dbg, installed):
    """Restore `installed.original`, but only when the bytes are still ours.

    The bytes are read back and compared before anything is suspended or
    written. "Ours" is the run `installed.patch` + the untouched tail of
    `installed.original`, so a short patch (one INT3 over five bytes) is
    verified by its own length and restores all five. A mismatch -- another
    owner, or the target itself, wrote over the detour -- is reported as a
    warning beginning `"bytes changed under us"` and nothing is written,
    because restoring blindly would erase that change.

    "Already `original`" is the provable no-op: no warnings, no writes, no
    thread suspension.

    When the bytes still match, the restore runs through the same
    suspend-all/check-RIP/write/resume protocol as `install_patch`, because a
    thread can be executing inside the bytes about to be restored.

    Returns:
        tuple[str, ...]: cleanup warnings, empty on a clean restore. A changed
        byte returns one `"bytes changed under us ..."` warning and writes
        nothing; thread resume and protection failures are reported as on
        install.

    Raises:
        TargetBusy: a thread is inside `[address, address + len(original))`, or
            the threads could not be suspended or read. `warnings` holds
            cleanup failures.
        PydbgError: the read-back or the write failed, or the record itself is
            not restorable.
    """
    address = installed.address
    patch = bytes(installed.patch)
    original = bytes(installed.original)
    if not patch:
        raise PydbgError("cannot uninstall a record with an empty patch")
    if not original:
        raise PydbgError("cannot uninstall an empty patch")
    if len(patch) > len(original):
        raise PydbgError(
            f"recorded patch is {len(patch)} bytes but its original is only "
            f"{len(original)}")
    current = bytes(dbg.read_memory(address, len(original)))
    # The install may have written fewer bytes than `original` covers (a
    # one-byte placeholder over five original bytes): the installed prefix
    # must still be there, and the untouched tail must still be `original`'s.
    expected = patch + original[len(patch):]
    if current == original:
        return ()                 # already restored; nothing to write
    if current != expected:
        return (f"{BYTES_CHANGED} at 0x{address:X}: expected "
                f"{expected.hex()}, found {current.hex()}",)

    def restore():
        return _write_protected(dbg, address, original)

    return _run_suspended(dbg, address, len(original), restore)
