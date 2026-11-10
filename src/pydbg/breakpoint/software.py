"""SoftwareBreakpointManager — int3 software breakpoints."""

from .. import _pydbg
from ..exceptions import BreakpointError
from .model import Breakpoint
from .outcome import HandleOutcome


class SoftwareBreakpointManager:
    """Manages int3 software breakpoints."""

    # Memory protection constants
    _PAGE_EXECUTE_READWRITE = 0x40

    _INT3 = b"\xcc"

    def __init__(self, session):
        self._s = session
        # Why the last hit could not be completed (read when handle_breakpoint_hit
        # answers DEGRADED).
        self.last_error = None
        # bp_ids whose INT3 is no longer in the target (see verify()).
        self.lost = set()

    def armed_state(self, bp_id):
        """Is the INT3 still in the target? True, False, or None.

        The three answers are genuinely different and verify() has to flatten
        two of them: False means the byte is there and it is not 0xCC (the
        target overwrote the breakpoint), None means the byte could not be
        read at all. verify() answers "is it intact" and calls both of the
        latter 'no'; read this one when the difference is the point.

        Raises BreakpointError if bp_id is not a software breakpoint.
        """
        bp = self._s.breakpoints.get(bp_id)
        if bp is None or bp.kind != "int3":
            raise BreakpointError(f"No software breakpoint {bp_id} to verify")

        h_process = bp.h_process or self._s.process_handle
        try:
            found = _pydbg.read_process_memory(h_process, bp.addr, 1)
        except OSError as e:
            self.last_error = e
            return None
        return found == self._INT3

    def verify(self, bp_id):
        """Check that the INT3 byte is still in the target. True if intact.

        A software breakpoint is one byte the target can overwrite. Self-
        unpacking code does exactly that by design — one analysis session had
        the OEP overwritten by the unpacker's own output, and the breakpoint
        simply stopped firing with nothing said. There is no event to hang
        detection on, so the state is answerable on request instead of silent.
        """
        if self.armed_state(bp_id) is True:
            self.lost.discard(bp_id)
            return True
        self.lost.add(bp_id)
        return False

    def verify_all(self):
        """Verify every software breakpoint; return the lost bp_ids.

        Result is ascending by bp_id so it reads the same as the breakpoints
        were created.
        """
        lost = []
        for bp_id, bp in list(self._s.breakpoints.items()):
            if bp.kind != "int3":
                continue
            if not self.verify(bp_id):
                lost.append(bp_id)
        return sorted(lost)

    def remove(self, bp_id):
        if bp_id not in self._s.breakpoints:
            raise BreakpointError(f"Breakpoint {bp_id} not found")

        bp = self._s.breakpoints[bp_id]
        if bp.kind != "int3":
            raise BreakpointError(
                f"Breakpoint {bp_id} is not a software breakpoint (type={bp.kind})"
            )
        del self._s.breakpoints[bp_id]
        self.lost.discard(bp_id)

        h_process = bp.h_process or self._s.process_handle
        # Restoring the original byte is right even if the target overwrote it
        # in the meantime: the caller asked for the breakpoint to be gone, and
        # the byte we put back is the one we displaced.
        self._restore_byte_handle(h_process, bp.addr, bp.original)

    def set_handle(self, h_process, addr):
        """Set INT3 breakpoint using explicit process handle.

        Idempotent per (process, address): asking twice returns the bp_id that
        is already armed there and writes nothing. The second write used to
        read back the 0xCC the first one had just planted and store it as the
        displaced byte, so remove() restored 0xCC for good — a permanent int3
        in the middle of a real instruction, with no error anywhere.
        """
        existing = self.find(addr, h_process)
        if existing is not None:
            return existing

        try:
            original = _pydbg.read_process_memory(h_process, addr, 1)
            old_prot = _pydbg.virtual_protect_ex(
                h_process, addr, 1, self._PAGE_EXECUTE_READWRITE
            )
            _pydbg.write_process_memory(h_process, addr, b"\xcc")
            _pydbg.virtual_protect_ex(h_process, addr, 1, old_prot)
        except OSError as e:
            raise BreakpointError(f"set_breakpoint at 0x{addr:X}: {e}")

        self._s.bp_counter += 1
        bp_id = self._s.bp_counter
        self._s.breakpoints[bp_id] = Breakpoint(
            kind="int3", addr=addr, original=original, h_process=h_process)
        return bp_id

    def _restore_byte_handle(self, h_process, addr, original):
        """Restore original byte at addr using explicit handle."""
        try:
            old_prot = _pydbg.virtual_protect_ex(
                h_process, addr, 1, self._PAGE_EXECUTE_READWRITE
            )
            _pydbg.write_process_memory(h_process, addr, original)
            _pydbg.virtual_protect_ex(h_process, addr, 1, old_prot)
        except OSError as e:
            raise BreakpointError(f"restore_byte at 0x{addr:X}: {e}")

    def _write_int3_handle(self, h_process, addr):
        """Write INT3 byte at addr using explicit handle."""
        try:
            old_prot = _pydbg.virtual_protect_ex(
                h_process, addr, 1, self._PAGE_EXECUTE_READWRITE
            )
            _pydbg.write_process_memory(h_process, addr, b"\xcc")
            _pydbg.virtual_protect_ex(h_process, addr, 1, old_prot)
        except OSError as e:
            raise BreakpointError(f"write_int3 at 0x{addr:X}: {e}")

    def handle_breakpoint_hit(self, tid, addr):
        """Handle breakpoint lifecycle: remove INT3, set single-step, schedule restore.

        Returns a HandleOutcome: NOT_MINE when the address is not one of our
        breakpoints, HANDLED when the thread is ready to be continued, and
        DEGRADED when the INT3 was re-armed but the thread could not be
        prepared (last_error says why).
        """
        bp_id = self.find(addr)
        if bp_id is None:
            return HandleOutcome.NOT_MINE

        # Count the hit here, before the rewind is attempted. The exception
        # was delivered for one of our breakpoints, so the site DID run —
        # that stays true on the degraded path below, where the rewind fails
        # but the code still reached this address.
        bp = self._s.breakpoints[bp_id]
        bp.hits += 1

        bp_addr = bp.addr
        h_process = bp.h_process or self._s.process_handle

        # Restore original byte (remove INT3)
        self._restore_byte_handle(h_process, bp_addr, bp.original)

        # Set single-step flag (TF) on the thread and rewind the instruction
        # pointer one byte back onto the breakpoint address. After an INT3
        # exception the IP already points past the breakpoint; backing it up
        # makes the single-step re-execute the original instruction instead of
        # the middle of it (which would corrupt the process).
        try:
            h_thread = _pydbg.open_thread(tid)
            try:
                machine = self._s.arch_for_tid(tid)
                regs = _pydbg.get_thread_context(h_thread, machine)
                regs["eflags"] = regs.get("eflags", 0) | 0x100
                if "rip" in regs:
                    regs["rip"] -= 1
                elif "eip" in regs:
                    regs["eip"] -= 1
                _pydbg.set_thread_context(h_thread, regs, machine)
            finally:
                _pydbg.close_handle(h_thread)
        except OSError as exc:
            # Cannot set TF — re-arm the breakpoint so the code is not left
            # with a permanently-removed INT3.
            #
            # The re-arm keeps the breakpoint alive, but this path leaves the
            # instruction pointer one byte past it, so the thread cannot
            # execute correctly. The answer says so (DEGRADED) instead of
            # leaving the caller to compare a counter before and after.
            self._write_int3_handle(h_process, bp_addr)
            self.last_error = exc
            return HandleOutcome.DEGRADED

        # Schedule restore on next single-step event
        self._s.pending_single_step[tid] = (bp_id, bp_addr, bp.original, h_process)
        return HandleOutcome.HANDLED

    def handle_single_step(self, tid):
        """Handle single-step event: restore INT3 if pending.

        Returns HANDLED if a pending single-step was consumed, NOT_MINE if the
        single-step belongs to somebody else.
        """
        if tid not in self._s.pending_single_step:
            return HandleOutcome.NOT_MINE

        entry = self._s.pending_single_step.pop(tid)
        bp_id = entry[0]
        addr = entry[1]
        h_process = entry[3] if len(entry) > 3 else self._s.process_handle

        # Only restore if breakpoint still exists (wasn't removed by user)
        if bp_id in self._s.breakpoints:
            self._write_int3_handle(h_process, addr)

        return HandleOutcome.HANDLED

    def teardown(self):
        """Put every displaced byte back. Returns [(what, why)] for failures.

        Never raises: close() has to keep walking the chain, so a breakpoint
        whose page is gone comes back as a reported problem instead of
        aborting the rest of the cleanup.
        """
        problems = []
        for bp_id in sorted(self._s.breakpoints):
            bp = self._s.breakpoints[bp_id]
            if bp.kind != "int3":
                continue
            h_process = bp.h_process or self._s.process_handle
            try:
                self._restore_byte_handle(h_process, bp.addr, bp.original)
            except BreakpointError as exc:
                problems.append((f"breakpoint {bp_id} at 0x{bp.addr:X}", str(exc)))
        self.discard()
        return problems

    def discard(self):
        """Forget every breakpoint without touching the target.

        For the terminate path: the process is gone, so there is no byte to put
        back, but the records must not outlive it and pretend to be armed.
        """
        for bp_id in [bid for bid, bp in self._s.breakpoints.items()
                      if bp.kind == "int3"]:
            self._s.breakpoints.pop(bp_id, None)
        self.lost.clear()
        self.last_error = None
        self._s.pending_single_step.clear()

    def find(self, addr, h_process=None):
        """bp_id of the software breakpoint at addr, or None.

        h_process narrows the answer to breakpoints armed through that handle.
        Addresses are process-local: a child and its parent can each hold one
        at 0x401000, and an address-only search would answer with whichever
        record came first — arming the wrong process, or none at all.
        """
        for bp_id, bp in self._s.breakpoints.items():
            if bp.kind != "int3" or bp.addr != addr:
                continue
            if h_process is not None and bp.h_process not in (None, h_process):
                continue
            return bp_id
        return None
