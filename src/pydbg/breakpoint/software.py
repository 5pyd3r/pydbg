"""SoftwareBreakpointManager — int3 software breakpoints."""

from .. import _pydbg
from ..exceptions import BreakpointError


class SoftwareBreakpointManager:
    """Manages int3 software breakpoints."""

    # Memory protection constants
    _PAGE_EXECUTE_READWRITE = 0x40

    def __init__(self, session):
        self._s = session

    def remove(self, bp_id):
        if bp_id not in self._s.breakpoints:
            raise BreakpointError(f"Breakpoint {bp_id} not found")

        bp_info = self._s.breakpoints[bp_id]
        if bp_info[0] != "int3":
            raise BreakpointError(
                f"Breakpoint {bp_id} is not a software breakpoint (type={bp_info[0]})"
            )
        del self._s.breakpoints[bp_id]

        addr = bp_info[1]
        original = bp_info[2]
        h_process = bp_info[3] if len(bp_info) > 3 else self._s.process_handle
        self._restore_byte_handle(h_process, addr, original)

    def set_handle(self, h_process, addr):
        """Set INT3 breakpoint using explicit process handle."""
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
        self._s.breakpoints[bp_id] = ("int3", addr, original, h_process)
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

        Returns True if a breakpoint was handled, False otherwise.
        """
        bp_id = self.find(addr)
        if bp_id is None:
            return False

        bp_info = self._s.breakpoints[bp_id]
        bp_addr = bp_info[1]
        original = bp_info[2]
        h_process = bp_info[3] if len(bp_info) > 3 else self._s.process_handle

        # Restore original byte (remove INT3)
        self._restore_byte_handle(h_process, bp_addr, original)

        # Set single-step flag (TF) on the thread and rewind the instruction
        # pointer one byte back onto the breakpoint address. After an INT3
        # exception the IP already points past the breakpoint; backing it up
        # makes the single-step re-execute the original instruction instead of
        # the middle of it (which would corrupt the process).
        try:
            h_thread = _pydbg.open_thread(tid)
            regs = _pydbg.get_thread_context(h_thread)
            regs["eflags"] = regs.get("eflags", 0) | 0x100
            if "rip" in regs:
                regs["rip"] -= 1
            elif "eip" in regs:
                regs["eip"] -= 1
            _pydbg.set_thread_context(h_thread, regs)
            _pydbg.close_handle(h_thread)
        except OSError:
            # Cannot set TF — re-arm the breakpoint so the code is not left
            # with a permanently-removed INT3.
            self._write_int3_handle(h_process, bp_addr)
            return True

        # Schedule restore on next single-step event
        self._s.pending_single_step[tid] = (bp_id, bp_addr, original, h_process)
        return True

    def handle_single_step(self, tid):
        """Handle single-step event: restore INT3 if pending.

        Returns True if a pending single-step was handled.
        """
        if tid not in self._s.pending_single_step:
            return False

        entry = self._s.pending_single_step.pop(tid)
        bp_id = entry[0]
        addr = entry[1]
        h_process = entry[3] if len(entry) > 3 else self._s.process_handle

        # Only restore if breakpoint still exists (wasn't removed by user)
        if bp_id in self._s.breakpoints:
            self._write_int3_handle(h_process, addr)

        return True

    def find(self, addr):
        for bp_id, bp_info in self._s.breakpoints.items():
            if bp_info[0] == "int3" and bp_info[1] == addr:
                return bp_id
        return None
