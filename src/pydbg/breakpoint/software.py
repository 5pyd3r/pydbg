"""SoftwareBreakpointManager — int3 software breakpoints."""

from .. import _pydbg
from ..exceptions import BreakpointError


class SoftwareBreakpointManager:
    """Manages int3 software breakpoints."""

    # Memory protection constants
    _PAGE_EXECUTE_READWRITE = 0x40

    def __init__(self, session):
        self._s = session

    def set(self, addr):
        try:
            original = _pydbg.read_process_memory(self._s.process_handle, addr, 1)
            # Make page writable before writing int3
            old_prot = _pydbg.virtual_protect_ex(
                self._s.process_handle, addr, 1, self._PAGE_EXECUTE_READWRITE
            )
            _pydbg.write_process_memory(self._s.process_handle, addr, b"\xcc")
            # Restore original page protection
            _pydbg.virtual_protect_ex(
                self._s.process_handle, addr, 1, old_prot
            )
        except OSError as e:
            raise BreakpointError(f"set_breakpoint at 0x{addr:X}: {e}")

        self._s.bp_counter += 1
        bp_id = self._s.bp_counter
        self._s.breakpoints[bp_id] = ("int3", addr, original)
        return bp_id

    def remove(self, bp_id):
        if bp_id not in self._s.breakpoints:
            raise BreakpointError(f"Breakpoint {bp_id} not found")

        bp_info = self._s.breakpoints.pop(bp_id)
        if bp_info[0] != "int3":
            raise BreakpointError(
                f"Breakpoint {bp_id} is not a software breakpoint (type={bp_info[0]})"
            )

        _, addr, original = bp_info
        self._restore_byte(addr, original)

    def _restore_byte(self, addr, original):
        """Restore original byte at addr."""
        try:
            old_prot = _pydbg.virtual_protect_ex(
                self._s.process_handle, addr, 1, self._PAGE_EXECUTE_READWRITE
            )
            _pydbg.write_process_memory(self._s.process_handle, addr, original)
            _pydbg.virtual_protect_ex(
                self._s.process_handle, addr, 1, old_prot
            )
        except OSError as e:
            raise BreakpointError(f"restore_byte at 0x{addr:X}: {e}")

    def _write_int3(self, addr):
        """Write INT3 byte at addr."""
        try:
            old_prot = _pydbg.virtual_protect_ex(
                self._s.process_handle, addr, 1, self._PAGE_EXECUTE_READWRITE
            )
            _pydbg.write_process_memory(self._s.process_handle, addr, b"\xcc")
            _pydbg.virtual_protect_ex(
                self._s.process_handle, addr, 1, old_prot
            )
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
        _, bp_addr, original = bp_info

        # Restore original byte (remove INT3)
        self._restore_byte(bp_addr, original)

        # Set single-step flag (TF) on the thread
        try:
            h_thread = _pydbg.open_thread(tid)
            regs = _pydbg.get_thread_context(h_thread)
            regs["eflags"] = regs.get("eflags", 0) | 0x100
            _pydbg.set_thread_context(h_thread, regs)
            _pydbg.close_handle(h_thread)
        except OSError:
            # If we can't set TF, just continue — breakpoint won't auto-restore
            return True

        # Schedule restore on next single-step event
        self._s.pending_single_step[tid] = (bp_id, bp_addr, original)
        return True

    def handle_single_step(self, tid):
        """Handle single-step event: restore INT3 if pending.

        Returns True if a pending single-step was handled.
        """
        if tid not in self._s.pending_single_step:
            return False

        bp_id, addr, original = self._s.pending_single_step.pop(tid)

        # Only restore if breakpoint still exists (wasn't removed by user)
        if bp_id in self._s.breakpoints:
            self._write_int3(addr)

        return True

    def find(self, addr):
        for bp_id, bp_info in self._s.breakpoints.items():
            if bp_info[0] == "int3" and bp_info[1] == addr:
                return bp_id
        return None
