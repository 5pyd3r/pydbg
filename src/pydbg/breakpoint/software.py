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
            _pydbg.virtual_protect_ex(
                self._s.process_handle, addr, 1, self._PAGE_EXECUTE_READWRITE
            )
            _pydbg.write_process_memory(self._s.process_handle, addr, b"\xcc")
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
        try:
            # Ensure page is writable before restoring original byte
            _pydbg.virtual_protect_ex(
                self._s.process_handle, addr, 1, self._PAGE_EXECUTE_READWRITE
            )
            _pydbg.write_process_memory(self._s.process_handle, addr, original)
        except OSError as e:
            raise BreakpointError(f"remove_breakpoint at 0x{addr:X}: {e}")

    def find(self, addr):
        for bp_id, bp_info in self._s.breakpoints.items():
            if bp_info[0] == "int3" and bp_info[1] == addr:
                return bp_id
        return None
