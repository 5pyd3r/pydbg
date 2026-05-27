"""HardwareBreakpointManager — debug-register hardware breakpoints."""

try:
    from ..cython import _bp
except ImportError:
    _bp = None

from ..exceptions import BreakpointError


class HardwareBreakpointManager:
    """Manages hardware (debug register) breakpoints."""

    COND_MAP = {'x': 0, 'w': 1, 'rw': 3}
    LEN_MAP = {1: 0, 2: 1, 4: 3, 8: 2}

    def __init__(self, session):
        self._s = session

    def set(self, addr, condition='x', length=1, slot=0):
        if condition not in self.COND_MAP:
            raise BreakpointError(f"Invalid condition '{condition}', use x/w/rw")
        if length not in self.LEN_MAP:
            raise BreakpointError(f"Invalid length {length}, use 1/2/4/8")

        try:
            _bp.set_hw_breakpoint(
                self._s.thread_handle, slot, addr,
                self.COND_MAP[condition], self.LEN_MAP[length])
        except (OSError, ValueError) as e:
            raise BreakpointError(f"set_hw_breakpoint: {e}")

        self._s.bp_counter += 1
        bp_id = self._s.bp_counter
        self._s.breakpoints[bp_id] = ('hw', addr, slot)
        return bp_id

    def clear(self, slot):
        try:
            _bp.clear_hw_breakpoint(self._s.thread_handle, slot)
        except (OSError, ValueError) as e:
            raise BreakpointError(f"clear_hw_breakpoint: {e}")

    def find(self, addr):
        for bp_id, bp_info in self._s.breakpoints.items():
            if bp_info[0] == 'hw' and bp_info[1] == addr:
                return bp_id
        return None

    def remove(self, bp_id):
        if bp_id not in self._s.breakpoints:
            raise BreakpointError(f"Breakpoint {bp_id} not found")

        bp_info = self._s.breakpoints.pop(bp_id)
        if bp_info[0] != 'hw':
            raise BreakpointError(
                f"Breakpoint {bp_id} is not a hardware breakpoint (type={bp_info[0]})")

        _, addr, slot = bp_info
        self.clear(slot)
