"""HardwareBreakpointManager — debug-register hardware breakpoints."""

from .. import _pydbg
from ..exceptions import BreakpointError


class HardwareBreakpointManager:
    """Manages hardware (debug register) breakpoints."""

    COND_MAP = {"x": 0, "w": 1, "rw": 3}
    LEN_MAP = {1: 0, 2: 1, 4: 3, 8: 2}

    def __init__(self, session):
        self._s = session

    def set(self, addr, condition="x", length=1, slot=0):
        if condition not in self.COND_MAP:
            raise BreakpointError(f"Invalid condition '{condition}', use x/w/rw")
        if length not in self.LEN_MAP:
            raise BreakpointError(f"Invalid length {length}, use 1/2/4/8")
        if self._s.target_arch == 32 and length == 8:
            raise BreakpointError(
                "8-byte hardware breakpoints are not supported on x86/WOW64 targets"
            )

        machine = self._s.target_arch
        # WOW64 平台怪癖：运行中的线程直接 Wow64SetThreadContext 写 Dr0-3
        # 约 3/4 概率不生效，须先 SuspendThread。净挂起计数保持 0。
        suspended = False
        try:
            if machine == 32:
                _pydbg.suspend_thread(self._s.thread_handle)
                suspended = True
            _pydbg.set_hw_breakpoint(
                self._s.thread_handle,
                slot,
                addr,
                self.COND_MAP[condition],
                self.LEN_MAP[length],
                machine,
            )
        except (OSError, ValueError) as e:
            raise BreakpointError(f"set_hw_breakpoint: {e}")
        finally:
            if suspended:
                try:
                    _pydbg.resume_thread(self._s.thread_handle)
                except OSError:
                    # 线程可能已退出；忽略，避免顶替主异常
                    pass

        self._s.bp_counter += 1
        bp_id = self._s.bp_counter
        self._s.breakpoints[bp_id] = ("hw", addr, slot)
        return bp_id

    def clear(self, slot):
        machine = self._s.target_arch
        suspended = False
        try:
            if machine == 32:
                _pydbg.suspend_thread(self._s.thread_handle)
                suspended = True
            _pydbg.clear_hw_breakpoint(self._s.thread_handle, slot, machine)
        except (OSError, ValueError) as e:
            raise BreakpointError(f"clear_hw_breakpoint: {e}")
        finally:
            if suspended:
                try:
                    _pydbg.resume_thread(self._s.thread_handle)
                except OSError:
                    # 线程可能已退出；忽略，避免顶替主异常
                    pass

    def find(self, addr):
        for bp_id, bp_info in self._s.breakpoints.items():
            if bp_info[0] == "hw" and bp_info[1] == addr:
                return bp_id
        return None

    def remove(self, bp_id):
        if bp_id not in self._s.breakpoints:
            raise BreakpointError(f"Breakpoint {bp_id} not found")

        bp_info = self._s.breakpoints[bp_id]
        if bp_info[0] != "hw":
            raise BreakpointError(
                f"Breakpoint {bp_id} is not a hardware breakpoint (type={bp_info[0]})"
            )
        del self._s.breakpoints[bp_id]

        _, addr, slot = bp_info
        self.clear(slot)
