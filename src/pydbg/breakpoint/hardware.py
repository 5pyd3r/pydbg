"""HardwareBreakpointManager — debug-register hardware breakpoints.

Hardware breakpoints (Dr0-3) are per-thread registers. `set()` arms a
breakpoint process-wide by default (all threads of the target process, plus
new threads via CREATE_THREAD replication) unless a specific `tid` is given.
DR slots (0-3) are globally unique across hardware breakpoints.
"""

from .. import _pydbg
from ..exceptions import BreakpointError


class HardwareBreakpointManager:
    """Manages hardware (debug register) breakpoints."""

    COND_MAP = {"x": 0, "w": 1, "rw": 3}
    LEN_MAP = {1: 0, 2: 1, 4: 3, 8: 2}

    def __init__(self, session):
        self._s = session

    def _machine_for_tid(self, tid):
        """Architecture (32/64) for a thread id, using per-thread tracking."""
        return self._s.arch_for_tid(tid)

    def _all_thread_ids(self):
        """TIDs of the target process's current threads (plus main thread)."""
        tids = []
        if self._s.pid is not None:
            try:
                tids = [t["tid"] for t in _pydbg.enumerate_threads(self._s.pid)]
            except OSError:
                raise BreakpointError("enumerate_threads failed")
        if self._s.tid is not None and self._s.tid not in tids:
            tids.append(self._s.tid)
        return tids

    def _arm_thread(self, h_thread, addr, slot, condition, length, machine):
        """Write a hardware breakpoint to one thread (suspend-first on WOW64)."""
        suspended = False
        try:
            if machine == 32:
                _pydbg.suspend_thread(h_thread)
                suspended = True
            _pydbg.set_hw_breakpoint(
                h_thread,
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
                    _pydbg.resume_thread(h_thread)
                except OSError:
                    pass

    def _disarm_thread(self, h_thread, slot, machine):
        """Clear a debug-register slot on one thread (suspend-first on WOW64)."""
        suspended = False
        try:
            if machine == 32:
                _pydbg.suspend_thread(h_thread)
                suspended = True
            _pydbg.clear_hw_breakpoint(h_thread, slot, machine)
        except (OSError, ValueError) as e:
            raise BreakpointError(f"clear_hw_breakpoint: {e}")
        finally:
            if suspended:
                try:
                    _pydbg.resume_thread(h_thread)
                except OSError:
                    pass

    def _arm_scope(self, scope, addr, slot, condition, length):
        tids = self._all_thread_ids() if scope is None else [scope]
        armed = []
        try:
            for th_tid in tids:
                h = _pydbg.open_thread(th_tid)
                try:
                    self._arm_thread(h, addr, slot, condition, length, self._machine_for_tid(th_tid))
                finally:
                    _pydbg.close_handle(h)
                armed.append(th_tid)
        except Exception as e:
            # Roll back threads armed so far so no slot is left armed
            # without a breakpoint record.
            for th_tid in armed:
                try:
                    h = _pydbg.open_thread(th_tid)
                    try:
                        self._disarm_thread(h, slot, self._machine_for_tid(th_tid))
                    finally:
                        _pydbg.close_handle(h)
                except Exception:
                    pass
            raise BreakpointError(f"arm hardware breakpoint: {e}")

    def _disarm_scope(self, scope, slot):
        tids = self._all_thread_ids() if scope is None else [scope]
        for th_tid in tids:
            try:
                h = _pydbg.open_thread(th_tid)
            except OSError:
                continue  # thread already gone; its DRs are gone with it
            try:
                self._disarm_thread(h, slot, self._machine_for_tid(th_tid))
            finally:
                try:
                    _pydbg.close_handle(h)
                except OSError:
                    pass

    def set(self, addr, condition="x", length=1, slot=0, tid=None):
        """Set a hardware breakpoint.

        Args:
            addr: Breakpoint address.
            condition: 'x' (execute), 'w' (write), 'rw' (read/write).
            length: 1, 2, 4, or 8 bytes (8 only on x64 targets).
            slot: Debug register slot 0-3 (globally unique across hw breakpoints).
            tid: If given, arm only that thread; otherwise process-wide (all
                threads + new threads via CREATE_THREAD replication).

        Note:
            Slots are globally unique across hardware breakpoints (a slot must
            be freed with remove() before reuse; clear() only disables a slot
            but keeps the record).

        Returns:
            bp_id (int).
        """
        if condition not in self.COND_MAP:
            raise BreakpointError(f"Invalid condition '{condition}', use x/w/rw")
        if length not in self.LEN_MAP:
            raise BreakpointError(f"Invalid length {length}, use 1/2/4/8")
        if self._s.target_arch == 32 and length == 8:
            raise BreakpointError(
                "8-byte hardware breakpoints are not supported on x86/WOW64 targets"
            )
        if slot < 0 or slot > 3:
            raise BreakpointError(f"slot must be 0-3, got {slot}")

        # Slot is globally unique across hardware breakpoints.
        for bp_id, bp_info in self._s.breakpoints.items():
            if bp_info[0] == "hw" and bp_info[2] == slot:
                raise BreakpointError(
                    f"hardware breakpoint slot {slot} already in use (bp {bp_id})"
                )

        scope = None if tid is None else tid
        if scope is not None and scope not in self._all_thread_ids():
            raise BreakpointError(f"tid {scope} is not a thread of the target process")
        self._arm_scope(scope, addr, slot, condition, length)

        self._s.bp_counter += 1
        bp_id = self._s.bp_counter
        self._s.breakpoints[bp_id] = ("hw", addr, slot, scope, condition, length)
        return bp_id

    def clear(self, slot):
        """Disarm a slot on all threads. The bp record is left for remove()."""
        self._disarm_scope(None, slot)

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
        slot, scope = bp_info[2], bp_info[3]
        self._disarm_scope(scope, slot)
        del self._s.breakpoints[bp_id]
