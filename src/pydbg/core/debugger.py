"""Debugger — high-level debugging API with composition pattern."""

from .session import DebugSession
from .event import DebugEvent

from ..exceptions import (
    ProcessError,
    ThreadError,
    BreakpointError,
)
from ..memory.manager import MemoryManager
from ..thread.manager import ThreadManager
from ..breakpoint.software import SoftwareBreakpointManager
from ..breakpoint.hardware import HardwareBreakpointManager
from ..module.resolver import ModuleResolver

try:
    from ..cython import _process, _exception
except ImportError:
    _process = _exception = None


class Debugger:
    """Main debugger class. Procedural API for Win32 debugging."""

    def __init__(self):
        self._session = DebugSession()
        self.memory = MemoryManager(self._session)
        self.thread = ThreadManager(self._session)
        self.brk_sw = SoftwareBreakpointManager(self._session)
        self.brk_hw = HardwareBreakpointManager(self._session)
        self.modules = ModuleResolver(self._session)

    # ── lifecycle ──────────────────────────────────────────────

    def create_process(self, path):
        try:
            pid, tid, h_proc, h_thr = _process.create_process(path)
        except OSError as e:
            raise ProcessError(f"Failed to create process: {e}")

        self._session.process_handle = h_proc
        self._session.thread_handle = h_thr
        self._session.pid = pid
        self._session.tid = tid
        return (pid, tid)

    def attach(self, pid):
        try:
            _process.debug_active_process(pid)
        except OSError as e:
            raise ProcessError(f"Failed to attach to pid {pid}: {e}")
        self._session.pid = pid

    def detach(self, pid=None):
        target = pid or self._session.pid
        if target is None:
            raise ProcessError("No process to detach from")
        try:
            _process.debug_active_process_stop(target)
        except OSError as e:
            raise ProcessError(f"Failed to detach from pid {target}: {e}")

    def terminate_process(self, exit_code=1):
        if self._session.process_handle is None:
            raise ProcessError("No process handle")
        try:
            _process.terminate_process(self._session.process_handle, exit_code)
        except OSError as e:
            raise ProcessError(f"TerminateProcess failed: {e}")

    def get_exit_code(self):
        if self._session.process_handle is None:
            raise ProcessError("No process handle")
        try:
            return _process.get_exit_code(self._session.process_handle)
        except OSError as e:
            raise ProcessError(f"GetExitCodeProcess failed: {e}")

    def close_handle(self, h_handle):
        try:
            _process.close_handle(h_handle)
        except OSError as e:
            raise ProcessError(f"CloseHandle: {e}")

    # ── event loop ─────────────────────────────────────────────

    def wait_event(self, timeout_ms=10000):
        try:
            event_dict = _process.wait_for_debug_event(timeout_ms)
        except OSError as e:
            raise ProcessError(f"WaitForDebugEvent failed: {e}")

        if event_dict is None:
            return None
        return DebugEvent(event_dict)

    def continue_event(self, pid=None, tid=None):
        try:
            _process.continue_debug_event(
                pid or self._session.pid,
                tid or self._session.tid)
        except OSError as e:
            raise ProcessError(f"ContinueDebugEvent failed: {e}")

    def run(self, callback, timeout_ms=10000):
        exit_code = 1
        while True:
            event = self.wait_event(timeout_ms)
            if event is None:
                continue

            result = callback(event)
            if result is False:
                break

            if event.type == 'EXIT_PROCESS':
                exit_code = event.raw.get('exit_code', 1)
                break

            self.continue_event(event.pid, event.tid)

        return exit_code

    # ── delegated: memory ──────────────────────────────────────

    def read_memory(self, addr, size):
        return self.memory.read(addr, size)

    def write_memory(self, addr, data):
        return self.memory.write(addr, data)

    def query_memory(self, addr):
        return self.memory.query(addr)

    def protect_memory(self, addr, size, protect):
        return self.memory.protect(addr, size, protect)

    # ── delegated: modules ─────────────────────────────────────

    def enum_modules(self):
        return self.modules.enumerate()

    def get_module_filename(self, h_module):
        return self.modules.get_filename(h_module)

    # ── delegated: thread ──────────────────────────────────────

    def open_thread(self, tid):
        return self.thread.open(tid)

    def get_registers(self, h_thread):
        return self.thread.get_context(h_thread)

    def set_registers(self, h_thread, context):
        return self.thread.set_context(h_thread, context)

    def set_register(self, h_thread, name, value):
        return self.thread.set_register(h_thread, name, value)

    def suspend_thread(self, h_thread):
        return self.thread.suspend(h_thread)

    def resume_thread(self, h_thread):
        return self.thread.resume(h_thread)

    def enumerate_threads(self, pid=None):
        target = pid or self._session.pid
        if target is None:
            raise ThreadError("No process to enumerate threads for")
        return self.thread.enumerate(target)

    def get_thread_ids(self, pid=None):
        target = pid or self._session.pid
        if target is None:
            raise ThreadError("No process to enumerate threads for")
        return self.thread.get_ids(target)

    def step(self, h_thread):
        self.thread.step(h_thread)

    # ── delegated: breakpoints ─────────────────────────────────

    def set_breakpoint(self, addr):
        return self.brk_sw.set(addr)

    def remove_breakpoint(self, bp_id):
        bp_info = self._session.breakpoints.get(bp_id)
        if bp_info is None:
            raise BreakpointError(f"Breakpoint {bp_id} not found")

        if bp_info[0] == 'int3':
            return self.brk_sw.remove(bp_id)
        elif bp_info[0] == 'hw':
            return self.brk_hw.remove(bp_id)
        else:
            raise BreakpointError(
                f"Unknown breakpoint type '{bp_info[0]}' for bp_id {bp_id}")

    def set_hw_breakpoint(self, addr, condition='x', length=1, slot=0):
        return self.brk_hw.set(addr, condition, length, slot)

    def find_breakpoint(self, addr):
        return self.brk_sw.find(addr) or self.brk_hw.find(addr)

    # ── exception helpers ──────────────────────────────────────

    def exception_code_to_str(self, code):
        return _exception.exception_code_to_str(code)

    def get_exception_info(self, code, addr, first_chance, exception_params):
        return _exception.get_exception_info(code, addr, first_chance, exception_params)
