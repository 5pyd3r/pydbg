"""Debugger — high-level debugging API with composition pattern."""

from .. import _pydbg
from ..breakpoint.hardware import HardwareBreakpointManager
from ..disasm.engine import DisasmEngine
from ..dump.stackwalk import StackWalker
from ..hook.iat import IATHook
from ..hook.inline import InlineHook
from ..patch.assembler import Assembler
from ..trace.step import StepTracer
from ..breakpoint.software import SoftwareBreakpointManager
from ..exceptions import (
    BreakpointError,
    ProcessError,
    ThreadError,
)
from ..memory.manager import MemoryManager
from ..module.resolver import ModuleResolver
from ..symbol.resolver import SymbolResolver
from ..thread.manager import ThreadManager
from .event import DebugEvent
from .session import DebugSession


class Debugger:
    """Main debugger class. Procedural API for Win32 debugging."""

    def __init__(self):
        self._session = DebugSession()
        self.memory = MemoryManager(self._session)
        self.thread = ThreadManager(self._session)
        self.brk_sw = SoftwareBreakpointManager(self._session)
        self.brk_hw = HardwareBreakpointManager(self._session)
        self.modules = ModuleResolver(self._session)
        self.symbols = SymbolResolver(self._session)
        self.disasm = DisasmEngine(self._session)
        self.assembler = Assembler()
        self.step_tracer = StepTracer(self._session)
        self.hook_iat = IATHook(self._session)
        self.hook_inline = InlineHook(self._session)
        self.stack_walker = StackWalker(self._session)

    def _get_process_handle(self, pid=None):
        """Return process handle for main or child process."""
        if pid is None or pid == self._session.pid:
            return self._session.process_handle
        child = self._session.child_processes.get(pid)
        if child is None:
            raise ProcessError(f"Unknown process pid={pid}")
        return child.process_handle

    # ── lifecycle ──────────────────────────────────────────────

    def set_debug_children(self, enabled=True):
        """Enable/disable child process debugging. Must be called before create_process."""
        if self._session.pid is not None:
            raise ProcessError(
                "set_debug_children must be called before create_process"
            )
        self._session.debug_children = enabled

    def create_process(self, path):
        try:
            pid, tid, h_proc, h_thr = _pydbg.create_process(
                path, self._session.debug_children
            )
        except OSError as e:
            raise ProcessError(f"Failed to create process: {e}")

        self._session.process_handle = h_proc
        self._session.thread_handle = h_thr
        self._session.pid = pid
        self._session.tid = tid
        self._session.target_arch = self._detect_target_arch(h_proc)
        return (pid, tid)

    def _detect_target_arch(self, h_process):
        """Detect if target process is 32-bit (WoW64) or 64-bit."""
        import struct
        import ctypes
        if struct.calcsize("P") == 8:
            # 64-bit host: check if target is WoW64 (32-bit)
            try:
                is_wow64 = ctypes.c_int(0)
                ctypes.windll.kernel32.IsWow64Process(
                    ctypes.c_void_p(h_process), ctypes.byref(is_wow64))
                return 32 if is_wow64.value else 64
            except Exception:
                return 64
        else:
            # 32-bit host: always 32-bit
            return 32

    def attach(self, pid):
        try:
            _pydbg.debug_active_process(pid)
        except OSError as e:
            raise ProcessError(f"Failed to attach to pid {pid}: {e}")
        self._session.pid = pid

        # Open process handle so memory/thread operations work immediately
        try:
            h_proc = _pydbg.open_process(pid)
            self._session.process_handle = h_proc
            self._session.target_arch = self._detect_target_arch(h_proc)
        except OSError:
            # Non-fatal: attach succeeded but handle open failed
            # User can still use wait_event / continue_event
            pass

    def detach(self, pid=None):
        target = pid or self._session.pid
        if target is None:
            raise ProcessError("No process to detach from")
        try:
            _pydbg.debug_active_process_stop(target)
        except OSError as e:
            raise ProcessError(f"Failed to detach from pid {target}: {e}")

    def terminate_process(self, exit_code=1, pid=None):
        h = self._get_process_handle(pid)
        try:
            _pydbg.terminate_process(h, exit_code)
        except OSError as e:
            raise ProcessError(f"TerminateProcess failed: {e}")
        # Drain events only for main process
        if pid is None or pid == self._session.pid:
            for _ in range(50):
                try:
                    event_dict = _pydbg.wait_for_debug_event(2000)
                    if event_dict is None:
                        break
                    _pydbg.continue_debug_event(event_dict["pid"], event_dict["tid"])
                    if event_dict.get("event_name") == "EXIT_PROCESS":
                        break
                except OSError:
                    break

    def get_exit_code(self):
        if self._session.process_handle is None:
            raise ProcessError("No process handle")
        try:
            return _pydbg.get_exit_code(self._session.process_handle)
        except OSError as e:
            raise ProcessError(f"GetExitCodeProcess failed: {e}")

    def close_handle(self, h_handle):
        try:
            _pydbg.close_handle(h_handle)
        except OSError as e:
            raise ProcessError(f"CloseHandle: {e}")

    # ── event loop ─────────────────────────────────────────────

    def wait_event(self, timeout_ms=10000):
        try:
            event_dict = _pydbg.wait_for_debug_event(timeout_ms)
        except OSError as e:
            raise ProcessError(f"WaitForDebugEvent failed: {e}")

        if event_dict is None:
            return None

        is_child = (
            self._session.debug_children
            and event_dict.get("event_name") == "CREATE_PROCESS"
            and event_dict.get("pid") != self._session.pid
        )
        event = DebugEvent(event_dict, is_child=is_child)

        # Auto-track child processes
        if (self._session.debug_children
                and event.type == "CREATE_PROCESS"
                and event.pid != self._session.pid):
            self._register_child(event)

        # Auto-unregister exited child processes
        if (event.type == "EXIT_PROCESS"
                and event.pid in self._session.child_processes):
            self._unregister_child(event)

        return event

    def get_child_processes(self):
        """Return dict of all child processes: pid -> ChildProcessInfo."""
        return dict(self._session.child_processes)

    def get_child_process(self, pid):
        """Return ChildProcessInfo for a specific child, or None."""
        return self._session.child_processes.get(pid)

    def _register_child(self, event):
        """Register a child process from CREATE_PROCESS event."""
        from .session import ChildProcessInfo
        h_proc = event.raw.get("child_process_handle", 0)
        h_thr = event.raw.get("child_thread_handle", 0)
        info = ChildProcessInfo(
            pid=event.pid,
            tid=event.tid,
            process_handle=h_proc,
            thread_handle=h_thr,
            base_of_image=event.raw.get("base_of_image", 0),
        )
        self._session.child_processes[event.pid] = info

    def _unregister_child(self, event):
        """Unregister a child process from EXIT_PROCESS event."""
        child = self._session.child_processes.get(event.pid)
        if child is not None:
            child.exit_code = event.raw.get("exit_code")

    def continue_event(self, pid=None, tid=None):
        try:
            _pydbg.continue_debug_event(
                pid or self._session.pid, tid or self._session.tid
            )
        except OSError:
            # Non-fatal: process may have already exited (common with children)
            pass

    def run(self, callback, timeout_ms=10000):
        """Event-driven debug loop. Runs until process exits or callback returns False.

        User software breakpoints are always delivered to the callback
        (GDB-style): when one of our breakpoints is hit, the INT3 is already
        removed, the instruction pointer is rewound onto the breakpoint, and a
        single-step is pending — so the callback sees the original instruction
        in place. Return False from the callback to stop at the breakpoint (the
        process stays paused; use wait_event()/continue_event() +
        handle_ss_manual() to resume), or return None to transparently step
        over it and continue. The internal single-step that re-arms the INT3
        is handled internally and never delivered. Breakpoints set by the
        system (e.g. the loader breakpoint) are not ours and are always
        delivered as ordinary EXCEPTION events.

        Args:
            callback: Called for each debug event. Return False to stop.
            timeout_ms: WaitForDebugEvent timeout in ms.
        """
        exit_code = 1
        while True:
            event = self.wait_event(timeout_ms)
            if event is None:
                continue

            # Auto-handle breakpoint lifecycle
            if event.type == "EXCEPTION":
                code = event.exception_code
                addr = event.exception_addr

                if code == 0x80000003:  # EXCEPTION_BREAKPOINT
                    # Remove INT3, rewind IP, set TF for single-step.
                    if self.brk_sw.handle_breakpoint_hit(event.tid, addr):
                        # Our breakpoint: deliver to callback with the original
                        # byte restored and single-step pending. The next
                        # EXCEPTION_SINGLE_STEP re-arms the INT3 internally.
                        result = callback(event)
                        if result is False:
                            break
                        # Continue to let the single-step happen
                        self.continue_event(event.pid, event.tid)
                        continue
                elif code == 0x80000004:  # EXCEPTION_SINGLE_STEP
                    # Restore INT3 if this was from our breakpoint lifecycle
                    if self.brk_sw.handle_single_step(event.tid):
                        self.continue_event(event.pid, event.tid)
                        continue  # Don't deliver internal single-step to user

            result = callback(event)
            if result is False:
                break

            if event.type == "EXIT_PROCESS":
                exit_code = event.raw.get("exit_code", 1)
                self.continue_event(event.pid, event.tid)
                break

            self.continue_event(event.pid, event.tid)

        return exit_code

    def handle_bp_manual(self, tid, addr):
        """Manually handle breakpoint hit when using wait_event()/continue_event().

        Call this after receiving EXCEPTION_BREAKPOINT to properly manage
        the INT3 lifecycle (remove INT3 -> single-step -> re-arm).

        Returns True if the breakpoint was one of ours and was handled.

        Example:
            event = dbg.wait_event()
            if event.type == 'EXCEPTION' and event.exception_code == 0x80000003:
                if dbg.handle_bp_manual(event.tid, event.exception_addr):
                    # Read memory at bp address (original byte is restored)
                    data = dbg.read_memory(event.exception_addr, 16)
                    # Continue — single-step + re-arm happens automatically
                dbg.continue_event(event.pid, event.tid)
        """
        return self.brk_sw.handle_breakpoint_hit(tid, addr)

    def handle_ss_manual(self, tid):
        """Manually handle single-step after breakpoint. Call after EXCEPTION_SINGLE_STEP."""
        return self.brk_sw.handle_single_step(tid)

    def remove_all_breakpoints(self):
        """Remove all software breakpoints, restoring original bytes.
        Call before detach() to avoid leaving stale INT3 bytes in code."""
        for bp_id in list(self._session.breakpoints.keys()):
            bp_info = self._session.breakpoints.get(bp_id)
            if bp_info and bp_info[0] == "int3":
                self.remove_breakpoint(bp_id)

    # ── delegated: memory ──────────────────────────────────────

    def read_memory(self, addr, size, pid=None):
        h = self._get_process_handle(pid)
        return self.memory.read_handle(h, addr, size)

    def write_memory(self, addr, data, pid=None):
        h = self._get_process_handle(pid)
        return self.memory.write_handle(h, addr, data)

    def query_memory(self, addr, pid=None):
        h = self._get_process_handle(pid)
        return self.memory.query_handle(h, addr)

    def protect_memory(self, addr, size, protect, pid=None):
        h = self._get_process_handle(pid)
        return self.memory.protect_handle(h, addr, size, protect)

    # ── delegated: modules ─────────────────────────────────────

    def enum_modules(self, pid=None):
        h = self._get_process_handle(pid)
        return self.modules.enumerate_handle(h)

    def get_module_filename(self, h_module):
        return self.modules.get_filename(h_module)

    def find_module(self, name):
        """Find a module by basename (e.g. 'kernel32.dll')."""
        return self.modules.find_module(name)

    # ── delegated: symbols ──────────────────────────────────────

    def symbol_initialize(self, search_path=None, invade=True):
        """Initialize dbghelp symbol handler. Call before symbol lookups."""
        self.symbols.initialize(search_path, invade)

    def symbol_cleanup(self):
        """Release dbghelp symbol resources."""
        self.symbols.cleanup()

    def symbol_from_name(self, name):
        """Look up symbol address by name."""
        return self.symbols.from_name(name)

    def symbol_from_addr(self, address):
        """Look up symbol name by address."""
        return self.symbols.from_addr(address)

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

    def set_breakpoint(self, addr, pid=None):
        h = self._get_process_handle(pid)
        return self.brk_sw.set_handle(h, addr)

    def remove_breakpoint(self, bp_id):
        bp_info = self._session.breakpoints.get(bp_id)
        if bp_info is None:
            raise BreakpointError(f"Breakpoint {bp_id} not found")

        if bp_info[0] == "int3":
            return self.brk_sw.remove(bp_id)
        elif bp_info[0] == "hw":
            return self.brk_hw.remove(bp_id)
        else:
            raise BreakpointError(
                f"Unknown breakpoint type '{bp_info[0]}' for bp_id {bp_id}"
            )

    def set_hw_breakpoint(self, addr, condition="x", length=1, slot=0):
        return self.brk_hw.set(addr, condition, length, slot)

    def find_breakpoint(self, addr):
        return self.brk_sw.find(addr) or self.brk_hw.find(addr)

    # ── delegated: disasm ───────────────────────────────────────

    def disasm_at(self, addr, size):
        return self.disasm.disasm(addr, self.memory.read(addr, size))

    # ── delegated: patch ────────────────────────────────────────

    def assemble(self, code, addr=0):
        return self.assembler.assemble(code, addr)

    def step_trace(self, h_thread):
        self.step_tracer.step(h_thread)

    # ── delegated: hook ─────────────────────────────────────────

    def iat_hook(self, module, func, new_addr):
        return self.hook_iat.set(module, func, new_addr)

    def iat_unhook(self, module, func, original_addr=None):
        return self.hook_iat.restore(module, func, original_addr)

    def inline_hook(self, target_addr, hook_addr):
        return self.hook_inline.set(target_addr, hook_addr)

    def inline_unhook(self, trampoline):
        return self.hook_inline.restore(trampoline)

    # ── exception helpers ──────────────────────────────────────

    def exception_code_to_str(self, code):
        return _pydbg.exception_code_to_str(code)

    def get_exception_info(self, code, addr, first_chance, exception_params):
        return _pydbg.get_exception_info(code, addr, first_chance, exception_params)
