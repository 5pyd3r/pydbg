"""Debugger — high-level debugging API with composition pattern."""

import time

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
    TimeoutError,
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

    # Access rights for a process opened by pid that we are not debugging.
    # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ is the pair a prior session
    # proved sufficient to read a real image out of another debugger's
    # debuggee; QUERY_LIMITED_INFORMATION is the fallback for processes that
    # refuse the broader query right.
    _READ_ACCESS = 0x0410
    _READ_ACCESS_LIMITED = 0x1010
    # What a foreign handle must carry before a write/terminate path may use
    # it, so a read-only handle is refused by name instead of failing later as
    # ERROR_NOACCESS out of the syscall that wanted the right.
    _NEED_VM_WRITE = 0x0028        # PROCESS_VM_WRITE | PROCESS_VM_OPERATION
    _NEED_TERMINATE = 0x0001       # PROCESS_TERMINATE

    def _get_process_handle(self, pid=None, need=0):
        """Return a process handle for the main target, a debug child, or a
        process already opened by pid via open_process().

        Deliberately strict: a pid that was never opened is an error here.
        This is the handle used by the paths that *write* to a process
        (write_memory, protect_memory) and by terminate_process, where
        opening an arbitrary pid on request would turn 'terminate the thing I
        am debugging' into 'terminate whatever pid was passed'. Reading keeps
        a separate, more permissive path — see _get_read_handle.

        'need' is the access mask a handle opened by open_process() must carry
        for this operation. The target's own handle and a debug child's are
        taken as having it: they come from create_process/DEBUG_PROCESS, not
        from a mask this class chose.
        """
        if pid is None or pid == self._session.pid:
            return self._session.process_handle
        child = self._session.child_processes.get(pid)
        if child is not None:
            return child.process_handle
        opened = self._session.foreign_handles.get(pid)
        if opened is None:
            raise ProcessError(f"Unknown process pid={pid}")
        have = self._session.foreign_access.get(pid, 0)
        if need and (have & need) != need:
            raise ProcessError(
                f"pid {pid} was opened with access 0x{have:X}, which does not "
                f"include 0x{need:X} needed here. close_process({pid}) and "
                f"reopen it with open_process({pid}, access=0x{have | need:X}).")
        return opened

    def _get_read_handle(self, pid=None):
        """Handle for reading: as _get_process_handle, but a pid that is
        neither the target nor a debug child is opened on demand.

        This is the nested-debugging case. After attach() to a debugger, the
        memory that matters usually belongs to the process *it* is debugging:
        that process is not our debug child, it produces no CREATE_PROCESS
        event for us, so get_child_processes() stays empty and read_memory()
        used to answer ProcessError("Unknown process pid"). Reaching it meant
        OpenProcess + ReadProcessMemory through ctypes in the caller.
        """
        if pid is None or pid == self._session.pid:
            return self._session.process_handle
        child = self._session.child_processes.get(pid)
        if child is not None:
            return child.process_handle
        return self.open_process(pid)

    def open_process(self, pid, access=None):
        """Open a handle to any process by pid so its memory can be read.

        Not a debugging relationship: nothing is attached, the process is not
        suspended, and no debug events will arrive for it. The handle is
        cached on the session (so repeated read_memory(pid=) calls reuse it)
        and released by close_process() or detach().

        The default access mask is read-only, and that is what the rest of
        this class then allows: read_memory, read_memory_safe, query_memory,
        enum_regions, enum_modules and module_at work by pid, while
        write_memory, protect_memory, set_breakpoint and terminate_process
        keep requiring either the debug target, a debug child, or a handle
        opened here with a mask that grants it. Pass access=0x1F0FFF
        (PROCESS_ALL_ACCESS) when the caller really does mean to patch or
        breakpoint a process it is not debugging.

        Args:
            pid: Process id.
            access: Win32 access mask. Defaults to PROCESS_VM_READ |
                PROCESS_QUERY_INFORMATION, retried with
                PROCESS_QUERY_LIMITED_INFORMATION.

        Returns:
            The process handle.

        Raises:
            ProcessError: the process could not be opened — it does not
                exist, or it exists but refuses this process the read rights.
        """
        cached = self._session.foreign_handles.get(pid)
        if cached is not None:
            # A cached handle is only good for the rights it carries. Handing
            # it back for a wider request would fail later at the first write,
            # as ERROR_NOACCESS from VirtualProtectEx — which names none of
            # this. Reopen instead when the caller asks for different rights.
            if access is None or self._session.foreign_access.get(pid) == access:
                return cached
            self.close_process(pid)

        masks = ((access,) if access is not None
                 else (self._READ_ACCESS, self._READ_ACCESS_LIMITED))
        last = None
        for mask in masks:
            try:
                handle = _pydbg.open_process(pid, mask)
            except OSError as e:
                last = e
                continue
            self._session.foreign_handles[pid] = handle
            self._session.foreign_access[pid] = mask
            return handle

        raise ProcessError(
            f"cannot open pid {pid} for reading: {last} (tried access mask(s) "
            f"{', '.join(f'0x{m:X}' for m in masks)}). The pid may not exist, "
            f"or it may be a process this one is not allowed to read.")

    def close_process(self, pid):
        """Close a handle opened by open_process(). No-op if never opened."""
        handle = self._session.foreign_handles.pop(pid, None)
        self._session.foreign_access.pop(pid, None)
        if handle is None:
            return
        try:
            _pydbg.close_handle(handle)
        except OSError as e:
            raise ProcessError(f"CloseHandle for pid {pid}: {e}")

    def _close_foreign_handles(self):
        """Release every handle open_process() handed out. Never raises."""
        for pid in list(self._session.foreign_handles):
            try:
                self.close_process(pid)
            except ProcessError:
                pass

    # ── lifecycle ──────────────────────────────────────────────

    def set_debug_children(self, enabled=True):
        """Enable/disable child process debugging. Must be called before create_process."""
        if self._session.pid is not None:
            raise ProcessError(
                "set_debug_children must be called before create_process"
            )
        self._session.debug_children = enabled

    def create_process(self, path, cmdline=None):
        """Start 'path' under debug control. Returns (pid, tid).

        Args:
            path: Executable to start.
            cmdline: Optional command line. Without it the process is started
                with 'path' as its command line. With it, 'path' names the
                image and 'cmdline' is passed verbatim — argv[0] included, so
                the caller owns that convention. Targets configured by argument
                can then be started here instead of forcing attach(), which
                loses every startup-time breakpoint.
        """
        try:
            pid, tid, h_proc, h_thr = _pydbg.create_process(
                path, self._session.debug_children, cmdline
            )
        except OSError as e:
            raise ProcessError(f"Failed to create process: {e}")

        self._session.process_handle = h_proc
        self._session.thread_handle = h_thr
        self._session.pid = pid
        self._session.tid = tid
        self._session.target_arch = self._detect_target_arch(h_proc)
        self._session.register_pid_arch(pid, self._session.target_arch)
        self._session.register_tid_arch(tid, self._session.target_arch)
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

        # Open process handle so memory/thread operations work immediately.
        # If full access fails, still detect the target architecture via a
        # query-only handle so a WOW64 target never falls back to native-64
        # register contexts.
        try:
            h_proc = _pydbg.open_process(pid)
            self._session.process_handle = h_proc
            self._session.target_arch = self._detect_target_arch(h_proc)
        except OSError:
            try:
                q = _pydbg.open_process(pid, 0x1000)  # PROCESS_QUERY_LIMITED_INFORMATION
                try:
                    self._session.target_arch = self._detect_target_arch(q)
                finally:
                    _pydbg.close_handle(q)
            except OSError:
                pass  # arch stays default; wait_event/continue_event still usable

        self._session.register_pid_arch(pid, self._session.target_arch)

        # create_process() leaves a session tid behind; attach() did not, so
        # anything relying on a default thread (the manual breakpoint helpers,
        # for one) had nothing to work with. Best-effort: an attached process
        # may legitimately have no thread we can open yet.
        try:
            tids = self.get_thread_ids(pid)
            if tids:
                self._session.tid = tids[0]
        except (OSError, ProcessError):
            pass

    def detach(self, pid=None):
        target = pid or self._session.pid
        if target is None:
            raise ProcessError("No process to detach from")
        try:
            _pydbg.debug_active_process_stop(target)
        except OSError as e:
            raise ProcessError(f"Failed to detach from pid {target}: {e}")
        # Close handles opened by pid too, whichever process is being detached:
        # they belong to this session, not to the process that was detached.
        self._close_foreign_handles()
        # Close main-session handles so repeated attach/detach cycles don't leak.
        if target == self._session.pid:
            for name in ("thread_handle", "process_handle"):
                h = getattr(self._session, name, None)
                if h:
                    try:
                        _pydbg.close_handle(h)
                    except OSError:
                        pass
                    setattr(self._session, name, None)

    def terminate_process(self, exit_code=1, pid=None):
        h = self._get_process_handle(pid, need=self._NEED_TERMINATE)
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

        # Record image bases as the loader reports them. An HMODULE is the
        # module's base address, so the base doubles as the handle. This table
        # is what module_at() reads; it is the only module information
        # available before the loader finishes, when PSAPI refuses to answer.
        if event.type == "CREATE_PROCESS":
            self._session.record_module(
                event.pid, event.raw.get("base_of_image", 0))
        elif event.type == "LOAD_DLL":
            self._session.record_module(
                event.pid, event.raw.get("dll_base", 0))

        # Track per-thread architecture so cross-arch children resolve the
        # correct register context.
        if event.type == "CREATE_THREAD":
            self._session.register_tid_arch(
                event.tid, self._session.pid_arch.get(event.pid) or self._session.target_arch
            )

        # Replicate process-wide hardware breakpoints to newly created threads
        # of THIS process (DR registers are per-thread; child processes must
        # not inherit the parent's process-wide breakpoints).
        if event.type == "CREATE_THREAD" and event.pid == self._session.pid:
            for bp_id, bp_info in self._session.breakpoints.items():
                if bp_info[0] == "hw" and bp_info[3] is None:
                    try:
                        h = _pydbg.open_thread(event.tid)
                        try:
                            self.brk_hw._arm_thread(
                                h,
                                bp_info[1],
                                bp_info[2],
                                bp_info[4],
                                bp_info[5],
                                self._session.arch_for_tid(event.tid),
                            )
                        finally:
                            _pydbg.close_handle(h)
                    except OSError:
                        pass  # thread may already be gone; skip replication

        # The main process's CREATE_PROCESS (idempotent; covers attach mode
        # where create_process wasn't used).
        if event.type == "CREATE_PROCESS" and event.pid == self._session.pid:
            self._session.register_pid_arch(event.pid, self._session.target_arch)
            self._session.register_tid_arch(event.tid, self._session.target_arch)

        # Attach mode: open the main thread handle from the CREATE_PROCESS
        # event so hardware breakpoints work after attach().
        if (event.type == "CREATE_PROCESS"
                and event.pid == self._session.pid
                and self._session.thread_handle is None):
            try:
                self._session.thread_handle = _pydbg.open_thread(event.tid)
            except OSError:
                pass  # non-fatal; thread ops fail later if open failed

        return event

    def get_child_processes(self):
        """Child processes we are DEBUGGING: pid -> ChildProcessInfo.

        Populated only from CREATE_PROCESS debug events, which means only when
        create_process() was used with set_debug_children(True).

        An empty dict therefore does NOT mean the target has no children. It
        means we are not debugging them, which is the normal state after
        attach(): Win32 attaches us to one process, and its children are not
        ours. Reading the empty dict as "no children exist" is exactly the
        false negative this wording exists to prevent — use
        enumerate_child_processes() for the OS's answer, which comes from a
        snapshot rather than from the event stream.
        """
        return dict(self._session.child_processes)

    def get_child_process(self, pid):
        """Return ChildProcessInfo for a specific child, or None.

        None means "not one of our debug children" — not "not a child of the
        target". See get_child_processes().
        """
        return self._session.child_processes.get(pid)

    def enumerate_processes(self):
        """Every process on the system: a list of dicts, ascending as returned.

        Each dict: 'pid', 'parent_pid', 'exe_name', 'thread_count'. Sourced
        from a Toolhelp32 snapshot, so it describes the process tree whether
        or not anything is being debugged.
        """
        try:
            return _pydbg.enumerate_processes()
        except OSError as e:
            raise ProcessError(f"process snapshot failed: {e}")

    def enumerate_child_processes(self, pid=None, recursive=False):
        """Children of 'pid' (default: the debug target) as the OS reports them.

        This is the process tree, not the debug-event stream, and the
        difference is the whole point of having it next to
        get_child_processes():

        * After attach() the target's own children produce no CREATE_PROCESS
          event for us, so an event-derived answer is empty while the children
          are running. An empty snapshot answer means the children really are
          gone.
        * It sees children that were never ours to debug, including the
          process another debugger (the target) is itself debugging — which
          is the process whose memory read_memory(pid=) then has to reach.

        Args:
            pid: Parent process id. Defaults to the session's target.
            recursive: Walk down the whole descendant tree, not just one level.

        Returns a list of snapshot dicts (see enumerate_processes), each with
        'parent_pid' naming the parent it was reached through. Raises
        ProcessError when no pid is given and there is no target.
        """
        parent = pid if pid is not None else self._session.pid
        if parent is None:
            raise ProcessError(
                "no process to enumerate children of: pass pid=, or create or "
                "attach to a process first")

        snapshot = self.enumerate_processes()
        children = []
        frontier = [parent]
        seen = {parent}
        while frontier:
            wanted = set(frontier)
            frontier = []
            for proc in snapshot:
                if proc['parent_pid'] in wanted and proc['pid'] not in seen:
                    seen.add(proc['pid'])
                    children.append(proc)
                    frontier.append(proc['pid'])
            if not recursive:
                break
        return children

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
        # Detect the child's architecture so its threads get the right
        # register context even when it differs from the parent's.
        if h_proc:
            info.target_arch = self._detect_target_arch(h_proc) or self._session.target_arch
        else:
            info.target_arch = self._session.target_arch
        self._session.register_pid_arch(event.pid, info.target_arch)
        self._session.register_tid_arch(event.tid, info.target_arch)
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

    def run(self, callback, timeout_ms=10000, max_idle_timeouts=None):
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
            max_idle_timeouts: Fail after this many consecutive WaitForDebugEvent
                timeouts with no event at all. Without it an idle or wedged
                target is indistinguishable from a running one — the loop just
                spins, and an idle GUI target can produce no events for minutes.
                Raises TimeoutError when exceeded.

        Other Python threads keep running while this blocks: the underlying
        WaitForDebugEvent releases the GIL. That was not always true, and the
        conclusion drawn from the old behaviour — that a watchdog for a target
        stuck on a modal dialog "must" live in a separate process — is
        corrected in _process.pxi (Correction, 2026-09-20), with the measured
        before/after in tests/test_probe_visibility.py.

        Raises:
            BreakpointError: a software breakpoint hit could not be completed
                (see SoftwareBreakpointManager.handle_breakpoint_hit). Continuing
                would leave the instruction pointer mid-instruction, so this is
                surfaced rather than retried.
        """
        exit_code = 1
        idle = 0
        while True:
            event = self.wait_event(timeout_ms)
            if event is None:
                idle += 1
                if max_idle_timeouts is not None and idle >= max_idle_timeouts:
                    raise TimeoutError(
                        f"no debug event for {idle} consecutive waits "
                        f"({timeout_ms} ms each); the target is idle, blocked, "
                        f"or wedged")
                continue
            idle = 0

            # Auto-handle breakpoint lifecycle
            if event.type == "EXCEPTION":
                code = event.exception_code
                addr = event.exception_addr

                if code == _pydbg.EXCEPTION_BREAKPOINT or code == _pydbg.STATUS_WX86_BREAKPOINT:
                    # Remove INT3, rewind IP, set TF for single-step.
                    degraded = self.brk_sw.degraded_hits
                    handled = self.brk_sw.handle_breakpoint_hit(event.tid, addr)
                    if self.brk_sw.degraded_hits != degraded:
                        # Our breakpoint, but the IP could not be rewound onto
                        # it. The thread would resume mid-instruction; surface
                        # it rather than continuing as though nothing is wrong.
                        raise BreakpointError(
                            f"breakpoint at 0x{addr:X} (tid {event.tid}) could not "
                            f"be completed: {self.brk_sw.last_error}. The "
                            f"instruction pointer was not rewound, so resuming "
                            f"would execute from the middle of an instruction.")
                    if handled:
                        result = callback(event)
                        if result is False:
                            break
                        self.continue_event(event.pid, event.tid)
                        continue
                elif code == _pydbg.EXCEPTION_SINGLE_STEP or code == _pydbg.STATUS_WX86_SINGLE_STEP:
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

    def _current_ip(self):
        """Best-effort instruction pointer of the session's default thread."""
        if not self._session.tid:
            return None
        try:
            regs = self.get_registers(self._session.tid)
        except Exception:
            return None
        return regs.get("rip") or regs.get("eip")

    def _unreached(self, addr, reason):
        """TimeoutError saying the target never got to 'addr', and where it is."""
        ip = self._current_ip()
        where = f"last instruction pointer 0x{ip:X}" if ip else "no instruction pointer available"
        return TimeoutError(f"did not reach 0x{addr:X}: {reason} ({where})")

    def run_until(self, addr, timeout_ms=10000, max_wait_ms=60000,
                  max_idle_timeouts=None):
        """Run until execution reaches 'addr', or give up after a budget.

        Answers "did the target get there?" with a definite yes or no. The
        previous answer was a wall-clock guess: a run that printed nothing for
        210s could not be told apart from one that had reached the address and
        was merely quiet.

        A temporary breakpoint is placed at 'addr' and removed on the way out;
        if the caller already has one there, theirs is reused and left alone.
        The caller's other software breakpoints met along the way are stepped
        over transparently — the same treatment run() gives a callback that
        returns None.

        On success the target is left PAUSED at 'addr', with the original
        instruction in place (the INT3 has been removed and the instruction
        pointer rewound), so registers can be inspected. Resume it with
        continue_event().

        Args:
            addr: Address to run to.
            timeout_ms: WaitForDebugEvent timeout for each individual wait.
            max_wait_ms: Total wall-clock budget for the whole run.
            max_idle_timeouts: As for run() — how many consecutive empty waits
                to tolerate before calling it wedged. None disables the check.

        Returns:
            The DebugEvent delivered at 'addr'.

        Raises:
            TimeoutError: the target did not reach 'addr' within the budget, or
                exited first. The message carries the last instruction pointer.
            BreakpointError: a breakpoint hit could not be completed.
        """
        own_bp = None
        if self.find_breakpoint(addr) is None:
            own_bp = self.set_breakpoint(addr)

        deadline = time.monotonic() + max_wait_ms / 1000.0
        idle = 0
        try:
            while True:
                remaining_ms = int((deadline - time.monotonic()) * 1000)
                if remaining_ms <= 0:
                    raise self._unreached(
                        addr, f"{max_wait_ms} ms budget elapsed")

                event = self.wait_event(min(timeout_ms, remaining_ms))
                if event is None:
                    idle += 1
                    if max_idle_timeouts is not None and idle >= max_idle_timeouts:
                        raise self._unreached(
                            addr,
                            f"no debug event for {idle} consecutive waits")
                    continue
                idle = 0

                if event.type == "EXCEPTION":
                    code = event.exception_code
                    hit_addr = event.exception_addr

                    if code in (_pydbg.EXCEPTION_BREAKPOINT,
                                _pydbg.STATUS_WX86_BREAKPOINT):
                        degraded = self.brk_sw.degraded_hits
                        handled = self.brk_sw.handle_breakpoint_hit(
                            event.tid, hit_addr)
                        if self.brk_sw.degraded_hits != degraded:
                            raise BreakpointError(
                                f"breakpoint at 0x{hit_addr:X} (tid {event.tid}) "
                                f"could not be completed: "
                                f"{self.brk_sw.last_error}. The instruction "
                                f"pointer was not rewound, so resuming would "
                                f"execute from the middle of an instruction.")
                        if handled:
                            if hit_addr == addr:
                                return event
                            self.continue_event(event.pid, event.tid)
                            continue
                    elif code in (_pydbg.EXCEPTION_SINGLE_STEP,
                                  _pydbg.STATUS_WX86_SINGLE_STEP):
                        if self.brk_sw.handle_single_step(event.tid):
                            self.continue_event(event.pid, event.tid)
                            continue

                if event.type == "EXIT_PROCESS":
                    code = event.raw.get("exit_code", 1)
                    self.continue_event(event.pid, event.tid)
                    raise self._unreached(
                        addr, f"the process exited first with code {code}")

                self.continue_event(event.pid, event.tid)
        finally:
            if own_bp is not None:
                try:
                    self.remove_breakpoint(own_bp)
                except BreakpointError:
                    pass  # already gone (target overwrote it, or user removed it)

    def handle_bp_manual(self, tid, addr):
        """Manually handle breakpoint hit when using wait_event()/continue_event().

        Call this after receiving EXCEPTION_BREAKPOINT to properly manage
        the INT3 lifecycle (remove INT3 -> single-step -> re-arm).

        Returns True if the breakpoint was one of ours and was handled.

        Note: WOW64 (32-bit target on a 64-bit host) reports breakpoints as
        STATUS_WX86_BREAKPOINT (0x4000001F) instead of EXCEPTION_BREAKPOINT;
        check for either code (or for the single-step counterpart
        STATUS_WX86_SINGLE_STEP 0x4000001E).

        Example:
            event = dbg.wait_event()
            if (event.type == 'EXCEPTION'
                    and event.exception_code in (0x80000003, 0x4000001F)):
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
        h = self._get_read_handle(pid)
        return self.memory.read_handle(h, addr, size)

    def write_memory(self, addr, data, pid=None):
        h = self._get_process_handle(pid, need=self._NEED_VM_WRITE)
        return self.memory.write_handle(h, addr, data)

    def query_memory(self, addr, pid=None):
        h = self._get_read_handle(pid)
        return self.memory.query_handle(h, addr)

    def protect_memory(self, addr, size, protect, pid=None):
        h = self._get_process_handle(pid, need=self._NEED_VM_WRITE)
        return self.memory.protect_handle(h, addr, size, protect)

    def read_memory_safe(self, addr, size, pid=None, max_bytes=None):
        """Read memory without losing the readable parts of the range.

        read_memory() raises on the first unreadable page and discards what it
        already copied, so dumping memory or rebuilding an image around an
        uncommitted page used to need a hand-rolled page-by-page fallback.

        Returns a MemoryRead: 'data' is always 'size' bytes (unreadable spans
        zero-filled), 'gaps' lists what could not be read, 'complete' is True
        when nothing was missing. Never raises for unreadable memory — but
        ValueError for a 'size' over max_bytes, which defaults to
        pydbg.memory.manager.DEFAULT_MAX_READ, so a length field that lies
        cannot start a multi-gigabyte read.
        """
        h = self._get_read_handle(pid)
        kwargs = {} if max_bytes is None else {'max_bytes': max_bytes}
        return self.memory.read_safe_handle(h, addr, size, **kwargs)

    def enum_regions(self, pid=None, start=0, max_addr=0):
        """Enumerate the target's memory regions, ascending by address.

        Each dict: base_address, allocation_base, allocation_protect,
        region_size, state, protect, type. Covers free and reserved regions
        too, so a caller can tell "not committed" from "not there". Unlike
        query_memory this walks the whole chain; reaching the end of the
        address space ends the walk rather than raising.
        """
        h = self._get_read_handle(pid)
        return self.memory.regions_handle(h, start, max_addr)

    # ── delegated: modules ─────────────────────────────────────

    def enum_modules(self, pid=None):
        """List loaded modules. Falls back to event-observed images.

        EnumProcessModulesEx fails with ERROR_PARTIAL_COPY while the target
        sits on the loader breakpoint, and on WOW64 cannot see the 32-bit
        image until the loader has mapped it. Rather than fail exactly when
        module information is first wanted, this falls back to the bases
        reported by CREATE_PROCESS / LOAD_DLL ('source': 'events' marks those).
        """
        h = self._get_read_handle(pid)
        return self.modules.enumerate_handle(h, allow_event_fallback=True, pid=pid)

    def module_at(self, addr, pid=None):
        """Module containing 'addr', or None. See ModuleResolver.module_at."""
        return self.modules.module_at(addr, pid)

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

    def _as_thread_handle(self, h_thread):
        """Accept either a thread HANDLE or a thread id; return a usable handle.

        Both are plain Python ints, so they cannot be told apart by type. A tid
        passed where a handle belongs fails at runtime with ERROR_INVALID_HANDLE
        (errno 6), which points nowhere near the real cause — and since
        DebugEvent carries a tid, that is the mistake callers actually make.
        If the value is a thread id of the current target, open it and hand back
        a handle the caller must close; `_opened` reports which case it was.
        """
        if h_thread is None:
            raise ThreadError("no thread handle or id given")
        pid = self._session.pid
        if pid is not None:
            try:
                if h_thread in set(self.get_thread_ids(pid)):
                    return _pydbg.open_thread(h_thread), True
            except (OSError, ProcessError, ThreadError):
                pass  # cannot enumerate; fall back to treating it as a handle
        return h_thread, False

    def get_registers(self, h_thread):
        """Read thread context. Accepts a thread HANDLE or a thread id."""
        h, opened = self._as_thread_handle(h_thread)
        try:
            return self.thread.get_context(h)
        finally:
            if opened:
                _pydbg.close_handle(h)

    def set_registers(self, h_thread, context):
        """Write thread context. Accepts a thread HANDLE or a thread id."""
        h, opened = self._as_thread_handle(h_thread)
        try:
            return self.thread.set_context(h, context)
        finally:
            if opened:
                _pydbg.close_handle(h)

    def set_register(self, h_thread, name, value):
        """Write one register. Accepts a thread HANDLE or a thread id."""
        h, opened = self._as_thread_handle(h_thread)
        try:
            return self.thread.set_register(h, name, value)
        finally:
            if opened:
                _pydbg.close_handle(h)

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
        """Single-step. Accepts a thread HANDLE or a thread id."""
        h, opened = self._as_thread_handle(h_thread)
        try:
            self.thread.step(h)
        finally:
            if opened:
                _pydbg.close_handle(h)

    # ── delegated: breakpoints ─────────────────────────────────

    def set_breakpoint(self, addr, pid=None):
        # A software breakpoint writes to the target (INT3 plus a protection
        # change), so a read-only foreign handle is refused here by name.
        h = self._get_process_handle(pid, need=self._NEED_VM_WRITE)
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

    def set_hw_breakpoint(self, addr, condition="x", length=1, slot=0, tid=None):
        return self.brk_hw.set(addr, condition, length, slot, tid)

    def find_breakpoint(self, addr):
        return self.brk_sw.find(addr) or self.brk_hw.find(addr)

    def verify_breakpoints(self):
        """Report software breakpoints the target has overwritten.

        A software breakpoint can be silently erased by the code it sits in —
        self-unpacking targets overwrite their own entry point by design, and
        the breakpoint then just stops firing. Nothing raises when that
        happens, so this is how the state gets asked for rather than assumed.

        Returns [{'bp_id', 'addr', 'found'}] for each breakpoint whose INT3 is
        gone; 'found' is the byte actually at the address. Empty means every
        software breakpoint is intact.
        """
        report = []
        for bp_id in self.brk_sw.verify_all():
            bp_info = self._session.breakpoints.get(bp_id)
            if bp_info is None:
                continue
            addr = bp_info[1]
            h_process = bp_info[3] if len(bp_info) > 3 else self._session.process_handle
            try:
                found = self.memory.read_handle(h_process, addr, 1)
            except Exception:
                found = None
            report.append({'bp_id': bp_id, 'addr': addr, 'found': found})
        return report

    def breakpoint_report(self):
        """Every software breakpoint: still armed? and how many hits so far?

        Answers the question a zero cannot. "This site never executes" and
        "the probe was never armed" both used to look identical — a run that
        produced no hit at all, with nothing to inspect afterwards — and one
        real session drew a false negative from exactly that (the target sat
        on a modal dialog, so the whole round produced zero hits in complete
        silence, and it read as proof that the function was never called).

        Each entry is a dict:

            bp_id  as returned by set_breakpoint()
            addr   the address the breakpoint was set at
            hits   times delivered since it was armed; 0 is a real answer,
                   meaning armed and never reached
            armed  True  the INT3 is in the target right now
                   False the byte is there and is no longer 0xCC — the target
                         overwrote it (verify_breakpoints() reports these)
                   None  the byte could not be read at all

        A bp_id that is absent from this report was never armed at all. So the
        three states are distinguishable in one place: absent means "never
        armed", (armed=True, hits=0) means "armed, never hit" — the state that
        was previously unaskable — and hits > 0 is a count.

        Hardware breakpoints are not listed: a Dr0-3 hit arrives as an ordinary
        single-step event, which this session does not attribute to a slot, so
        there is no honest hit count to report for one. They are still visible
        through find_breakpoint() / session.breakpoints.

        One memory read per software breakpoint, and it updates
        brk_sw.lost the same way verify_breakpoints() does.
        """
        report = []
        for bp_id, bp_info in sorted(self._session.breakpoints.items()):
            if bp_info[0] != "int3":
                continue
            armed = self.brk_sw.armed_state(bp_id)
            if armed is True:
                self.brk_sw.lost.discard(bp_id)
            else:
                self.brk_sw.lost.add(bp_id)
            report.append({
                'bp_id': bp_id,
                'addr': bp_info[1],
                'hits': self.brk_sw.hits.get(bp_id, 0),
                'armed': armed,
            })
        return report

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
