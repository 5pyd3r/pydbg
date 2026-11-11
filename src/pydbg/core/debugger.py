"""Debugger — high-level debugging API with composition pattern."""

import struct
import time
from dataclasses import dataclass

from .. import _pydbg
from ..breakpoint.hardware import HardwareBreakpointManager
from ..breakpoint.outcome import HandleOutcome
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
    TeardownError,
    ThreadError,
    TimeoutError,
)
from ..instrument.instrumenter import Instrumenter
from ..memory.manager import MemoryManager
from ..module.resolver import ModuleResolver
from ..symbol.resolver import SymbolResolver
from ..thread.manager import ThreadManager
from .event import DebugEvent
from .process import ProcessManager, enumerate_processes
from .session import DebugSession
from .status import ExitReason, ExitStatus
from .windows import Windows
from .window_probe import MessageLoopState


def _timeout(message, probe=None):
    """A TimeoutError carrying what was learned about the target.

    The class is unchanged, so `except PydbgError` / `except TimeoutError`
    callers are unaffected; what is new is that the probe's answer and its
    caveat travel with the exception instead of being rendered into a sentence
    and thrown away. A caller that wants to branch on the cause can, and one
    that only prints the message still gets a message that names it.
    """
    error = TimeoutError(message)
    error.probe = probe
    error.caveat = probe.caveat if probe is not None else None
    return error


def _caveat(probe):
    return f" {probe.caveat}." if probe.caveat else ""


@dataclass(frozen=True)
class _Dispatch:
    """What one EXCEPTION event means for the debugger loop.

    'deliver' says whether the event belongs to the caller's callback: a
    breakpoint we own is the user's event, the single-step that follows it is
    ours and never leaves this class.
    """

    outcome: HandleOutcome
    deliver: bool


class Debugger:
    """Main debugger class. Procedural API for Win32 debugging."""

    def __init__(self):
        self._session = DebugSession()
        self.process = ProcessManager(self._session)
        self.windows = Windows(self._session)
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
        self.instrumenter = Instrumenter(self._session)
        self.stack_walker = StackWalker(self._session)

    # The masks live on ProcessManager; these aliases are what the call sites
    # in this class still spell.
    _READ_ACCESS = ProcessManager.READ_ACCESS
    _READ_ACCESS_LIMITED = ProcessManager.READ_ACCESS_LIMITED
    _NEED_VM_WRITE = ProcessManager.NEED_VM_WRITE
    _NEED_TERMINATE = ProcessManager.NEED_TERMINATE

    def _get_process_handle(self, pid=None, need=0):
        """Strict resolution: the target, a debug child, or an opened pid."""
        return self.process.handle(pid, need)

    def _get_read_handle(self, pid=None):
        """Permissive resolution: opens an unknown pid on demand."""
        return self.process.read_handle(pid)

    def _close_foreign_handles(self):
        """Release every handle open_process() handed out. Never raises."""
        self.process.release_all()

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
        self._session.terminated = False
        self._session.register_pid_arch(pid, self._detect_target_arch(h_proc))
        self._session.register_thread(tid, pid)
        return (pid, tid)

    def _detect_target_arch(self, h_process):
        """Detect if target process is 32-bit (WoW64) or 64-bit."""
        if struct.calcsize("P") != 8:
            return 32
        # Ask Windows rather than guessing: a failed query used to be swallowed
        # and answered "64", which mislabelled every WOW64 target and made the
        # rest of the session read 64-bit context structs from a 32-bit process.
        try:
            is_wow64 = _pydbg.is_wow64_process(h_process)
        except OSError as e:
            raise ProcessError(
                f"cannot determine target architecture: {e}") from e
        return 32 if is_wow64 else 64

    def attach(self, pid):
        try:
            _pydbg.debug_active_process(pid)
        except OSError as e:
            raise ProcessError(f"Failed to attach to pid {pid}: {e}")
        self._session.pid = pid
        self._session.terminated = False

        # Open process handle so memory/thread operations work immediately.
        # If full access fails, still detect the target architecture via a
        # query-only handle so a WOW64 target never falls back to native-64
        # register contexts.
        try:
            h_proc = _pydbg.open_process(pid)
            self._session.process_handle = h_proc
            self._session.register_pid_arch(pid, self._detect_target_arch(h_proc))
        except OSError:
            try:
                q = _pydbg.open_process(pid, 0x1000)  # PROCESS_QUERY_LIMITED_INFORMATION
                try:
                    self._session.register_pid_arch(
                        pid, self._detect_target_arch(q))
                finally:
                    _pydbg.close_handle(q)
            except OSError:
                pass  # arch stays unknown; wait_event/continue_event still usable

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

    # What close() undoes, in the order it undoes it. Hooks go first because
    # they redirect control flow into memory that later steps release; the
    # INT3s go after the debug registers, because a single-step that still has
    # a stale DR slot fires inside the code that was just restored.
    _TEARDOWN_ORDER = (
        "hook_iat", "hook_inline", "instrumenter",
        "brk_hw", "brk_sw", "symbols",
    )

    def close(self):
        """Undo everything this session installed, then let go of the target.

        Each manager undoes its own work (ADR-0004). Every step is attempted
        even when an earlier one fails, and what could not be undone comes back
        as one TeardownError: stopping at the first failure is how a target is
        left with a detour pointing into freed memory and nobody looking.

        Idempotent — managers forget what they already undid.
        """
        problems = []
        for name in self._TEARDOWN_ORDER:
            teardown = getattr(getattr(self, name, None), "teardown", None)
            if teardown is None:
                continue
            try:
                problems.extend(teardown() or [])
            except Exception as exc:      # a teardown must not abort the chain
                problems.append((name, str(exc)))
        try:
            self._stop_debugging(self._session.pid)
        except ProcessError as exc:
            problems.append(("DebugActiveProcessStop", str(exc)))
        finally:
            self._release_handles()
        if problems:
            raise TeardownError(problems)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            self.close()
        except TeardownError:
            # Never mask the exception that brought us here; on a clean exit
            # the failure is the thing to report.
            if exc_type is None:
                raise
        return False

    def _stop_debugging(self, pid):
        """Stop being the debugger of 'pid'. No-op once the target is gone."""
        if pid is None or self._session.terminated:
            return
        if pid == self._session.pid and self._session.process_handle is None:
            return  # the main target is already released; nothing to detach
        try:
            _pydbg.debug_active_process_stop(pid)
        except OSError as e:
            raise ProcessError(f"Failed to detach from pid {pid}: {e}")

    def _release_handles(self):
        """Close every handle this session opened. Never raises."""
        self._close_foreign_handles()
        for child in self._session.child_processes.values():
            for attr in ("thread_handle", "process_handle"):
                h = getattr(child, attr, None)
                if h:
                    try:
                        _pydbg.close_handle(h)
                    except OSError:
                        pass
                    setattr(child, attr, None)
        self._session.child_processes.clear()
        for name in ("thread_handle", "process_handle"):
            h = getattr(self._session, name, None)
            if h:
                try:
                    _pydbg.close_handle(h)
                except OSError:
                    pass
                setattr(self._session, name, None)

    def detach(self, pid=None):
        """Stop debugging. Detaching the main target is close()."""
        if pid is None and self._session.pid is None:
            raise ProcessError("No process to detach from")
        if pid is None or pid == self._session.pid:
            self.close()
            return
        self._stop_debugging(pid)
        child = self._session.child_processes.pop(pid, None)
        if child is not None:
            for attr in ("thread_handle", "process_handle"):
                h = getattr(child, attr, None)
                if h:
                    try:
                        _pydbg.close_handle(h)
                    except OSError:
                        pass

    def terminate_process(self, exit_code=1, pid=None):
        """Kill the target and forget what was installed in it.

        The bytes cannot be put back after a kill, so this discards the records
        instead of pretending to undo them. The process handle stays open —
        reading the exit code is the one thing it is still good for; call
        close() to release it.
        """
        h = self._get_process_handle(pid, need=self._NEED_TERMINATE)
        try:
            _pydbg.terminate_process(h, exit_code)
        except OSError as e:
            raise ProcessError(f"TerminateProcess failed: {e}")
        main = pid is None or pid == self._session.pid
        if main:
            self._session.terminated = True
            for name in self._TEARDOWN_ORDER:
                discard = getattr(getattr(self, name, None), "discard", None)
                if discard is not None:
                    discard()
            # Drain events only for main process
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

        # Every event names the process its thread belongs to. Recording it
        # here (not only on CREATE_THREAD) covers threads that existed before
        # attach and therefore never produce a creation event.
        self._session.register_thread(event.tid, event.pid)

        # Replicate process-wide hardware breakpoints to newly created threads
        # of THIS process (DR registers are per-thread; child processes must
        # not inherit the parent's process-wide breakpoints).
        if event.type == "CREATE_THREAD" and event.pid == self._session.pid:
            for bp_id, bp in self._session.breakpoints.items():
                if bp.kind == "hw" and bp.scope is None and bp.pid is None:
                    try:
                        h = _pydbg.open_thread(event.tid)
                        try:
                            self.brk_hw._arm_thread(
                                h,
                                bp.addr,
                                bp.slot,
                                bp.condition,
                                bp.length,
                                self._session.arch_for_tid(event.tid),
                            )
                        finally:
                            _pydbg.close_handle(h)
                    except OSError:
                        pass  # thread may already be gone; skip replication

        # The main process's CREATE_PROCESS (idempotent; covers attach mode
        # where create_process wasn't used).
        if event.type == "CREATE_PROCESS" and event.pid == self._session.pid:
            self._session.register_thread(event.tid, event.pid)

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

    # ── lifecycle: children ────────────────────────────────────

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

        snapshot = enumerate_processes()
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
        # register context even when it differs from the parent's. A failed
        # query leaves the child unregistered and arch_for_pid falls back to
        # the parent's — wrong only for a cross-arch child whose header could
        # not be read, and that is a read failure, not a silent 64-bit guess.
        if h_proc:
            try:
                self._session.register_pid_arch(
                    event.pid, self._detect_target_arch(h_proc))
            except ProcessError:
                pass
        self._session.register_thread(event.tid, event.pid)
        self._session.child_processes[event.pid] = info

    def _unregister_child(self, event):
        """Unregister a child process from EXIT_PROCESS event."""
        child = self._session.child_processes.get(event.pid)
        if child is not None:
            child.exit_code = event.raw.get("exit_code")

    def continue_event(self, pid=None, tid=None):
        """Continue a paused debug event.

        Fails loudly unless the pid/tid pair is simply no longer a paused
        event (ERROR_INVALID_PARAMETER) — which is what continuing after a
        target, usually a child, has already exited looks like. Every other
        failure used to vanish here as well.
        """
        try:
            _pydbg.continue_debug_event(
                pid or self._session.pid, tid or self._session.tid
            )
        except OSError as e:
            if getattr(e, "errno", None) == 87:      # ERROR_INVALID_PARAMETER
                return
            raise ProcessError(
                f"ContinueDebugEvent(pid={pid or self._session.pid}, "
                f"tid={tid or self._session.tid}): {e}") from e

    def _dispatch_exception(self, event):
        """Run the breakpoint/single-step lifecycle for one EXCEPTION event.

        run(), run_until() and the manual helpers all need this answer, and
        each used to spell it out again — including the "compare a counter
        before and after" step that the manual path quietly left out, so a
        failed IP rewind there still answered True.
        """
        code = event.exception_code
        if code in (_pydbg.EXCEPTION_BREAKPOINT, _pydbg.STATUS_WX86_BREAKPOINT):
            outcome = self.brk_sw.handle_breakpoint_hit(
                event.tid, event.exception_addr)
            return _Dispatch(outcome, deliver=outcome is HandleOutcome.HANDLED)
        if code in (_pydbg.EXCEPTION_SINGLE_STEP,
                    _pydbg.STATUS_WX86_SINGLE_STEP):
            outcome = self.brk_sw.handle_single_step(event.tid)
            return _Dispatch(outcome, deliver=False)
        return _Dispatch(HandleOutcome.NOT_MINE, deliver=True)

    def _degraded_message(self, tid, addr):
        """The one sentence both loops and the manual path raise."""
        return (
            f"breakpoint at 0x{addr:X} (tid {tid}) could not be completed: "
            f"{self.brk_sw.last_error}. The instruction pointer was not "
            f"rewound, so resuming would execute from the middle of an "
            f"instruction.")

    def run(self, callback, timeout_ms=10000, max_idle_timeouts=None,
            probe_on_idle=True):
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

        Returns:
            ExitStatus: why the loop stopped, and the exit code when there was
            one. A callback that returns False stops the loop while the target
            is still running, so exit_code is None and the reason says so —
            the old int return used 1 for that *and* for an exit code of 1.
        """
        idle = 0
        while True:
            event = self.wait_event(timeout_ms)
            if event is None:
                idle += 1
                if max_idle_timeouts is not None and idle >= max_idle_timeouts:
                    raise self._idle_timeout(idle, timeout_ms, probe_on_idle)
                continue
            idle = 0

            # Auto-handle breakpoint lifecycle (one implementation, shared with
            # run_until() and the manual helpers; see _dispatch_exception).
            if event.type == "EXCEPTION":
                dispatch = self._dispatch_exception(event)
                if dispatch.outcome is HandleOutcome.DEGRADED:
                    raise BreakpointError(
                        self._degraded_message(event.tid, event.exception_addr))
                if dispatch.outcome is HandleOutcome.HANDLED:
                    if dispatch.deliver and callback(event) is False:
                        return ExitStatus(None, ExitReason.STOPPED_BY_CALLBACK)
                    self.continue_event(event.pid, event.tid)
                    continue  # the re-arming single-step is ours, not the user's

            result = callback(event)
            if result is False:
                return ExitStatus(None, ExitReason.STOPPED_BY_CALLBACK)

            if event.type == "EXIT_PROCESS":
                exit_code = event.raw.get("exit_code", 1)
                self.continue_event(event.pid, event.tid)
                return ExitStatus(exit_code, ExitReason.TARGET_EXITED)

            self.continue_event(event.pid, event.tid)

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

    def _idle_timeout(self, idle, timeout_ms, probe_on_idle=True):
        """The exception for a run that saw no events, with what is known.

        The old message named three causes and separated none of them:
        "the target is idle, blocked, or wedged". That sentence is how a
        target sitting on a modal dialog got read as a component that does not
        write files — the zeros were real and the conclusion drawn from them
        was backwards. So the probe runs here, at the moment the threshold
        trips and nowhere else, and its answer goes into the message.
        """
        prefix = (f"no debug event for {idle} consecutive waits "
                  f"({timeout_ms} ms each)")
        if not probe_on_idle:
            return _timeout(
                f"{prefix}; the target is idle, blocked, or wedged. "
                f"cannot rule out that the target is blocked: the window "
                f"probe was disabled (probe_on_idle=False)", probe=None)

        probe = self.windows.probe()
        if probe is None:
            return _timeout(
                f"{prefix}. cannot rule out that the target is blocked: the "
                f"window probe is unavailable on this platform", probe=None)

        if probe.state is MessageLoopState.MODAL:
            detail = (f"the target is waiting on a dialog it cannot dismiss "
                      f"itself ({probe.evidence})")
        elif probe.state is MessageLoopState.WEDGED:
            detail = (f"the target's window thread is not answering messages "
                      f"({probe.evidence})")
        elif probe.state is MessageLoopState.GONE:
            detail = "the target has exited"
        elif probe.state is MessageLoopState.PUMPING:
            detail = (f"the target is pumping messages ({probe.evidence}) and "
                      f"simply produced no debug event")
        else:
            detail = (f"cannot rule out that the target is blocked "
                      f"({probe.evidence})")
        return _timeout(f"{prefix}. {detail}.{_caveat(probe)}", probe=probe)

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
                    dispatch = self._dispatch_exception(event)
                    if dispatch.outcome is HandleOutcome.DEGRADED:
                        raise BreakpointError(
                            self._degraded_message(
                                event.tid, event.exception_addr))
                    if dispatch.outcome is HandleOutcome.HANDLED:
                        if dispatch.deliver and event.exception_addr == addr:
                            return event
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

        Raises:
            BreakpointError: it was ours but could not be completed. The manual
                path used to answer True here as well, which made a failed IP
                rewind indistinguishable from a good hit.

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
        outcome = self.brk_sw.handle_breakpoint_hit(tid, addr)
        if outcome is HandleOutcome.DEGRADED:
            raise BreakpointError(self._degraded_message(tid, addr))
        return outcome is HandleOutcome.HANDLED

    def handle_ss_manual(self, tid):
        """Manually handle single-step after breakpoint. Call after EXCEPTION_SINGLE_STEP."""
        return self.brk_sw.handle_single_step(tid) is HandleOutcome.HANDLED

    def remove_all_breakpoints(self):
        """Remove all software breakpoints, restoring original bytes.
        Call before detach() to avoid leaving stale INT3 bytes in code."""
        for bp_id in list(self._session.breakpoints):
            bp = self._session.breakpoints.get(bp_id)
            if bp is not None and bp.kind == "int3":
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

    def parse_loaded_dll(self, event):
        """PE for the image a LOAD_DLL event announced.

        Parses the image where it is mapped (LoadedView over process memory):
        that is where the directories actually point, and it reflects any
        runtime fixups. Falls back to the file the loader named when the image
        is no longer readable — a stale event, or a module already unloaded.

        The event carries the path rather than the file's bytes on purpose:
        copying every loaded DLL into the event stream costs hundreds of
        megabytes per process, and most callers never look.

        Raises PydbgError when the event has neither a readable image nor a
        usable path.
        """
        base = getattr(event, 'dll_base', 0) or 0
        path = getattr(event, 'dll_path', '') or ''
        from ..analysis.process_source import ProcessSource
        from ..exceptions import PydbgError
        from ..pe import PE
        from ..pe.view import LoadedView

        if base:
            try:
                return PE.from_source(ProcessSource(self._session, base),
                                      LoadedView(), va_base=base)
            except (PydbgError, OSError):
                if not path:
                    raise
        if not path:
            raise PydbgError(
                "LOAD_DLL event carries neither a readable image nor a path")
        return PE.from_file(path)

    def get_module_filename(self, h_module):
        return self.modules.get_filename(h_module)

    def find_module(self, name):
        """Find a module by basename (e.g. 'kernel32.dll')."""
        return self.modules.find_module(name)

    # ── delegated: symbols ──────────────────────────────────────

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
        """Arm an INT3 breakpoint and return its bp_id.

        Idempotent per (process, address): arming an address that already has
        one returns the existing bp_id instead of writing a second INT3 over
        the first. 'pid' selects the process; the same address in a child and
        in the parent are two different breakpoints.

        A software breakpoint writes to the target (INT3 plus a protection
        change), so a read-only foreign handle is refused here by name.

        Raises:
            BreakpointError: the INT3 could not be written.
        """
        h = self._get_process_handle(pid, need=self._NEED_VM_WRITE)
        return self.brk_sw.set_handle(h, addr)

    def remove_breakpoint(self, bp_id):
        bp = self._session.breakpoints.get(bp_id)
        if bp is None:
            raise BreakpointError(f"Breakpoint {bp_id} not found")

        if bp.kind == "int3":
            return self.brk_sw.remove(bp_id)
        elif bp.kind == "hw":
            return self.brk_hw.remove(bp_id)
        else:
            raise BreakpointError(
                f"Unknown breakpoint type '{bp.kind}' for bp_id {bp_id}"
            )

    def set_hw_breakpoint(self, addr, condition="x", length=1, slot=0, tid=None,
                          pid=None):
        return self.brk_hw.set(addr, condition, length, slot, tid, pid)

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
            bp = self._session.breakpoints.get(bp_id)
            if bp is None:
                continue
            h_process = bp.h_process or self._session.process_handle
            try:
                found = self.memory.read_handle(h_process, bp.addr, 1)
            except Exception:
                found = None
            report.append({'bp_id': bp_id, 'addr': bp.addr, 'found': found})
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
        for bp_id, bp in sorted(self._session.breakpoints.items()):
            if bp.kind != "int3":
                continue
            armed = self.brk_sw.armed_state(bp_id)
            if armed is True:
                self.brk_sw.lost.discard(bp_id)
            else:
                self.brk_sw.lost.add(bp_id)
            report.append({
                'bp_id': bp_id,
                'addr': bp.addr,
                'hits': bp.hits,
                'armed': armed,
            })
        return report

    # ── exception helpers ──────────────────────────────────────

    def exception_code_to_str(self, code):
        return _pydbg.exception_code_to_str(code)

    def get_exception_info(self, code, addr, first_chance, exception_params):
        return _pydbg.get_exception_info(code, addr, first_chance, exception_params)
