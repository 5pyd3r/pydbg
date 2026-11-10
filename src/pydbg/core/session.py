"""DebugSession — pure state holder for the debugger session."""

import struct
from dataclasses import dataclass, field


@dataclass
class ChildProcessInfo:
    """Info about a child process being debugged."""
    pid: int
    tid: int                    # 主线程 ID
    process_handle: int         # OpenProcess 返回的句柄
    thread_handle: int          # 主线程句柄
    base_of_image: int = 0      # 加载基址
    exit_code: int | None = None  # 退出后填入


@dataclass
class DebugSession:
    """Holds debug session state. No logic — pure data."""

    process_handle: int | None = None
    thread_handle: int | None = None
    pid: int | None = None
    tid: int | None = None
    host_arch: int = struct.calcsize("P") * 8  # 32 or 64
    bp_counter: int = 0
    breakpoints: dict = field(default_factory=dict)  # id -> (type, addr, extra)
    # Breakpoint lifecycle: tid -> (bp_id, addr, original_bytes)
    pending_single_step: dict = field(default_factory=dict)
    # Set once the main target has been terminated: the handles stay open so
    # get_exit_code() still answers, but nothing is left to detach from.
    terminated: bool = False

    # Child process debugging
    debug_children: bool = False
    child_processes: dict = field(default_factory=dict)  # pid -> ChildProcessInfo

    # Processes opened by pid that we are NOT debugging (see Debugger.open_process).
    # The nested-debugging case: the memory wanted belongs to the debuggee of the
    # process we attached to, which never arrives as a CREATE_PROCESS event and is
    # therefore not in child_processes. pid -> HANDLE, and pid -> access mask it
    # was opened with, so a later request for different rights reopens instead of
    # silently handing back a handle that cannot do what was asked.
    foreign_handles: dict = field(default_factory=dict)
    foreign_access: dict = field(default_factory=dict)

    # The one place a process's architecture lives: pid -> 32 | 64. A thread
    # has no architecture of its own, only its process's — see tid_pid below.
    # The key None holds the answer used before any target exists, which is
    # also what target_arch answers then.
    pid_arch: dict = field(default_factory=dict)
    # tid -> pid, so arch_for_tid can reach the process a thread belongs to.
    tid_pid: dict = field(default_factory=dict)

    # Modules observed through debug events: pid -> {base_address: record}.
    # CREATE_PROCESS and LOAD_DLL name every image the loader maps, with no
    # syscall and no dependence on the process being far enough along for
    # EnumProcessModulesEx — which is the whole point, because that call fails
    # with ERROR_PARTIAL_COPY while the target sits on the loader breakpoint.
    loaded_modules: dict = field(default_factory=dict)

    def record_module(self, pid, base_address, handle=0):
        """Record an image seen in a debug event. Idempotent per (pid, base).

        Only the base address (and its HMODULE alias) is known here; arch, size
        and name are resolved lazily by ModuleResolver, which owns the PE
        reads. Returns the record, or None if no base address was given.
        """
        if not base_address or pid is None:
            return None
        mods = self.loaded_modules.setdefault(pid, {})
        rec = mods.get(base_address)
        if rec is None:
            rec = {
                'handle': handle or base_address,
                'base_address': base_address,
                'name': '',
                'size': 0,
                'arch': 'unknown',
                'source': 'events',
            }
            mods[base_address] = rec
        return rec

    def modules_for(self, pid):
        """Event-observed modules for 'pid', ascending by base address."""
        if pid is None:
            return []
        mods = self.loaded_modules.get(pid)
        if not mods:
            return []
        return [mods[base] for base in sorted(mods)]

    @property
    def target_arch(self):
        """The main target's architecture: 32 or 64.

        Derived from pid_arch every time, so there is no second copy to drift
        out of step. With no target yet this answers the architecture recorded
        before one existed, or the host's — what an unattached disassembler
        should assume.
        """
        if self.pid is not None:
            arch = self.pid_arch.get(self.pid)
            if arch:
                return arch
        return self.pid_arch.get(None) or self.host_arch

    @target_arch.setter
    def target_arch(self, arch):
        """Record the architecture. Keyed by pid, or None before there is one."""
        self.pid_arch[self.pid] = arch

    def register_pid_arch(self, pid, arch):
        """Record the architecture (32/64) of a process by pid."""
        if pid is None:
            return
        self.pid_arch[pid] = arch

    def register_thread(self, tid, pid):
        """Record which process a thread belongs to (threads have no arch)."""
        if tid is None or pid is None:
            return
        self.tid_pid[tid] = pid

    def arch_for_pid(self, pid):
        """Architecture of 'pid', falling back to the main target's."""
        if pid is not None:
            arch = self.pid_arch.get(pid)
            if arch:
                return arch
        return self.target_arch

    def arch_for_tid(self, tid):
        """Architecture of the process 'tid' belongs to.

        A thread created before attach, or one never seen in a debug event, is
        not in tid_pid; the main target's architecture is the only honest
        answer left, and it is the right one for every single-process session.
        """
        return self.arch_for_pid(self.tid_pid.get(tid))
