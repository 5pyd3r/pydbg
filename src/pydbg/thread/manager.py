"""ThreadManager — thread open/context/suspend/resume/enumerate/step."""

from .. import _pydbg
from ..exceptions import ThreadError

# dbghelp/IMAGE_FILE machine constants for the two architectures this package
# walks. StackWalker spells the same values on its own class; callers may pass
# either form (or 'x86'/'x64') where a machine is wanted.
MACHINE_X86 = 0x14C
MACHINE_X64 = 0x8664

_ARCH_BY_NAME = {'x86': 32, 'x32': 32, 'i386': 32, 'x64': 64, 'amd64': 64}


def arch_for_machine(machine):
    """The 32/64 architecture a machine specification names, or None.

    Accepts the forms callers actually hold: None (meaning "ask the target"),
    the extension's 32/64, the dbghelp machine constants MACHINE_X86 /
    MACHINE_X64, and the strings 'x86'/'x64'. Anything else raises ValueError
    instead of quietly unwinding a WOW64 stack with x64 rules.
    """
    if machine is None:
        return None
    if isinstance(machine, str):
        arch = _ARCH_BY_NAME.get(machine.strip().lower())
        if arch is None:
            raise ValueError(
                f"unknown machine {machine!r}; expected 'x86' or 'x64'")
        return arch
    if machine in (32, MACHINE_X86):
        return 32
    if machine in (64, MACHINE_X64):
        return 64
    raise ValueError(
        f"unknown machine {machine!r}; expected 'x86'/'x64' or "
        f"MACHINE_X86 (0x{MACHINE_X86:X}) / MACHINE_X64 (0x{MACHINE_X64:X})")


def arch_for(session, h_thread, machine=None):
    """Resolve a machine specification to 32/64 for one thread.

    machine=None asks the session which process the thread belongs to — the
    same single source of truth every other thread operation uses — and falls
    back to the main target when the thread cannot be resolved. An explicit
    machine wins.
    """
    arch = arch_for_machine(machine)
    if arch is not None:
        return arch
    try:
        tid = _pydbg.get_thread_id(h_thread)
    except OSError:
        tid = None
    lookup = getattr(session, 'arch_for_tid', None)
    if tid is not None and lookup is not None:
        return lookup(tid)
    return getattr(session, 'target_arch', 64)


class ThreadManager:
    """Manages thread operations for the debugged process."""

    def __init__(self, session):
        self._s = session

    def open(self, tid):
        try:
            return _pydbg.open_thread(tid)
        except OSError as e:
            raise ThreadError(f"OpenThread for tid {tid}: {e}")

    def _machine_for(self, h_thread):
        """Resolve the machine (32/64) for a thread handle, falling back to the
        main target architecture when the thread cannot be resolved."""
        return arch_for(self._s, h_thread)

    def get_context(self, h_thread):
        try:
            return _pydbg.get_thread_context(h_thread, self._machine_for(h_thread))
        except OSError as e:
            raise ThreadError(f"GetThreadContext: {e}")

    def get_context_bytes(self, h_thread, *, machine=None):
        """Capture a thread's raw CONTEXT bytes for stack walking.

        get_context() answers with a register dict and frees its buffer;
        StackWalk64 needs the CONTEXT bytes themselves. The returned length is
        the architecture's CONTEXT size — 1232 bytes on x64, 716 on WOW64.

        machine: None asks the target (the same arch_for_tid source the rest
        of the thread layer uses); 'x86'/'x64', 32/64 and MACHINE_X86 /
        MACHINE_X64 state it explicitly. Raises ThreadError on failure.
        """
        if h_thread is None:
            raise ThreadError("get_context_bytes: no thread handle given")
        arch = arch_for(self._s, h_thread, machine)
        try:
            return _pydbg.get_thread_context_bytes(h_thread, arch)
        except OSError as e:
            raise ThreadError(f"GetThreadContext: {e}")

    def set_context(self, h_thread, context):
        try:
            _pydbg.set_thread_context(h_thread, context, self._machine_for(h_thread))
        except OSError as e:
            raise ThreadError(f"SetThreadContext: {e}")

    def set_register(self, h_thread, name, value):
        self.set_context(h_thread, {name.lower(): value})

    def suspend(self, h_thread):
        try:
            return _pydbg.suspend_thread(h_thread)
        except OSError as e:
            raise ThreadError(f"SuspendThread: {e}")

    def resume(self, h_thread):
        try:
            return _pydbg.resume_thread(h_thread)
        except OSError as e:
            raise ThreadError(f"ResumeThread: {e}")

    def enumerate(self, pid):
        try:
            return _pydbg.enumerate_threads(pid)
        except OSError as e:
            raise ThreadError(f"EnumerateThreads: {e}")

    def get_ids(self, pid):
        return [t["tid"] for t in self.enumerate(pid)]

    def step(self, h_thread):
        regs = self.get_context(h_thread)
        regs["eflags"] = regs.get("eflags", 0) | 0x100
        self.set_context(h_thread, regs)

    def teardown(self):
        """Undo nothing: this manager opens no handle and keeps no record.

        It writes the target (context, suspend/resume), so it belongs in the
        teardown chain (ADR-0004), but it owns no artifact to release: `open()`
        hands the handle to the caller, every context/suspend call acts on a
        caller-owned handle, and `Debugger.close()` closes the session's own
        thread handle. Returning () is the honest answer, not a placeholder.
        """
        return ()
