"""ProcessManager — the one place a process handle is resolved.

Before this, three call sites answered "which handle for this pid" three
different ways: Debugger's read path opened an unknown pid on demand, its
write path refused one, ModuleResolver returned None, and the hook and
instrumentation classes read session.process_handle directly and ignored pid
entirely. They disagreed about all three of the things that matter — is an
unknown pid an error, may a handle be opened on demand, and what rights must
it carry.
"""

from .. import _pydbg
from ..exceptions import ProcessError


class ProcessManager:
    """Handles for the debug target, its debug children, and foreign pids."""

    # Access rights for a process opened by pid that we are not debugging.
    # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ is the pair a prior session
    # proved sufficient to read a real image out of another debugger's
    # debuggee; QUERY_LIMITED_INFORMATION is the fallback for processes that
    # refuse the broader query right.
    READ_ACCESS = 0x0410
    READ_ACCESS_LIMITED = 0x1010
    # What a foreign handle must carry before a write/terminate path may use
    # it, so a read-only handle is refused by name instead of failing later as
    # ERROR_NOACCESS out of the syscall that wanted the right.
    NEED_VM_WRITE = 0x0028         # PROCESS_VM_WRITE | PROCESS_VM_OPERATION
    NEED_TERMINATE = 0x0001        # PROCESS_TERMINATE

    def __init__(self, session):
        self._s = session

    def handle(self, pid=None, need=0):
        """Return a process handle for the main target, a debug child, or a
        process already opened by pid via open().

        Deliberately strict: a pid that was never opened is an error here.
        This is the handle used by the paths that *write* to a process
        (write_memory, protect_memory) and by terminate_process, where
        opening an arbitrary pid on request would turn 'terminate the thing I
        am debugging' into 'terminate whatever pid was passed'. Reading keeps
        a separate, more permissive path — see read_handle.

        'need' is the access mask a handle opened by open() must carry for
        this operation. The target's own handle and a debug child's are taken
        as having it: they come from create_process/DEBUG_PROCESS, not from a
        mask this class chose.
        """
        if pid is None or pid == self._s.pid:
            return self._s.process_handle
        child = self._s.child_processes.get(pid)
        if child is not None:
            return child.process_handle
        opened = self._s.foreign_handles.get(pid)
        if opened is None:
            raise ProcessError(f"Unknown process pid={pid}")
        have = self._s.foreign_access.get(pid, 0)
        if need and (have & need) != need:
            raise ProcessError(
                f"pid {pid} was opened with access 0x{have:X}, which does not "
                f"include 0x{need:X} needed here. close_process({pid}) and "
                f"reopen it with open_process({pid}, access=0x{have | need:X}).")
        return opened

    def try_handle(self, pid):
        """Handle for a *known* pid, or None. Never opens anything.

        This is the answer ModuleResolver needs: "is this address inside a
        process I can read?" is a question, and an unknown pid is a valid
        answer to it rather than an error.
        """
        if pid is None:
            return None
        try:
            return self.handle(pid)
        except ProcessError:
            return None

    def read_handle(self, pid=None):
        """Handle for reading: as handle(), but a pid that is neither the
        target nor a debug child is opened on demand.

        This is the nested-debugging case. After attach() to a debugger, the
        memory that matters usually belongs to the process *it* is debugging:
        that process is not our debug child, it produces no CREATE_PROCESS
        event for us, so get_child_processes() stays empty and read_memory()
        used to answer ProcessError("Unknown process pid"). Reaching it meant
        OpenProcess + ReadProcessMemory through ctypes in the caller.
        """
        if pid is None or pid == self._s.pid:
            return self._s.process_handle
        child = self._s.child_processes.get(pid)
        if child is not None:
            return child.process_handle
        return self.open(pid)

    def open(self, pid, access=None):
        """Open a handle to any process by pid so its memory can be read.

        Not a debugging relationship: nothing is attached, the process is not
        suspended, and no debug events will arrive for it. The handle is
        cached on the session (so repeated read_memory(pid=) calls reuse it)
        and released by close() or release_all().

        The default access mask is read-only, and that is what the rest of the
        library then allows: the read paths work by pid, while write_memory,
        protect_memory, set_breakpoint and terminate_process keep requiring
        either the debug target, a debug child, or a handle opened here with a
        mask that grants it. Pass access=0x1F0FFF (PROCESS_ALL_ACCESS) when
        the caller really does mean to patch or breakpoint a process it is not
        debugging.

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
        cached = self._s.foreign_handles.get(pid)
        if cached is not None:
            # A cached handle is only good for the rights it carries. Handing
            # it back for a wider request would fail later at the first write,
            # as ERROR_NOACCESS from VirtualProtectEx — which names none of
            # this. Reopen instead when the caller asks for different rights.
            if access is None or self._s.foreign_access.get(pid) == access:
                return cached
            self.close(pid)

        masks = ((access,) if access is not None
                 else (self.READ_ACCESS, self.READ_ACCESS_LIMITED))
        last = None
        for mask in masks:
            try:
                handle = _pydbg.open_process(pid, mask)
            except OSError as e:
                last = e
                continue
            self._s.foreign_handles[pid] = handle
            self._s.foreign_access[pid] = mask
            return handle

        raise ProcessError(
            f"cannot open pid {pid} for reading: {last} (tried access mask(s) "
            f"{', '.join(f'0x{m:X}' for m in masks)}). The pid may not exist, "
            f"or it may be a process this one is not allowed to read.")

    def close(self, pid):
        """Close a handle opened by open(). No-op if never opened."""
        handle = self._s.foreign_handles.pop(pid, None)
        self._s.foreign_access.pop(pid, None)
        if handle is None:
            return
        try:
            _pydbg.close_handle(handle)
        except OSError as e:
            raise ProcessError(f"CloseHandle for pid {pid}: {e}")

    def release_all(self):
        """Release every handle open() handed out. Never raises."""
        for pid in list(self._s.foreign_handles):
            try:
                self.close(pid)
            except ProcessError:
                pass
