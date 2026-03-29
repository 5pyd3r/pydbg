"""pydbg — High-level debugging API.

Provides a procedural interface over the Cython Win32 wrappers.
"""

from .exceptions import (
    PydbgError,
    ProcessError,
    MemoryError as PydbgMemoryError,
    ThreadError,
    BreakpointError,
    TimeoutError,
)

# Import Cython modules (available after build)
try:
    from pydbg.cython import _process, _memory, _thread, _exception, _bp
except ImportError:
    _process = _memory = _thread = _exception = _bp = None


class DebugEvent:
    """Represents a debug event."""

    __slots__ = ('type', 'pid', 'tid', 'exception_code', 'exception_addr',
                 'first_chance', 'raw')

    def __init__(self, event_dict):
        self.raw = event_dict
        self.type = event_dict.get('event_name', 'UNKNOWN')
        self.pid = event_dict.get('pid', 0)
        self.tid = event_dict.get('tid', 0)
        self.exception_code = event_dict.get('exception_code')
        self.exception_addr = event_dict.get('exception_addr')
        self.first_chance = event_dict.get('first_chance')

    def __repr__(self):
        return f"<DebugEvent {self.type} pid={self.pid} tid={self.tid}>"


class Debugger:
    """Main debugger class. Procedural API for Win32 debugging."""

    def __init__(self):
        self._process_handle = None
        self._thread_handle = None
        self._pid = None
        self._tid = None
        self._bp_counter = 0
        self._breakpoints = {}  # id -> (addr, type)

    def create_process(self, path):
        """Create a process under debug control.

        Args:
            path: Path to executable.

        Returns:
            (pid, tid) tuple.

        Raises:
            ProcessError: On failure.
        """
        try:
            pid, tid, h_proc, h_thr = _process.create_process(path)
        except OSError as e:
            raise ProcessError(f"Failed to create process: {e}")

        self._process_handle = h_proc
        self._thread_handle = h_thr
        self._pid = pid
        self._tid = tid
        return (pid, tid)

    def attach(self, pid):
        """Attach to a running process.

        Args:
            pid: Process ID to attach to.

        Raises:
            ProcessError: On failure.
        """
        try:
            _process.debug_active_process(pid)
        except OSError as e:
            raise ProcessError(f"Failed to attach to pid {pid}: {e}")
        self._pid = pid

    def detach(self, pid=None):
        """Detach from a process.

        Args:
            pid: Process ID. Defaults to the last attached/created process.

        Raises:
            ProcessError: On failure.
        """
        target = pid or self._pid
        if target is None:
            raise ProcessError("No process to detach from")
        try:
            _process.debug_active_process_stop(target)
        except OSError as e:
            raise ProcessError(f"Failed to detach from pid {target}: {e}")

    def wait_event(self, timeout_ms=10000):
        """Wait for the next debug event.

        Args:
            timeout_ms: Timeout in milliseconds.

        Returns:
            DebugEvent object, or None on timeout.

        Raises:
            ProcessError: On failure.
        """
        try:
            event_dict = _process.wait_for_debug_event(timeout_ms)
        except OSError as e:
            raise ProcessError(f"WaitForDebugEvent failed: {e}")

        if event_dict is None:
            return None
        return DebugEvent(event_dict)

    def continue_event(self, pid=None, tid=None, status=0):
        """Continue a stopped thread.

        Args:
            pid: Process ID. Defaults to last.
            tid: Thread ID. Defaults to last.
            status: Continue status (0 = DBG_CONTINUE).

        Raises:
            ProcessError: On failure.
        """
        try:
            _process.continue_debug_event(
                pid or self._pid,
                tid or self._tid,
                status)
        except OSError as e:
            raise ProcessError(f"ContinueDebugEvent failed: {e}")

    def read_memory(self, addr, size):
        """Read bytes from process memory.

        Args:
            addr: Memory address (int).
            size: Number of bytes to read.

        Returns:
            bytes object.

        Raises:
            PydbgMemoryError: On failure.
        """
        try:
            return _memory.read_process_memory(self._process_handle, addr, size)
        except OSError as e:
            raise PydbgMemoryError(f"ReadProcessMemory at 0x{addr:X}: {e}")

    def write_memory(self, addr, data):
        """Write bytes to process memory.

        Args:
            addr: Memory address (int).
            data: bytes to write.

        Returns:
            Number of bytes written.

        Raises:
            PydbgMemoryError: On failure.
        """
        try:
            return _memory.write_process_memory(self._process_handle, addr, data)
        except OSError as e:
            raise PydbgMemoryError(f"WriteProcessMemory at 0x{addr:X}: {e}")

    def query_memory(self, addr):
        """Query memory region information.

        Args:
            addr: Memory address (int).

        Returns:
            dict with region info.

        Raises:
            PydbgMemoryError: On failure.
        """
        try:
            return _memory.virtual_query_ex(self._process_handle, addr)
        except OSError as e:
            raise PydbgMemoryError(f"VirtualQueryEx at 0x{addr:X}: {e}")

    def enum_modules(self):
        """Enumerate loaded modules.

        Returns:
            list of dicts with module info.

        Raises:
            PydbgMemoryError: On failure.
        """
        try:
            return _memory.enum_process_modules(self._process_handle)
        except OSError as e:
            raise PydbgMemoryError(f"EnumProcessModules: {e}")

    def get_module_filename(self, h_module):
        """Get file name of a loaded module.

        Args:
            h_module: Module handle (int).

        Returns:
            File path string.

        Raises:
            PydbgMemoryError: On failure.
        """
        try:
            return _memory.get_module_file_name_ex(self._process_handle, h_module)
        except OSError as e:
            raise PydbgMemoryError(f"GetModuleFileNameEx: {e}")

    def open_thread(self, thread_id):
        """Open a thread by ID.

        Args:
            thread_id: Thread ID (int).

        Returns:
            Thread handle (int).

        Raises:
            ThreadError: On failure.
        """
        try:
            return _thread.open_thread(thread_id)
        except OSError as e:
            raise ThreadError(f"OpenThread for tid {thread_id}: {e}")

    def get_registers(self, h_thread):
        """Get thread register context.

        Args:
            h_thread: Thread handle (int).

        Returns:
            dict of register name -> value.

        Raises:
            ThreadError: On failure.
        """
        try:
            return _thread.get_thread_context(h_thread)
        except OSError as e:
            raise ThreadError(f"GetThreadContext: {e}")

    def set_registers(self, h_thread, context):
        """Set thread register context.

        Args:
            h_thread: Thread handle (int).
            context: dict of register name -> value.

        Raises:
            ThreadError: On failure.
        """
        try:
            _thread.set_thread_context(h_thread, context)
        except OSError as e:
            raise ThreadError(f"SetThreadContext: {e}")

    def set_register(self, h_thread, name, value):
        """Set a single register.

        Args:
            h_thread: Thread handle (int).
            name: Register name (str, e.g. "Rip").
            value: New value (int).

        Raises:
            ThreadError: On failure.
        """
        self.set_registers(h_thread, {name.lower(): value})

    def suspend_thread(self, h_thread):
        """Suspend a thread.

        Args:
            h_thread: Thread handle (int).

        Returns:
            Previous suspend count.

        Raises:
            ThreadError: On failure.
        """
        try:
            return _thread.suspend_thread(h_thread)
        except OSError as e:
            raise ThreadError(f"SuspendThread: {e}")

    def resume_thread(self, h_thread):
        """Resume a thread.

        Args:
            h_thread: Thread handle (int).

        Returns:
            Previous suspend count.

        Raises:
            ThreadError: On failure.
        """
        try:
            return _thread.resume_thread(h_thread)
        except OSError as e:
            raise ThreadError(f"ResumeThread: {e}")

    def set_breakpoint(self, addr):
        """Set an int3 software breakpoint.

        Args:
            addr: Address (int).

        Returns:
            Breakpoint ID.

        Raises:
            BreakpointError: On failure.
        """
        original = self.read_memory(addr, 1)
        self.write_memory(addr, b'\xCC')

        self._bp_counter += 1
        bp_id = self._bp_counter
        self._breakpoints[bp_id] = ('int3', addr, original)
        return bp_id

    def remove_breakpoint(self, bp_id):
        """Remove a breakpoint.

        Args:
            bp_id: Breakpoint ID from set_breakpoint/set_hw_breakpoint.

        Raises:
            BreakpointError: If bp_id not found.
        """
        if bp_id not in self._breakpoints:
            raise BreakpointError(f"Breakpoint {bp_id} not found")

        bp_type, addr, original = self._breakpoints.pop(bp_id)
        if bp_type == 'int3':
            self.write_memory(addr, original)

    def set_hw_breakpoint(self, addr, condition='x', length=1, slot=0):
        """Set a hardware breakpoint.

        Args:
            addr: Address (int).
            condition: 'x' (execute), 'w' (write), 'rw' (read/write).
            length: 1, 2, 4, or 8 bytes.
            slot: 0-3.

        Returns:
            Breakpoint ID.

        Raises:
            BreakpointError: On failure.
        """
        cond_map = {'x': 0, 'w': 1, 'rw': 3}
        len_map = {1: 0, 2: 1, 4: 3, 8: 2}

        if condition not in cond_map:
            raise BreakpointError(f"Invalid condition '{condition}', use x/w/rw")
        if length not in len_map:
            raise BreakpointError(f"Invalid length {length}, use 1/2/4/8")

        try:
            _bp.set_hw_breakpoint(
                self._thread_handle, slot, addr,
                cond_map[condition], len_map[length])
        except (OSError, ValueError) as e:
            raise BreakpointError(f"set_hw_breakpoint: {e}")

        self._bp_counter += 1
        bp_id = self._bp_counter
        self._breakpoints[bp_id] = ('hw', addr, slot)
        return bp_id

    def step(self, h_thread):
        """Single-step a thread.

        Sets the Trap Flag (TF) in EFlags, then continues.
        The thread will execute one instruction and raise
        EXCEPTION_SINGLE_STEP.

        Args:
            h_thread: Thread handle (int).

        Raises:
            ThreadError: On failure.
        """
        regs = self.get_registers(h_thread)
        regs['eflags'] = regs.get('eflags', 0) | 0x100  # TF flag
        self.set_registers(h_thread, regs)

    def close_handle(self, h_handle):
        """Close a Win32 handle.

        Args:
            h_handle: Handle (int).

        Raises:
            ProcessError: On failure.
        """
        try:
            _process.close_handle(h_handle)
        except OSError as e:
            raise ProcessError(f"CloseHandle: {e}")
