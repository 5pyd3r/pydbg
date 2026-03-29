# Debugger Advanced Features Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix HW breakpoint removal bug, complete exception features, add event-driven debug loop, add thread enumeration, and add convenience methods.

**Architecture:** All new Python methods wrap existing Cython functions. One new Cython function needed for thread enumeration (CreateToolhelp32Snapshot). Follow existing patterns: Cython raises OSError, Python converts to custom exceptions.

**Tech Stack:** Python, Cython, Win32 API, unittest

---

## File Structure

| File | Action | Purpose |
|------|--------|---------|
| `pydbg/debugger.py` | Modify | Fix remove_breakpoint HW path; enhance DebugEvent; add exception_code_to_str, get_exception_info, run, enumerate_threads, get_thread_ids, find_breakpoint |
| `pydbg/cython/_thread.pyx` | Modify | Add enumerate_threads using CreateToolhelp32Snapshot |
| `pydbg/cython/_win32types.pxd` | Modify | Add CreateToolhelp32Snapshot, Thread32First, Thread32Next declarations and THREADENTRY32 struct |
| `pydbg/__init__.py` | Modify | Export exception constants |
| `tests/test_debugger.py` | Modify | Add tests for all new features |

---

### Task 1: Fix remove_breakpoint HW breakpoint bug

**Files:**
- Modify: `pydbg/debugger.py:356-361`

- [ ] **Step 1: Fix the remove_breakpoint method**

The current `remove_breakpoint` does nothing for HW breakpoints — it just pops the dict entry. It needs to call `_bp.clear_hw_breakpoint()` with the thread handle and slot.

Replace lines 356-361 of `pydbg/debugger.py`:

```python
    def remove_breakpoint(self, bp_id):
        """Remove a breakpoint.

        Args:
            bp_id: Breakpoint ID from set_breakpoint/set_hw_breakpoint.

        Raises:
            BreakpointError: If bp_id not found.
        """
        if bp_id not in self._breakpoints:
            raise BreakpointError(f"Breakpoint {bp_id} not found")

        bp_info = self._breakpoints.pop(bp_id)
        if bp_info[0] == 'int3':
            _, addr, original = bp_info
            self.write_memory(addr, original)
        elif bp_info[0] == 'hw':
            _, addr, slot = bp_info
            try:
                _bp.clear_hw_breakpoint(self._thread_handle, slot)
            except (OSError, ValueError) as e:
                raise BreakpointError(f"clear_hw_breakpoint: {e}")
```

- [ ] **Step 2: Commit**

```bash
git add pydbg/debugger.py
git commit -m "fix: clear debug registers when removing hardware breakpoints"
```

---

### Task 2: Complete exception functionality

**Files:**
- Modify: `pydbg/debugger.py` — enhance DebugEvent, add 2 new Debugger methods
- Modify: `pydbg/__init__.py` — export exception constants

- [ ] **Step 1: Enhance DebugEvent with exception_name and exception_info**

In `pydbg/debugger.py`, update the `DebugEvent.__init__` to populate `exception_name` and `exception_info` when the event is an EXCEPTION:

```python
class DebugEvent:
    """Represents a debug event."""

    __slots__ = ('type', 'pid', 'tid', 'exception_code', 'exception_addr',
                 'first_chance', 'exception_name', 'exception_info', 'raw')

    def __init__(self, event_dict):
        self.raw = event_dict
        self.type = event_dict.get('event_name', 'UNKNOWN')
        self.pid = event_dict.get('pid', 0)
        self.tid = event_dict.get('tid', 0)
        self.exception_code = event_dict.get('exception_code')
        self.exception_addr = event_dict.get('exception_addr')
        self.first_chance = event_dict.get('first_chance')
        self.exception_name = None
        self.exception_info = None
        if self.exception_code is not None:
            self.exception_name = _exception.exception_code_to_str(self.exception_code)
            self.exception_info = _exception.get_exception_info(
                self.exception_code,
                self.exception_addr or 0,
                1 if self.first_chance else 0,
                event_dict.get('exception_params', []))

    def __repr__(self):
        return f"<DebugEvent {self.type} pid={self.pid} tid={self.tid}>"
```

- [ ] **Step 2: Add exception_code_to_str method to Debugger**

Add after `get_exit_code()` (around line 459):

```python
    def exception_code_to_str(self, code):
        """Convert an exception code to a human-readable string.

        Args:
            code: Exception code (int).

        Returns:
            str: Human-readable exception name.
        """
        return _exception.exception_code_to_str(code)
```

- [ ] **Step 3: Add get_exception_info method to Debugger**

Add after `exception_code_to_str()`:

```python
    def get_exception_info(self, code, addr, first_chance, exception_params):
        """Parse exception data into a structured dict.

        Args:
            code: Exception code (int).
            addr: Exception address (int).
            first_chance: 1 if first-chance, 0 if second-chance.
            exception_params: List of exception parameter values.

        Returns:
            dict with parsed exception info.
        """
        return _exception.get_exception_info(code, addr, first_chance, exception_params)
```

- [ ] **Step 4: Export exception constants from __init__.py**

Update `pydbg/__init__.py` to export constants:

```python
from .debugger import Debugger
from .exceptions import (
    PydbgError,
    ProcessError,
    MemError,
    ThreadError,
    BreakpointError,
    TimeoutError,
)
from .cython._exception import (
    EXCEPTION_ACCESS_VIOLATION,
    EXCEPTION_BREAKPOINT,
    EXCEPTION_SINGLE_STEP,
    EXCEPTION_GUARD_PAGE,
    EXCEPTION_READ_FAULT,
    EXCEPTION_WRITE_FAULT,
    EXCEPTION_EXECUTE_FAULT,
)

__version__ = '0.1.0'
__all__ = [
    'Debugger',
    'PydbgError',
    'ProcessError',
    'MemError',
    'ThreadError',
    'BreakpointError',
    'TimeoutError',
    'EXCEPTION_ACCESS_VIOLATION',
    'EXCEPTION_BREAKPOINT',
    'EXCEPTION_SINGLE_STEP',
    'EXCEPTION_GUARD_PAGE',
    'EXCEPTION_READ_FAULT',
    'EXCEPTION_WRITE_FAULT',
    'EXCEPTION_EXECUTE_FAULT',
]
```

- [ ] **Step 5: Commit**

```bash
git add pydbg/debugger.py pydbg/__init__.py
git commit -m "feat: complete exception functionality - DebugEvent enhancement, methods, constants export"
```

---

### Task 3: Add event-driven debug loop with callback

**Files:**
- Modify: `pydbg/debugger.py` — add `run()` method

- [ ] **Step 1: Add run(callback) method**

Add after `get_exception_info()`. The loop: wait_event → call callback → continue_event. Stop on EXIT_PROCESS or callback returning False.

```python
    def run(self, callback, timeout_ms=10000):
        """Run the debug event loop.

        Waits for debug events and dispatches them to the callback.
        Continues until the target process exits or the callback returns False.

        Args:
            callback: Function(DebugEvent) -> bool or None.
                      Return False to stop the loop.
            timeout_ms: Timeout per wait_event call (default 10000).

        Returns:
            int: Exit code of the process.

        Raises:
            ProcessError: On failure.
        """
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
```

- [ ] **Step 2: Commit**

```bash
git add pydbg/debugger.py
git commit -m "feat: add run() event-driven debug loop with callback pattern"
```

---

### Task 4: Add thread enumeration

**Files:**
- Modify: `pydbg/cython/_win32types.pxd` — add CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32
- Modify: `pydbg/cython/_thread.pyx` — add enumerate_threads function
- Modify: `pydbg/debugger.py` — add enumerate_threads() and get_thread_ids() methods

- [ ] **Step 1: Add toolhelp snapshot declarations to _win32types.pxd**

Add at the end of `_win32types.pxd`, before the closing of the `psapi.h` block:

```pxd
cdef extern from "tlhelp32.h":
    DWORD TH32CS_SNAPTHREAD
    DWORD GetCurrentProcessId()

    ctypedef struct THREADENTRY32:
        DWORD dwSize
        DWORD cntUsage
        DWORD th32ThreadID
        DWORD th32OwnerProcessID
        LONG tpBasePri
        LONG tpDeltaPri
        DWORD dwFlags

    HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID)
    BOOL Thread32First(HANDLE hSnapshot, THREADENTRY32* lpte)
    BOOL Thread32Next(HANDLE hSnapshot, THREADENTRY32* lpte)
```

- [ ] **Step 2: Add enumerate_threads to _thread.pyx**

Add imports for the new types at the top of `_thread.pyx`:

```cython
from _win32types cimport (
    HANDLE, DWORD, BOOL, LPVOID, CONTEXT,
    OpenThread, GetThreadContext, SetThreadContext,
    SuspendThread, ResumeThread, GetLastError, CloseHandle,
    THREAD_ALL_ACCESS, CONTEXT_ALL,
    CONTEXT_DEBUG_REGISTERS, CONTEXT_INTEGER, CONTEXT_CONTROL,
    CreateToolhelp32Snapshot, Thread32First, Thread32Next,
    THREADENTRY32, TH32CS_SNAPTHREAD,
)
```

Add the function at the end of `_thread.pyx`:

```cython
cpdef list enumerate_threads(int pid):
    """Enumerate thread IDs for a given process.

    Uses CreateToolhelp32Snapshot + Thread32First/Thread32Next.

    Args:
        pid: Process ID.

    Returns:
        list of thread ID dicts with keys: 'tid', 'owner_pid', 'base_priority'.

    Raises:
        OSError: On snapshot failure.
    """
    cdef HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, <DWORD>pid)
    if snap == <HANDLE><unsigned long long>-1:  # INVALID_HANDLE_VALUE
        raise OSError(GetLastError(), "CreateToolhelp32Snapshot failed")

    cdef THREADENTRY32 te
    te.dwSize = sizeof(THREADENTRY32)
    cdef list threads = []

    cdef BOOL ok = Thread32First(snap, &te)
    while ok:
        if te.th32OwnerProcessID == <DWORD>pid:
            threads.append({
                'tid': te.th32ThreadID,
                'owner_pid': te.th32OwnerProcessID,
                'base_priority': te.tpBasePri,
            })
        ok = Thread32Next(snap, &te)

    CloseHandle(snap)
    return threads
```

- [ ] **Step 3: Add enumerate_threads and get_thread_ids to Debugger**

Add after `run()` in `pydbg/debugger.py`:

```python
    def enumerate_threads(self, pid=None):
        """Enumerate threads for a process.

        Args:
            pid: Process ID. Defaults to the current debugged process.

        Returns:
            list of dicts with 'tid', 'owner_pid', 'base_priority'.

        Raises:
            ThreadError: On failure.
        """
        target = pid or self._pid
        if target is None:
            raise ThreadError("No process to enumerate threads for")
        try:
            return _thread.enumerate_threads(target)
        except OSError as e:
            raise ThreadError(f"EnumerateThreads: {e}")

    def get_thread_ids(self, pid=None):
        """Get just the thread IDs for a process.

        Args:
            pid: Process ID. Defaults to the current debugged process.

        Returns:
            list of int thread IDs.

        Raises:
            ThreadError: On failure.
        """
        return [t['tid'] for t in self.enumerate_threads(pid)]
```

- [ ] **Step 4: Commit**

```bash
git add pydbg/cython/_win32types.pxd pydbg/cython/_thread.pyx pydbg/debugger.py
git commit -m "feat: add thread enumeration via CreateToolhelp32Snapshot"
```

---

### Task 5: Add find_breakpoint convenience method

**Files:**
- Modify: `pydbg/debugger.py` — add find_breakpoint()

- [ ] **Step 1: Add find_breakpoint method**

Add after `get_thread_ids()` in `pydbg/debugger.py`:

```python
    def find_breakpoint(self, addr):
        """Find a breakpoint by address.

        Args:
            addr: Memory address to search for.

        Returns:
            Breakpoint ID (int), or None if not found.
        """
        for bp_id, bp_info in self._breakpoints.items():
            if bp_info[1] == addr:
                return bp_id
        return None
```

- [ ] **Step 2: Commit**

```bash
git add pydbg/debugger.py
git commit -m "feat: add find_breakpoint convenience method"
```

---

### Task 6: Write tests for all new features

**Files:**
- Modify: `tests/test_debugger.py` — add new test classes

- [ ] **Step 1: Add TestRemoveHwBreakpoint class**

Add to `tests/test_debugger.py`:

```python
class TestRemoveHwBreakpoint(unittest.TestCase):
    """Tests for hardware breakpoint removal."""

    def test_remove_hw_breakpoint_clears_registers(self):
        """Verify remove_breakpoint calls clear_hw_breakpoint for HW breakpoints."""
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        # Open thread and set HW breakpoint
        h_thread = dbg.open_thread(tid)
        regs = dbg.get_registers(h_thread)
        bp_id = dbg.set_hw_breakpoint(regs['rip'], condition='x', length=1, slot=0)

        # Remove it — should not raise
        dbg.remove_breakpoint(bp_id)
        self.assertIsNone(dbg.find_breakpoint(regs['rip']))

        dbg.terminate_process(0)
        dbg.close_handle(dbg._process_handle)
        dbg.close_handle(dbg._thread_handle)
```

- [ ] **Step 2: Add TestExceptionFeatures class**

```python
class TestExceptionFeatures(unittest.TestCase):
    """Tests for exception_code_to_str and get_exception_info via Debugger."""

    def test_debugger_exception_code_to_str(self):
        """Verify Debugger.exception_code_to_str delegates to Cython."""
        from pydbg import Debugger

        dbg = Debugger()
        self.assertEqual(
            dbg.exception_code_to_str(0x80000003), 'EXCEPTION_BREAKPOINT')
        self.assertEqual(
            dbg.exception_code_to_str(0xC0000005), 'EXCEPTION_ACCESS_VIOLATION')

    def test_debugger_get_exception_info(self):
        """Verify Debugger.get_exception_info parses access violation."""
        from pydbg import Debugger

        dbg = Debugger()
        # Simulate access violation read at 0xDEAD
        info = dbg.get_exception_info(
            0xC0000005, 0xDEAD, 1, [0, 0xDEAD])
        self.assertEqual(info['name'], 'EXCEPTION_ACCESS_VIOLATION')
        self.assertEqual(info['access_type'], 'read')
        self.assertEqual(info['access_addr'], 0xDEAD)

    def test_debug_event_exception_fields(self):
        """Verify DebugEvent populates exception_name and exception_info."""
        from pydbg.debugger import DebugEvent

        raw = {
            'event_name': 'EXCEPTION',
            'pid': 100,
            'tid': 200,
            'exception_code': 0x80000003,
            'exception_addr': 0x1000,
            'first_chance': True,
            'exception_params': [],
        }
        event = DebugEvent(raw)
        self.assertEqual(event.exception_name, 'EXCEPTION_BREAKPOINT')
        self.assertIsNotNone(event.exception_info)
        self.assertEqual(event.exception_info['name'], 'EXCEPTION_BREAKPOINT')
```

- [ ] **Step 3: Add TestRunLoop class**

```python
class TestRunLoop(unittest.TestCase):
    """Tests for the event-driven debug loop."""

    def test_run_with_callback(self):
        """Verify run() dispatches events to callback and returns exit code."""
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)

        events = []

        def on_event(event):
            events.append(event.type)
            if event.type == 'EXIT_PROCESS':
                pass  # let run() handle it

        exit_code = dbg.run(on_event, timeout_ms=5000)

        self.assertIn('CREATE_PROCESS', events)
        self.assertIsInstance(exit_code, int)
```

- [ ] **Step 4: Add TestThreadEnumeration class**

```python
class TestThreadEnumeration(unittest.TestCase):
    """Tests for thread enumeration."""

    def setUp(self):
        from pydbg.cython import _process
        self.pid, self.tid, self.h_proc, self.h_thr = _process.create_process(
            TEST_TARGET_PATH)
        _process.wait_for_debug_event(5000)
        _process.continue_debug_event(self.pid, self.tid, 0)

    def tearDown(self):
        from pydbg.cython import _process
        _process.terminate_process(self.h_proc, 0)
        _process.close_handle(self.h_proc)
        _process.close_handle(self.h_thr)

    def test_enumerate_threads(self):
        """Verify enumerate_threads returns at least one thread."""
        from pydbg.cython import _thread

        threads = _thread.enumerate_threads(self.pid)
        self.assertGreater(len(threads), 0)
        self.assertIn('tid', threads[0])

    def test_get_thread_ids(self):
        """Verify Debugger.get_thread_ids returns list of ints."""
        from pydbg import Debugger

        dbg = Debugger()
        dbg._pid = self.pid
        dbg._process_handle = self.h_proc

        tids = dbg.get_thread_ids()
        self.assertGreater(len(tids), 0)
        self.assertIsInstance(tids[0], int)
```

- [ ] **Step 5: Add TestFindBreakpoint class**

```python
class TestFindBreakpoint(unittest.TestCase):
    """Tests for find_breakpoint."""

    def test_find_existing_breakpoint(self):
        """Verify find_breakpoint returns correct ID."""
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        modules = dbg.enum_modules()
        base = modules[0]['base_address']
        bp_id = dbg.set_breakpoint(base)

        self.assertEqual(dbg.find_breakpoint(base), bp_id)

        dbg.remove_breakpoint(bp_id)
        self.assertIsNone(dbg.find_breakpoint(base))

        dbg.terminate_process(0)
        dbg.close_handle(dbg._process_handle)
        dbg.close_handle(dbg._thread_handle)

    def test_find_nonexistent_breakpoint(self):
        """Verify find_breakpoint returns None for unknown address."""
        from pydbg import Debugger

        dbg = Debugger()
        self.assertIsNone(dbg.find_breakpoint(0xDEADBEEF))
```

- [ ] **Step 6: Commit**

```bash
git add tests/test_debugger.py
git commit -m "test: add tests for HW breakpoint removal, exception features, run loop, thread enum, find_breakpoint"
```

---

## Verification

```bash
cd /c/Users/spyder/Desktop/workspace/mimo_cc/pydbg
python -m pytest tests/ -v
```

All existing tests should continue to pass. New tests validate each feature.
