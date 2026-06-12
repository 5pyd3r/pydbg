# Child Process Debugging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-in child process debugging to pydbg so users can debug processes spawned by the target.

**Architecture:** Extend `DebugSession` with a process table (`child_processes` dict). Modify `_process.pxi` to pass `DEBUG_PROCESS` without `DEBUG_ONLY_THIS_PROCESS` when `debug_children=True`. Add `_handle` variants to internal components so `Debugger` methods can route to child processes via an optional `pid` parameter.

**Tech Stack:** Python 3.14, Cython 3.x, Win32 Debug API, meson, unittest

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `src/pydbg/cython/_process.pxi` | Modify | `create_process` flag, event dict fields |
| `src/pydbg/core/session.py` | Modify | `ChildProcessInfo`, `DebugSession` fields |
| `src/pydbg/core/event.py` | Modify | `is_child` field |
| `src/pydbg/core/debugger.py` | Modify | New methods, pid routing, auto-tracking |
| `src/pydbg/memory/manager.py` | Modify | `*_handle` variants |
| `src/pydbg/breakpoint/software.py` | Modify | `set_handle`, `remove_handle` |
| `src/pydbg/module/resolver.py` | Modify | `enumerate_handle` |
| `tests/target/child_target.c` | Create | Test target that spawns a child process |
| `tests/test_child_process.py` | Create | 12 test cases |

---

### Task 1: Test Target — child_target.c

**Files:**
- Create: `tests/target/child_target.c`

- [ ] **Step 1: Write child_target.c**

```c
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[]) {
    if (argc > 1 && strcmp(argv[1], "child") == 0) {
        printf("child process pid=%lu\n", GetCurrentProcessId());
        fflush(stdout);
        Sleep(2000);
        return 42;
    }

    printf("parent process pid=%lu\n", GetCurrentProcessId());
    fflush(stdout);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmd[MAX_PATH];

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    snprintf(cmd, sizeof(cmd), "%s child", argv[0]);

    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "CreateProcess failed: %lu\n", GetLastError());
        return 1;
    }

    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
```

- [ ] **Step 2: Compile child_target.exe**

```bash
cl.exe /Fe:tests/target/child_target.exe tests/target/child_target.c /W4
```

- [ ] **Step 3: Verify it runs**

```bash
tests/target/child_target.exe
```

Expected output:
```
parent process pid=XXXX
child process pid=YYYY
```

- [ ] **Step 4: Commit**

```bash
git add tests/target/child_target.c tests/target/child_target.exe
git commit -m "test: add child_target.c test target for subprocess debugging"
```

---

### Task 2: Cython Layer — _process.pxi

**Files:**
- Modify: `src/pydbg/cython/_process.pxi:37-69` (create_process)
- Modify: `src/pydbg/cython/_process.pxi:121-163` (wait_for_debug_event)

- [ ] **Step 1: Modify create_process signature and flags**

In `src/pydbg/cython/_process.pxi`, change `create_process` from:

```python
cpdef tuple create_process(str path):
```

to:

```python
cpdef tuple create_process(str path, bint debug_children=False):
```

And change the `CreateProcessA` call from:

```python
    cdef BOOL result = CreateProcessA(
        <LPCSTR>NULL,
        <char*>path_bytes,
        NULL, NULL, 0,
        DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS,
        NULL, <LPCSTR>NULL,
        &si, &pi)
```

to:

```python
    cdef DWORD flags = DEBUG_PROCESS
    if not debug_children:
        flags |= DEBUG_ONLY_THIS_PROCESS

    cdef BOOL result = CreateProcessA(
        <LPCSTR>NULL,
        <char*>path_bytes,
        NULL, NULL, 0,
        flags,
        NULL, <LPCSTR>NULL,
        &si, &pi)
```

- [ ] **Step 2: Add child process handle fields to CREATE_PROCESS_DEBUG_EVENT**

In `wait_for_debug_event`, change:

```python
    elif code == CREATE_PROCESS_DEBUG_EVENT:
        event['base_of_image'] = <unsigned long long>de.u.CreateProcessInfo.lpBaseOfImage
```

to:

```python
    elif code == CREATE_PROCESS_DEBUG_EVENT:
        event['base_of_image'] = <unsigned long long>de.u.CreateProcessInfo.lpBaseOfImage
        event['child_process_handle'] = <unsigned long long>de.u.CreateProcessInfo.hProcess
        event['child_thread_handle'] = <unsigned long long>de.u.CreateProcessInfo.hThread
```

- [ ] **Step 3: Rebuild Cython extension**

```bash
cd C:\Users\Spyder\Desktop\ai_eden\Output\pydbg
./venv-x86/Scripts/python.exe scripts/build_venv.py x86
```

- [ ] **Step 4: Verify existing tests still pass**

```bash
cd C:\Users\Spyder\Desktop\ai_eden\Output\pydbg
PYTHONPATH=src ./venv-x86/Scripts/python.exe -m unittest tests.test_process -v
```

Expected: All tests pass, no regression.

- [ ] **Step 5: Commit**

```bash
git add src/pydbg/cython/_process.pxi
git commit -m "feat: add debug_children flag to create_process and child handle fields to events"
```

---

### Task 3: Data Structures — session.py, event.py

**Files:**
- Modify: `src/pydbg/core/session.py`
- Modify: `src/pydbg/core/event.py`

- [ ] **Step 1: Add ChildProcessInfo and extend DebugSession**

In `src/pydbg/core/session.py`, replace the entire file with:

```python
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
    target_arch: int = struct.calcsize("P") * 8  # 32 or 64, auto-detected
    bp_counter: int = 0
    breakpoints: dict = field(default_factory=dict)  # id -> (type, addr, extra)
    # Breakpoint lifecycle: tid -> (bp_id, addr, original_bytes)
    # Tracks breakpoints that have been hit and are pending single-step + restore
    pending_single_step: dict = field(default_factory=dict)

    # Child process debugging
    debug_children: bool = False
    child_processes: dict = field(default_factory=dict)  # pid -> ChildProcessInfo
```

- [ ] **Step 2: Add is_child to DebugEvent**

In `src/pydbg/core/event.py`, add `is_child` to `__slots__` and `__init__`:

```python
"""DebugEvent — debug event wrapper."""

from .. import _pydbg


class DebugEvent:
    """Represents a debug event."""

    __slots__ = (
        "type",
        "pid",
        "tid",
        "exception_code",
        "exception_addr",
        "first_chance",
        "exception_name",
        "exception_info",
        "raw",
        "is_child",
    )

    def __init__(self, event_dict, is_child=False):
        self.raw = event_dict
        self.type = event_dict.get("event_name", "UNKNOWN")
        self.pid = event_dict.get("pid", 0)
        self.tid = event_dict.get("tid", 0)
        self.exception_code = event_dict.get("exception_code")
        self.exception_addr = event_dict.get("exception_addr")
        self.first_chance = event_dict.get("first_chance")
        self.exception_name = None
        self.exception_info = None
        self.is_child = is_child
        if self.exception_code is not None:
            self.exception_name = _pydbg.exception_code_to_str(self.exception_code)
            self.exception_info = _pydbg.get_exception_info(
                self.exception_code,
                self.exception_addr or 0,
                1 if self.first_chance else 0,
                event_dict.get("exception_params", []),
            )

    def __repr__(self):
        return f"<DebugEvent {self.type} pid={self.pid} tid={self.tid}>"
```

- [ ] **Step 3: Update __init__.py exports**

In `src/pydbg/__init__.py`, add `ChildProcessInfo` to imports and `__all__`:

Add to imports:
```python
from .core.session import DebugSession, ChildProcessInfo
```

Add `ChildProcessInfo` to `__all__`.

- [ ] **Step 4: Commit**

```bash
git add src/pydbg/core/session.py src/pydbg/core/event.py src/pydbg/__init__.py
git commit -m "feat: add ChildProcessInfo, extend DebugSession and DebugEvent for child process tracking"
```

---

### Task 4: Internal Components — _handle variants

**Files:**
- Modify: `src/pydbg/memory/manager.py`
- Modify: `src/pydbg/breakpoint/software.py`
- Modify: `src/pydbg/module/resolver.py`

- [ ] **Step 1: Add _handle variants to MemoryManager**

In `src/pydbg/memory/manager.py`, add `read_handle`, `write_handle`, `query_handle`, `protect_handle`:

```python
"""MemoryManager — read/write/query/protect process memory."""

from .. import _pydbg
from ..exceptions import MemError


class MemoryManager:
    """Manages process memory operations."""

    def __init__(self, session):
        self._s = session

    def read(self, addr, size):
        try:
            return _pydbg.read_process_memory(self._s.process_handle, addr, size)
        except OSError as e:
            raise MemError(f"ReadProcessMemory at 0x{addr:X}: {e}")

    def write(self, addr, data):
        try:
            return _pydbg.write_process_memory(self._s.process_handle, addr, data)
        except OSError as e:
            raise MemError(f"WriteProcessMemory at 0x{addr:X}: {e}")

    def query(self, addr):
        try:
            return _pydbg.virtual_query_ex(self._s.process_handle, addr)
        except OSError as e:
            raise MemError(f"VirtualQueryEx at 0x{addr:X}: {e}")

    def protect(self, addr, size, protect):
        try:
            return _pydbg.virtual_protect_ex(
                self._s.process_handle, addr, size, protect
            )
        except OSError as e:
            raise MemError(f"VirtualProtectEx at 0x{addr:X}: {e}")

    # ── handle variants for child process support ──

    def read_handle(self, h_process, addr, size):
        try:
            return _pydbg.read_process_memory(h_process, addr, size)
        except OSError as e:
            raise MemError(f"ReadProcessMemory at 0x{addr:X}: {e}")

    def write_handle(self, h_process, addr, data):
        try:
            return _pydbg.write_process_memory(h_process, addr, data)
        except OSError as e:
            raise MemError(f"WriteProcessMemory at 0x{addr:X}: {e}")

    def query_handle(self, h_process, addr):
        try:
            return _pydbg.virtual_query_ex(h_process, addr)
        except OSError as e:
            raise MemError(f"VirtualQueryEx at 0x{addr:X}: {e}")

    def protect_handle(self, h_process, addr, size, protect):
        try:
            return _pydbg.virtual_protect_ex(h_process, addr, size, protect)
        except OSError as e:
            raise MemError(f"VirtualProtectEx at 0x{addr:X}: {e}")
```

- [ ] **Step 2: Add _handle variants to SoftwareBreakpointManager**

In `src/pydbg/breakpoint/software.py`, add `set_handle`:

```python
    def set_handle(self, h_process, addr):
        """Set INT3 breakpoint using explicit process handle."""
        try:
            original = _pydbg.read_process_memory(h_process, addr, 1)
            old_prot = _pydbg.virtual_protect_ex(
                h_process, addr, 1, self._PAGE_EXECUTE_READWRITE
            )
            _pydbg.write_process_memory(h_process, addr, b"\xcc")
            _pydbg.virtual_protect_ex(h_process, addr, 1, old_prot)
        except OSError as e:
            raise BreakpointError(f"set_breakpoint at 0x{addr:X}: {e}")

        self._s.bp_counter += 1
        bp_id = self._s.bp_counter
        self._s.breakpoints[bp_id] = ("int3", addr, original, h_process)
        return bp_id
```

Note: The tuple now has 4 elements (type, addr, original, h_process) for child process breakpoints. The `remove` method must handle both 3-element and 4-element tuples:

```python
    def remove(self, bp_id):
        if bp_id not in self._s.breakpoints:
            raise BreakpointError(f"Breakpoint {bp_id} not found")

        bp_info = self._s.breakpoints.pop(bp_id)
        if bp_info[0] != "int3":
            raise BreakpointError(
                f"Breakpoint {bp_id} is not a software breakpoint (type={bp_info[0]})"
            )

        addr = bp_info[1]
        original = bp_info[2]
        h_process = bp_info[3] if len(bp_info) > 3 else self._s.process_handle
        self._restore_byte_handle(h_process, addr, original)
```

And add a `_restore_byte_handle` method:

```python
    def _restore_byte_handle(self, h_process, addr, original):
        """Restore original byte at addr using explicit handle."""
        try:
            old_prot = _pydbg.virtual_protect_ex(
                h_process, addr, 1, self._PAGE_EXECUTE_READWRITE
            )
            _pydbg.write_process_memory(h_process, addr, original)
            _pydbg.virtual_protect_ex(h_process, addr, 1, old_prot)
        except OSError as e:
            raise BreakpointError(f"restore_byte at 0x{addr:X}: {e}")
```

- [ ] **Step 3: Add _handle variant to ModuleResolver**

In `src/pydbg/module/resolver.py`, add `enumerate_handle`:

```python
    def enumerate_handle(self, h_process):
        try:
            return _pydbg.enum_process_modules(h_process)
        except OSError as e:
            raise MemError(f"EnumProcessModules: {e}")
```

- [ ] **Step 4: Commit**

```bash
git add src/pydbg/memory/manager.py src/pydbg/breakpoint/software.py src/pydbg/module/resolver.py
git commit -m "feat: add _handle variants to MemoryManager, SoftwareBreakpointManager, ModuleResolver"
```

---

### Task 5: Debugger API — new methods and pid routing

**Files:**
- Modify: `src/pydbg/core/debugger.py`

- [ ] **Step 1: Add _get_process_handle internal method**

In `src/pydbg/core/debugger.py`, add after `__init__`:

```python
    def _get_process_handle(self, pid=None):
        """Return process handle for main or child process."""
        if pid is None or pid == self._session.pid:
            return self._session.process_handle
        child = self._session.child_processes.get(pid)
        if child is None:
            raise ProcessError(f"Unknown process pid={pid}")
        return child.process_handle
```

- [ ] **Step 2: Add set_debug_children method**

```python
    def set_debug_children(self, enabled=True):
        """Enable/disable child process debugging. Must be called before create_process."""
        if self._session.pid is not None:
            raise ProcessError(
                "set_debug_children must be called before create_process"
            )
        self._session.debug_children = enabled
```

- [ ] **Step 3: Add get_child_processes and get_child_process methods**

```python
    def get_child_processes(self):
        """Return dict of all child processes: pid -> ChildProcessInfo."""
        return dict(self._session.child_processes)

    def get_child_process(self, pid):
        """Return ChildProcessInfo for a specific child, or None."""
        return self._session.child_processes.get(pid)
```

- [ ] **Step 4: Add _register_child and _unregister_child internal methods**

```python
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
```

- [ ] **Step 5: Modify create_process to pass debug_children flag**

Change:
```python
    def create_process(self, path):
        try:
            pid, tid, h_proc, h_thr = _pydbg.create_process(path)
        except OSError as e:
            raise ProcessError(f"Failed to create process: {e}")
```

to:

```python
    def create_process(self, path):
        try:
            pid, tid, h_proc, h_thr = _pydbg.create_process(
                path, self._session.debug_children
            )
        except OSError as e:
            raise ProcessError(f"Failed to create process: {e}")
```

- [ ] **Step 6: Modify wait_event for auto-tracking**

Change:
```python
    def wait_event(self, timeout_ms=10000):
        try:
            event_dict = _pydbg.wait_for_debug_event(timeout_ms)
        except OSError as e:
            raise ProcessError(f"WaitForDebugEvent failed: {e}")

        if event_dict is None:
            return None
        return DebugEvent(event_dict)
```

to:

```python
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
```

- [ ] **Step 7: Modify read_memory and write_memory with pid parameter**

Change:
```python
    def read_memory(self, addr, size):
        return self.memory.read(addr, size)

    def write_memory(self, addr, data):
        return self.memory.write(addr, data)
```

to:

```python
    def read_memory(self, addr, size, pid=None):
        h = self._get_process_handle(pid)
        return self.memory.read_handle(h, addr, size)

    def write_memory(self, addr, data, pid=None):
        h = self._get_process_handle(pid)
        return self.memory.write_handle(h, addr, data)
```

- [ ] **Step 8: Modify query_memory and protect_memory with pid parameter**

```python
    def query_memory(self, addr, pid=None):
        h = self._get_process_handle(pid)
        return self.memory.query_handle(h, addr)

    def protect_memory(self, addr, size, protect, pid=None):
        h = self._get_process_handle(pid)
        return self.memory.protect_handle(h, addr, size, protect)
```

- [ ] **Step 9: Modify set_breakpoint with pid parameter**

```python
    def set_breakpoint(self, addr, pid=None):
        h = self._get_process_handle(pid)
        return self.brk_sw.set_handle(h, addr)
```

- [ ] **Step 10: Modify enum_modules with pid parameter**

```python
    def enum_modules(self, pid=None):
        h = self._get_process_handle(pid)
        return self.modules.enumerate_handle(h)
```

- [ ] **Step 11: Modify terminate_process with pid parameter**

```python
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
```

- [ ] **Step 12: Commit**

```bash
git add src/pydbg/core/debugger.py
git commit -m "feat: add child process debugging API to Debugger (set_debug_children, pid params)"
```

---

### Task 6: Tests — test_child_process.py

**Files:**
- Create: `tests/test_child_process.py`

- [ ] **Step 1: Write test_child_process.py**

```python
"""Tests for child process debugging support."""

import os
import struct
import unittest

HOST_ARCH = struct.calcsize("P") * 8
TEST_CHILD_TARGET = os.path.join(
    os.path.dirname(__file__), "target", "child_target.exe"
)

try:
    from pydbg import _pydbg
    _has_cython = True
except ImportError:
    _has_cython = False


@unittest.skipUnless(_has_cython, "requires Cython extension")
@unittest.skipUnless(os.path.exists(TEST_CHILD_TARGET), "child_target.exe not found")
class TestChildProcessFlag(unittest.TestCase):
    """Tests for set_debug_children flag."""

    def test_set_debug_children(self):
        from pydbg import Debugger
        dbg = Debugger()
        dbg.set_debug_children(True)
        self.assertTrue(dbg._session.debug_children)
        dbg.set_debug_children(False)
        self.assertFalse(dbg._session.debug_children)

    def test_set_debug_children_after_create_raises(self):
        from pydbg import Debugger
        from pydbg.exceptions import ProcessError
        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_CHILD_TARGET)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)
        with self.assertRaises(ProcessError):
            dbg.set_debug_children(True)
        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)


@unittest.skipUnless(_has_cython, "requires Cython extension")
@unittest.skipUnless(os.path.exists(TEST_CHILD_TARGET), "child_target.exe not found")
class TestChildProcessTracking(unittest.TestCase):
    """Tests for automatic child process tracking."""

    def _create_with_children(self):
        from pydbg import Debugger
        dbg = Debugger()
        dbg.set_debug_children(True)
        pid, tid = dbg.create_process(TEST_CHILD_TARGET)
        return dbg, pid, tid

    def test_child_process_event_tracking(self):
        dbg, pid, tid = self._create_with_children()

        child_found = False
        for _ in range(100):
            event = dbg.wait_event(3000)
            if event is None:
                continue
            dbg.continue_event(event.pid, event.tid)
            if event.type == "CREATE_PROCESS" and event.is_child:
                child_found = True
                break
            if event.type == "EXIT_PROCESS" and event.pid == pid:
                break

        self.assertTrue(child_found, "Should receive CREATE_PROCESS for child")
        children = dbg.get_child_processes()
        self.assertGreater(len(children), 0)

        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    def test_child_process_exit_tracking(self):
        dbg, pid, tid = self._create_with_children()

        child_pid = None
        for _ in range(100):
            event = dbg.wait_event(3000)
            if event is None:
                continue
            dbg.continue_event(event.pid, event.tid)
            if event.type == "CREATE_PROCESS" and event.is_child:
                child_pid = event.pid
            if event.type == "EXIT_PROCESS" and child_pid and event.pid == child_pid:
                break

        if child_pid:
            child = dbg.get_child_process(child_pid)
            self.assertIsNotNone(child)
            self.assertIsNotNone(child.exit_code)

        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    def test_get_child_processes(self):
        dbg, pid, tid = self._create_with_children()

        for _ in range(50):
            event = dbg.wait_event(3000)
            if event is None:
                continue
            dbg.continue_event(event.pid, event.tid)
            if event.type == "CREATE_PROCESS" and event.is_child:
                break

        children = dbg.get_child_processes()
        self.assertIsInstance(children, dict)
        self.assertGreater(len(children), 0)

        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    def test_is_child_event(self):
        dbg, pid, tid = self._create_with_children()

        found_parent = False
        found_child = False
        for _ in range(100):
            event = dbg.wait_event(3000)
            if event is None:
                continue
            dbg.continue_event(event.pid, event.tid)
            if event.type == "CREATE_PROCESS":
                if event.pid == pid:
                    found_parent = True
                    self.assertFalse(event.is_child)
                else:
                    found_child = True
                    self.assertTrue(event.is_child)
            if found_parent and found_child:
                break

        self.assertTrue(found_parent)
        self.assertTrue(found_child)

        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)


@unittest.skipUnless(_has_cython, "requires Cython extension")
@unittest.skipUnless(os.path.exists(TEST_CHILD_TARGET), "child_target.exe not found")
class TestChildProcessOperations(unittest.TestCase):
    """Tests for operating on child processes via pid parameter."""

    def _get_child_pid(self, dbg):
        """Wait for child process and return its pid."""
        for _ in range(100):
            event = dbg.wait_event(3000)
            if event is None:
                continue
            dbg.continue_event(event.pid, event.tid)
            if event.type == "CREATE_PROCESS" and event.is_child:
                return event.pid
        return None

    def test_read_child_memory(self):
        from pydbg import Debugger
        dbg = Debugger()
        dbg.set_debug_children(True)
        pid, tid = dbg.create_process(TEST_CHILD_TARGET)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        child_pid = self._get_child_pid(dbg)
        self.assertIsNotNone(child_pid)

        # Read MZ header from child process
        children = dbg.get_child_processes()
        child = children[child_pid]
        if child.process_handle:
            data = dbg.read_memory(child.base_of_image or 0x400000, 2, pid=child_pid)
            self.assertEqual(data[:2], b"MZ")

        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    def test_set_child_breakpoint(self):
        from pydbg import Debugger
        dbg = Debugger()
        dbg.set_debug_children(True)
        pid, tid = dbg.create_process(TEST_CHILD_TARGET)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        child_pid = self._get_child_pid(dbg)
        self.assertIsNotNone(child_pid)

        children = dbg.get_child_processes()
        child = children[child_pid]
        if child.process_handle and child.base_of_image:
            bp_id = dbg.set_breakpoint(child.base_of_image, pid=child_pid)
            self.assertGreater(bp_id, 0)
            dbg.remove_breakpoint(bp_id)

        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    def test_detach_child(self):
        from pydbg import Debugger
        dbg = Debugger()
        dbg.set_debug_children(True)
        pid, tid = dbg.create_process(TEST_CHILD_TARGET)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        child_pid = self._get_child_pid(dbg)
        self.assertIsNotNone(child_pid)

        # Detach child — should not raise
        dbg.detach(pid=child_pid)

        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)


@unittest.skipUnless(_has_cython, "requires Cython extension")
class TestChildProcessErrors(unittest.TestCase):
    """Tests for error handling."""

    def test_unknown_pid_raises(self):
        from pydbg import Debugger
        from pydbg.exceptions import ProcessError
        dbg = Debugger()
        with self.assertRaises(ProcessError):
            dbg.read_memory(0x1000, 4, pid=999999)

    def test_default_no_children(self):
        """Default behavior: no child tracking."""
        from pydbg import Debugger
        dbg = Debugger()
        self.assertFalse(dbg._session.debug_children)
        self.assertEqual(dbg._session.child_processes, {})


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Add test to meson.build**

In `tests/meson.build`, add after the `comprehensive` test:

```meson
test(
  'child_process',
  py,
  args: ['-m', 'unittest', 'tests.test_child_process'],
  env: test_env,
  workdir: meson.project_build_root(),
)
```

- [ ] **Step 3: Run tests**

```bash
cd C:\Users\Spyder\Desktop\ai_eden\Output\pydbg
PYTHONPATH=src ./venv-x86/Scripts/python.exe -m unittest tests.test_child_process -v
```

- [ ] **Step 4: Commit**

```bash
git add tests/test_child_process.py tests/meson.build
git commit -m "test: add child process debugging tests (12 cases)"
```

---

### Task 7: Integration — full test suite

- [ ] **Step 1: Run all existing tests to verify no regression**

```bash
cd C:\Users\Spyder\Desktop\ai_eden\Output\pydbg
PYTHONPATH=src TEST_TARGET_PATH=tests/target/simple_target.exe ./venv-x86/Scripts/python.exe -m unittest tests.test_process tests.test_memory tests.test_thread tests.test_breakpoint tests.test_debugger tests.test_pe tests.test_trace tests.test_dump tests.test_hook tests.test_comprehensive tests.test_child_process -v 2>&1 | grep -E "(Ran|OK|FAIL)"
```

Expected: All tests pass (no regression).

- [ ] **Step 2: Run flake8 on new/modified files**

```bash
cd C:\Users\Spyder\Desktop\ai_eden\Output\pydbg
./venv-x86/Scripts/python.exe -m flake8 src/pydbg/core/debugger.py src/pydbg/core/session.py src/pydbg/core/event.py src/pydbg/memory/manager.py src/pydbg/breakpoint/software.py src/pydbg/module/resolver.py tests/test_child_process.py --max-line-length=120
```

Expected: No errors.

- [ ] **Step 3: Rebuild and test x64**

```bash
cd C:\Users\Spyder\Desktop\ai_eden\Output\pydbg
./venv-x64/Scripts/python.exe scripts/build_venv.py x64
```

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "feat: child process debugging support (opt-in via set_debug_children)"
```
