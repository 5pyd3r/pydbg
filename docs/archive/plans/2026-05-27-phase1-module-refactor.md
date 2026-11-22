# Phase 1 Module Refactoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split `debugger.py` (602 lines, 6 responsibilities) into single-responsibility modules while keeping the public API (`from pydbg import Debugger`) unchanged.

**Architecture:** Composition pattern — Debugger creates a `DebugSession` dataclass (pure state holder) and five Manager classes (MemoryManager, ThreadManager, SoftwareBreakpointManager, HardwareBreakpointManager, ModuleResolver), each receiving the session in its constructor. Debugger delegates methods to managers; lifecycle and event-loop methods stay on Debugger.

**Tech Stack:** Python 3.12+, Cython (pre-built `.pyd` extensions), meson build system, pytest/unittest

---

### Task 1: Create directory structure and meson.build files

**Files:**
- Create: `src/pydbg/core/__init__.py`
- Create: `src/pydbg/memory/__init__.py`
- Create: `src/pydbg/thread/__init__.py`
- Create: `src/pydbg/breakpoint/__init__.py`
- Create: `src/pydbg/module/__init__.py`
- Modify: `src/pydbg/meson.build`

- [ ] **Step 1: Create all `__init__.py` files for new subpackages**

```bash
mkdir -p src/pydbg/core src/pydbg/memory src/pydbg/thread src/pydbg/breakpoint src/pydbg/module
touch src/pydbg/core/__init__.py
touch src/pydbg/memory/__init__.py
touch src/pydbg/thread/__init__.py
touch src/pydbg/breakpoint/__init__.py
touch src/pydbg/module/__init__.py
```

- [ ] **Step 2: Update meson.build to install new source files**

Read `src/pydbg/meson.build`, then replace its content with:

```meson
# Install pure Python files
py.install_sources(
  '__init__.py',
  'exceptions.py',
  'pe.py',
  'core/__init__.py',
  'core/session.py',
  'core/event.py',
  'core/debugger.py',
  'memory/__init__.py',
  'memory/manager.py',
  'thread/__init__.py',
  'thread/manager.py',
  'breakpoint/__init__.py',
  'breakpoint/software.py',
  'breakpoint/hardware.py',
  'module/__init__.py',
  'module/resolver.py',
  subdir: 'pydbg',
)

# Copy pure Python files to build dir so build/pydbg/ is a complete package
py_sources = [
  '__init__.py', 'exceptions.py', 'pe.py',
  'core/__init__.py', 'core/session.py', 'core/event.py', 'core/debugger.py',
  'memory/__init__.py', 'memory/manager.py',
  'thread/__init__.py', 'thread/manager.py',
  'breakpoint/__init__.py', 'breakpoint/software.py', 'breakpoint/hardware.py',
  'module/__init__.py', 'module/resolver.py',
]
foreach f : py_sources
  configure_file(
    input: f,
    output: f,
    copy: true,
  )
endforeach

subdir('cython')
```

- [ ] **Step 3: Verify directory structure**

```bash
find src/pydbg -name "*.py" -type f | sort
```

Expected: All 5 new `__init__.py` files plus existing files visible.

- [ ] **Step 4: Commit**

```bash
git add src/pydbg/core/ src/pydbg/memory/ src/pydbg/thread/ src/pydbg/breakpoint/ src/pydbg/module/ src/pydbg/meson.build
git commit -m "feat: add directory structure and meson.build for Phase 1 module refactoring"
```

---

### Task 2: Create DebugSession dataclass (core/session.py)

**Files:**
- Create: `src/pydbg/core/session.py`

- [ ] **Step 1: Write core/session.py**

```python
"""DebugSession — pure state holder for the debugger session."""

from dataclasses import dataclass, field


@dataclass
class DebugSession:
    """Holds debug session state. No logic — pure data."""

    process_handle: int | None = None
    thread_handle: int | None = None
    pid: int | None = None
    tid: int | None = None
    bp_counter: int = 0
    breakpoints: dict = field(default_factory=dict)  # id -> (type, addr, extra)
```

- [ ] **Step 2: Verify import works**

```bash
cd src && python3 -c "from pydbg.core.session import DebugSession; s = DebugSession(); print(s)"
```

Expected: `DebugSession(process_handle=None, thread_handle=None, pid=None, tid=None, bp_counter=0, breakpoints={})`

- [ ] **Step 3: Commit**

```bash
git add src/pydbg/core/session.py
git commit -m "feat: add DebugSession dataclass"
```

---

### Task 3: Move DebugEvent to core/event.py

**Files:**
- Create: `src/pydbg/core/event.py`

- [ ] **Step 1: Write core/event.py**

Move the `DebugEvent` class from `debugger.py:22-47` into its own file:

```python
"""DebugEvent — debug event wrapper."""

try:
    from ..cython import _exception
except ImportError:
    _exception = None


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

- [ ] **Step 2: Verify it imports correctly from its new location**

```bash
cd src && python3 -c "from pydbg.core.event import DebugEvent; e = DebugEvent({'event_name': 'TEST', 'pid': 1, 'tid': 2}); print(repr(e))"
```

Expected: `<DebugEvent TEST pid=1 tid=2>`

- [ ] **Step 3: Commit**

```bash
git add src/pydbg/core/event.py
git commit -m "feat: move DebugEvent to core/event.py"
```

---

### Task 4: Create MemoryManager (memory/manager.py)

**Files:**
- Create: `src/pydbg/memory/manager.py`

- [ ] **Step 1: Write memory/manager.py**

```python
"""MemoryManager — read/write/query/protect process memory."""

try:
    from ..cython import _memory
except ImportError:
    _memory = None

from ..exceptions import MemError


class MemoryManager:
    """Manages process memory operations."""

    def __init__(self, session):
        self._s = session

    def read(self, addr, size):
        try:
            return _memory.read_process_memory(self._s.process_handle, addr, size)
        except OSError as e:
            raise MemError(f"ReadProcessMemory at 0x{addr:X}: {e}")

    def write(self, addr, data):
        try:
            return _memory.write_process_memory(self._s.process_handle, addr, data)
        except OSError as e:
            raise MemError(f"WriteProcessMemory at 0x{addr:X}: {e}")

    def query(self, addr):
        try:
            return _memory.virtual_query_ex(self._s.process_handle, addr)
        except OSError as e:
            raise MemError(f"VirtualQueryEx at 0x{addr:X}: {e}")

    def protect(self, addr, size, protect):
        try:
            return _memory.virtual_protect_ex(
                self._s.process_handle, addr, size, protect)
        except OSError as e:
            raise MemError(f"VirtualProtectEx at 0x{addr:X}: {e}")
```

- [ ] **Step 2: Verify it imports**

```bash
cd src && python3 -c "from pydbg.memory.manager import MemoryManager; print('OK')"
```

Expected: `OK` (or ImportError about Cython if not built — either is fine for import check)

- [ ] **Step 3: Commit**

```bash
git add src/pydbg/memory/manager.py
git commit -m "feat: add MemoryManager"
```

---

### Task 5: Create ThreadManager (thread/manager.py)

**Files:**
- Create: `src/pydbg/thread/manager.py`

- [ ] **Step 1: Write thread/manager.py**

```python
"""ThreadManager — thread open/context/suspend/resume/enumerate/step."""

try:
    from ..cython import _thread
except ImportError:
    _thread = None

from ..exceptions import ThreadError


class ThreadManager:
    """Manages thread operations for the debugged process."""

    def __init__(self, session):
        self._s = session

    def open(self, tid):
        try:
            return _thread.open_thread(tid)
        except OSError as e:
            raise ThreadError(f"OpenThread for tid {tid}: {e}")

    def get_context(self, h_thread):
        try:
            return _thread.get_thread_context(h_thread)
        except OSError as e:
            raise ThreadError(f"GetThreadContext: {e}")

    def set_context(self, h_thread, context):
        try:
            _thread.set_thread_context(h_thread, context)
        except OSError as e:
            raise ThreadError(f"SetThreadContext: {e}")

    def set_register(self, h_thread, name, value):
        self.set_context(h_thread, {name.lower(): value})

    def suspend(self, h_thread):
        try:
            return _thread.suspend_thread(h_thread)
        except OSError as e:
            raise ThreadError(f"SuspendThread: {e}")

    def resume(self, h_thread):
        try:
            return _thread.resume_thread(h_thread)
        except OSError as e:
            raise ThreadError(f"ResumeThread: {e}")

    def enumerate(self, pid):
        try:
            return _thread.enumerate_threads(pid)
        except OSError as e:
            raise ThreadError(f"EnumerateThreads: {e}")

    def get_ids(self, pid):
        return [t['tid'] for t in self.enumerate(pid)]

    def step(self, h_thread):
        regs = self.get_context(h_thread)
        regs['eflags'] = regs.get('eflags', 0) | 0x100
        self.set_context(h_thread, regs)
```

- [ ] **Step 2: Verify it imports**

```bash
cd src && python3 -c "from pydbg.thread.manager import ThreadManager; print('OK')"
```

Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add src/pydbg/thread/manager.py
git commit -m "feat: add ThreadManager"
```

---

### Task 6: Create SoftwareBreakpointManager (breakpoint/software.py)

**Files:**
- Create: `src/pydbg/breakpoint/software.py`

- [ ] **Step 1: Write breakpoint/software.py**

```python
"""SoftwareBreakpointManager — int3 software breakpoints."""

try:
    from ..cython import _memory
except ImportError:
    _memory = None

from ..exceptions import BreakpointError


class SoftwareBreakpointManager:
    """Manages int3 software breakpoints."""

    def __init__(self, session):
        self._s = session

    def set(self, addr):
        try:
            original = _memory.read_process_memory(self._s.process_handle, addr, 1)
            _memory.write_process_memory(self._s.process_handle, addr, b'\xCC')
        except OSError as e:
            raise BreakpointError(f"set_breakpoint at 0x{addr:X}: {e}")

        self._s.bp_counter += 1
        bp_id = self._s.bp_counter
        self._s.breakpoints[bp_id] = ('int3', addr, original)
        return bp_id

    def remove(self, bp_id):
        if bp_id not in self._s.breakpoints:
            raise BreakpointError(f"Breakpoint {bp_id} not found")

        bp_info = self._s.breakpoints.pop(bp_id)
        if bp_info[0] != 'int3':
            raise BreakpointError(
                f"Breakpoint {bp_id} is not a software breakpoint (type={bp_info[0]})")

        _, addr, original = bp_info
        try:
            _memory.write_process_memory(self._s.process_handle, addr, original)
        except OSError as e:
            raise BreakpointError(f"remove_breakpoint at 0x{addr:X}: {e}")

    def find(self, addr):
        for bp_id, bp_info in self._s.breakpoints.items():
            if bp_info[0] == 'int3' and bp_info[1] == addr:
                return bp_id
        return None
```

- [ ] **Step 2: Verify it imports**

```bash
cd src && python3 -c "from pydbg.breakpoint.software import SoftwareBreakpointManager; print('OK')"
```

Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add src/pydbg/breakpoint/software.py
git commit -m "feat: add SoftwareBreakpointManager"
```

---

### Task 7: Create HardwareBreakpointManager (breakpoint/hardware.py)

**Files:**
- Create: `src/pydbg/breakpoint/hardware.py`

- [ ] **Step 1: Write breakpoint/hardware.py**

```python
"""HardwareBreakpointManager — debug-register hardware breakpoints."""

try:
    from ..cython import _bp
except ImportError:
    _bp = None

from ..exceptions import BreakpointError


class HardwareBreakpointManager:
    """Manages hardware (debug register) breakpoints."""

    COND_MAP = {'x': 0, 'w': 1, 'rw': 3}
    LEN_MAP = {1: 0, 2: 1, 4: 3, 8: 2}

    def __init__(self, session):
        self._s = session

    def set(self, addr, condition='x', length=1, slot=0):
        if condition not in self.COND_MAP:
            raise BreakpointError(f"Invalid condition '{condition}', use x/w/rw")
        if length not in self.LEN_MAP:
            raise BreakpointError(f"Invalid length {length}, use 1/2/4/8")

        try:
            _bp.set_hw_breakpoint(
                self._s.thread_handle, slot, addr,
                self.COND_MAP[condition], self.LEN_MAP[length])
        except (OSError, ValueError) as e:
            raise BreakpointError(f"set_hw_breakpoint: {e}")

        self._s.bp_counter += 1
        bp_id = self._s.bp_counter
        self._s.breakpoints[bp_id] = ('hw', addr, slot)
        return bp_id

    def clear(self, slot):
        try:
            _bp.clear_hw_breakpoint(self._s.thread_handle, slot)
        except (OSError, ValueError) as e:
            raise BreakpointError(f"clear_hw_breakpoint: {e}")

    def find(self, addr):
        for bp_id, bp_info in self._s.breakpoints.items():
            if bp_info[0] == 'hw' and bp_info[1] == addr:
                return bp_id
        return None

    def remove(self, bp_id):
        if bp_id not in self._s.breakpoints:
            raise BreakpointError(f"Breakpoint {bp_id} not found")

        bp_info = self._s.breakpoints.pop(bp_id)
        if bp_info[0] != 'hw':
            raise BreakpointError(
                f"Breakpoint {bp_id} is not a hardware breakpoint (type={bp_info[0]})")

        _, addr, slot = bp_info
        self.clear(slot)
```

- [ ] **Step 2: Verify it imports**

```bash
cd src && python3 -c "from pydbg.breakpoint.hardware import HardwareBreakpointManager; print('OK')"
```

Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add src/pydbg/breakpoint/hardware.py
git commit -m "feat: add HardwareBreakpointManager"
```

---

### Task 8: Create ModuleResolver (module/resolver.py)

**Files:**
- Create: `src/pydbg/module/resolver.py`

- [ ] **Step 1: Write module/resolver.py**

```python
"""ModuleResolver — enumerate modules and resolve filenames."""

try:
    from ..cython import _memory
except ImportError:
    _memory = None

from ..exceptions import MemError


class ModuleResolver:
    """Resolves module information for the debugged process."""

    def __init__(self, session):
        self._s = session

    def enumerate(self):
        try:
            return _memory.enum_process_modules(self._s.process_handle)
        except OSError as e:
            raise MemError(f"EnumProcessModules: {e}")

    def get_filename(self, h_module):
        try:
            return _memory.get_module_file_name_ex(self._s.process_handle, h_module)
        except OSError as e:
            raise MemError(f"GetModuleFileNameEx: {e}")
```

- [ ] **Step 2: Verify it imports**

```bash
cd src && python3 -c "from pydbg.module.resolver import ModuleResolver; print('OK')"
```

Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add src/pydbg/module/resolver.py
git commit -m "feat: add ModuleResolver"
```

---

### Task 9: Refactor Debugger (core/debugger.py) using composition

**Files:**
- Create: `src/pydbg/core/debugger.py`
- Modify: `src/pydbg/debugger.py` (will be deleted in Task 11 after verification)

- [ ] **Step 1: Write core/debugger.py — the refactored Debugger**

```python
"""Debugger — high-level debugging API with composition pattern."""

from .session import DebugSession
from .event import DebugEvent

from ..exceptions import (
    PydbgError,
    ProcessError,
    MemError,
    ThreadError,
    BreakpointError,
    TimeoutError,
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
```

- [ ] **Step 2: Verify the new Debugger imports correctly**

```bash
cd src && python3 -c "from pydbg.core.debugger import Debugger; d = Debugger(); print('session:', d._session); print('memory:', d.memory); print('thread:', d.thread)"
```

Expected output showing DebugSession and manager instances.

- [ ] **Step 3: Commit**

```bash
git add src/pydbg/core/debugger.py
git commit -m "feat: add refactored Debugger with composition pattern in core/debugger.py"
```

---

### Task 10: Update pydbg/__init__.py to re-export from new locations

**Files:**
- Modify: `src/pydbg/__init__.py`

- [ ] **Step 1: Update __init__.py imports**

Replace the content of `src/pydbg/__init__.py` with:

```python
from .core.debugger import Debugger
from .core.event import DebugEvent
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
    'DebugEvent',
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

- [ ] **Step 2: Verify public API still works**

```bash
cd src && python3 -c "from pydbg import Debugger, DebugEvent; d = Debugger(); e = DebugEvent({'event_name': 'TEST', 'pid': 1, 'tid': 2}); print('OK:', d, e)"
```

- [ ] **Step 3: Verify all exception constants are still exported**

```bash
cd src && python3 -c "from pydbg import EXCEPTION_BREAKPOINT, EXCEPTION_ACCESS_VIOLATION; print('OK:', hex(EXCEPTION_BREAKPOINT), hex(EXCEPTION_ACCESS_VIOLATION))"
```

- [ ] **Step 4: Commit**

```bash
git add src/pydbg/__init__.py
git commit -m "feat: update __init__.py to re-export from core module"
```

---

### Task 11: Update tests for new import paths and private state access

**Files:**
- Modify: `tests/test_debugger.py`

- [ ] **Step 1: Update test_debugger.py — DebugEvent imports**

Change all 4 occurrences of `from pydbg.debugger import DebugEvent` to `from pydbg import DebugEvent`.

Lines: 19, 37, 45, 54

```python
# Line 19:
        from pydbg import DebugEvent

# Line 37:
        from pydbg import DebugEvent

# Line 45:
        from pydbg import DebugEvent

# Line 54:
        from pydbg import DebugEvent
```

- [ ] **Step 2: Update test_debugger.py — private state access**

Tests that access `dbg._process_handle` or `dbg._thread_handle` need to use `dbg._session.process_handle` and `dbg._session.thread_handle`. Tests that set `dbg._pid` need to use `dbg._session.pid`.

Locations to update:
- Lines 85-86: `dbg._process_handle` → `dbg._session.process_handle`, `dbg._thread_handle` → `dbg._session.thread_handle`
- Lines 101-102: same
- Lines 173-174: same
- Lines 229-230: `dbg._pid` → `dbg._session.pid`, `dbg._process_handle` → `dbg._session.process_handle`
- Lines 260-261: `dbg._process_handle` → `dbg._session.process_handle`, `dbg._thread_handle` → `dbg._session.thread_handle`

For lines 85-86 (in `test_terminate_process`):
```python
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)
```

For lines 101-102 (in `test_get_exit_code_running`):
```python
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)
```

For lines 173-174 (in `test_remove_hw_breakpoint`):
```python
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)
```

For lines 229-230 (in `test_get_thread_ids`):
```python
        dbg._session.pid = self.pid
        dbg._session.process_handle = self.h_proc
```

For lines 260-261 (in `test_find_existing_breakpoint`):
```python
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)
```

- [ ] **Step 3: Update test_process.py — private state access**

Lines 111-112:
```python
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)
```

- [ ] **Step 4: Update test_thread.py — private state access**

Lines 85-86:
```python
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)
```

- [ ] **Step 5: Update test_breakpoint.py — private state access**

Lines 102-103:
```python
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)
```

Lines 126-127:
```python
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)
```

- [ ] **Step 6: Verify no remaining references to old private attributes**

```bash
grep -rn "dbg\._process_handle\|dbg\._thread_handle\|dbg\._pid\b\|dbg\._tid\b\|from pydbg\.debugger" tests/
```

Expected: No output (all references updated).

- [ ] **Step 7: Commit**

```bash
git add tests/
git commit -m "test: update tests for new module structure — DebugEvent import path and session state access"
```

---

### Task 12: Remove old debugger.py

**Files:**
- Remove: `src/pydbg/debugger.py`

- [ ] **Step 1: Delete the old file**

```bash
rm src/pydbg/debugger.py
```

- [ ] **Step 2: Verify nothing imports from the old path**

```bash
grep -rn "from.*pydbg\.debugger\|import.*pydbg\.debugger" src/ tests/ || echo "No references — safe to delete"
```

Expected: No references.

- [ ] **Step 3: Commit**

```bash
git add src/pydbg/debugger.py
git commit -m "refactor: remove old debugger.py, replaced by core/debugger.py"
```

---

### Task 13: Build with meson and verify compilation

**Files:**
- Verify: build output

- [ ] **Step 1: Reconfigure and build**

```bash
cd /app/pydbg && meson setup build --wipe 2>&1 | tail -5
```

Expected: `Build type: ...` and no errors.

- [ ] **Step 2: Compile**

```bash
cd /app/pydbg && meson compile -C build 2>&1 | tail -10
```

Expected: Compilation succeeds. Cython extensions built. Pure Python files copied to `build/pydbg/`.

- [ ] **Step 3: Verify the build output has the new structure**

```bash
find /app/pydbg/build/pydbg -name "*.py" -type f | sort
```

Expected: New files visible under `build/pydbg/core/`, `build/pydbg/memory/`, `build/pydbg/thread/`, `build/pydbg/breakpoint/`, `build/pydbg/module/`, AND no `build/pydbg/debugger.py`.

- [ ] **Step 4: Commit (if meson.build changed during debug)**

No commit needed if build succeeds — this step is verification only.

---

### Task 14: Run tests against the refactored codebase

**Files:**
- Verify: all tests pass

- [ ] **Step 1: Run all tests**

```bash
cd /app/pydbg && PYTHONPATH=build python3 -m pytest tests/ -v 2>&1
```

Expected: All tests pass (or skip appropriately if not on Windows/no Cython).

- [ ] **Step 2: Run individual test files to isolate failures if any**

If the full suite has failures, run each file:

```bash
cd /app/pydbg && PYTHONPATH=build python3 -m pytest tests/test_debugger.py -v 2>&1
cd /app/pydbg && PYTHONPATH=build python3 -m pytest tests/test_memory.py -v 2>&1
cd /app/pydbg && PYTHONPATH=build python3 -m pytest tests/test_thread.py -v 2>&1
cd /app/pydbg && PYTHONPATH=build python3 -m pytest tests/test_breakpoint.py -v 2>&1
cd /app/pydbg && PYTHONPATH=build python3 -m pytest tests/test_process.py -v 2>&1
cd /app/pydbg && PYTHONPATH=build python3 -m pytest tests/test_pe.py -v 2>&1
```

- [ ] **Step 3: Verify no regressions**

Confirm all test files pass. `test_pe.py` should be unaffected (pure Python, no Debugger dependency).

---

### Task 15: Final verification — public API compatibility check

**Files:**
- Verify: import paths

- [ ] **Step 1: Verify all public imports work**

```bash
cd /app/pydbg && PYTHONPATH=build python3 -c "
from pydbg import Debugger, DebugEvent
from pydbg import PydbgError, ProcessError, MemError, ThreadError, BreakpointError, TimeoutError
from pydbg import EXCEPTION_ACCESS_VIOLATION, EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP
from pydbg import EXCEPTION_GUARD_PAGE, EXCEPTION_READ_FAULT, EXCEPTION_WRITE_FAULT, EXCEPTION_EXECUTE_FAULT
print('All public imports OK')
print('Version:', __import__('pydbg').__version__)
"
```

- [ ] **Step 2: Verify manager direct access works**

```bash
cd /app/pydbg && PYTHONPATH=build python3 -c "
from pydbg import Debugger
d = Debugger()
assert hasattr(d, 'memory')
assert hasattr(d, 'thread')
assert hasattr(d, 'brk_sw')
assert hasattr(d, 'brk_hw')
assert hasattr(d, 'modules')
assert hasattr(d, '_session')
print('All manager attributes present')
"
```

- [ ] **Step 3: Commit (if any fixes were needed)**

If steps 1-2 passed without changes, no commit needed.
