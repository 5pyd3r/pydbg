# Phase 1 Module Refactoring Design

## Goal

Split `debugger.py` (602 lines, 6 responsibilities) into single-responsibility modules.
Public API (`from pydbg import Debugger`) unchanged. Internal modularity for testability and
future extension.

## Scope

**Extract** (become independent Manager classes):
- C. Memory operations → `MemoryManager`
- D. Thread operations → `ThreadManager`
- E. Breakpoint operations → `SoftwareBreakpointManager` + `HardwareBreakpointManager`
- F. Module operations → `ModuleResolver`

**Keep in Debugger** (core debug loop, not separable):
- A. Lifecycle: create_process / attach / detach / terminate / close_handle
- B. Event loop: wait_event / continue_event / run
- G. Exception helpers: exception_code_to_str / get_exception_info

## Architecture: Composition Pattern

```
Debugger
  ├── _session: DebugSession          ← state holder
  ├── memory: MemoryManager           ← injected, references _session
  ├── thread: ThreadManager           ← injected, references _session
  ├── brk_sw: SoftwareBreakpointManager  ← injected, references _session
  ├── brk_hw: HardwareBreakpointManager  ← injected, references _session
  └── modules: ModuleResolver         ← injected, references _session
```

Each Manager receives `DebugSession` in constructor, stores as `_session`.
Debugger creates all managers in `__init__` and delegates methods.
Advanced users can also use managers directly: `dbg.memory.read(addr, size)`.

## File Layout

```
src/pydbg/
├── core/
│   ├── __init__.py
│   ├── session.py    — DebugSession dataclass
│   ├── event.py      — DebugEvent (moved from debugger.py)
│   └── debugger.py   — Debugger facade (lifecycle + event loop + delegation)
├── memory/
│   ├── __init__.py
│   └── manager.py    — MemoryManager
├── thread/
│   ├── __init__.py
│   └── manager.py    — ThreadManager
├── breakpoint/
│   ├── __init__.py
│   ├── software.py   — SoftwareBreakpointManager
│   └── hardware.py   — HardwareBreakpointManager
├── module/
│   ├── __init__.py
│   └── resolver.py   — ModuleResolver
├── exceptions.py      — (unchanged)
├── pe.py              — (unchanged)
├── __init__.py        — re-export, API identical
└── cython/            — (unchanged)
```

## `DebugSession` (new: core/session.py, ~20 lines)

Dataclass. Pure data, no logic.

```python
@dataclass
class DebugSession:
    process_handle: int | None = None
    thread_handle: int | None = None
    pid: int | None = None
    tid: int | None = None
    bp_counter: int = 0
    breakpoints: dict = field(default_factory=dict)  # id -> (type, addr, ...)
```

## `DebugEvent` (moved: core/event.py, ~50 lines)

Move existing class from debugger.py. No behavior changes. Import path changes from
`pydbg.debugger.DebugEvent` to `pydbg.core.event.DebugEvent`, but `pydbg.__init__`
re-exports it so `from pydbg import DebugEvent` still works.

## `Debugger` (refactored: core/debugger.py, ~200 lines)

```python
class Debugger:
    def __init__(self):
        self._session = DebugSession()
        self.memory = MemoryManager(self._session)
        self.thread = ThreadManager(self._session)
        self.brk_sw = SoftwareBreakpointManager(self._session)
        self.brk_hw = HardwareBreakpointManager(self._session)
        self.modules = ModuleResolver(self._session)

    # Lifecycle (kept here — these set session state)
    def create_process(self, path): ...
    def attach(self, pid): ...
    def detach(self, pid=None): ...
    def terminate_process(self, exit_code=1): ...
    def get_exit_code(self): ...
    def close_handle(self, h_handle): ...

    # Event loop (kept here — core debug loop)
    def wait_event(self, timeout_ms=10000): ...
    def continue_event(self, pid=None, tid=None): ...
    def run(self, callback, timeout_ms=10000): ...

    # Delegated methods
    def read_memory(self, addr, size):       return self.memory.read(addr, size)
    def write_memory(self, addr, data):      return self.memory.write(addr, data)
    def query_memory(self, addr):            return self.memory.query(addr)
    def protect_memory(self, addr, sz, p):   return self.memory.protect(addr, sz, p)
    def enum_modules(self):                  return self.modules.enumerate()
    def get_module_filename(self, h):        return self.modules.get_filename(h)
    def open_thread(self, tid):              return self.thread.open(tid)

    def get_registers(self, h):              return self.thread.get_context(h)
    def set_registers(self, h, ctx):         return self.thread.set_context(h, ctx)
    def set_register(self, h, name, val):    return self.thread.set_register(h, name, val)
    def suspend_thread(self, h):             return self.thread.suspend(h)
    def resume_thread(self, h):              return self.thread.resume(h)
    def enumerate_threads(self, pid=None):   return self.thread.enumerate(pid or self._session.pid)
    def get_thread_ids(self, pid=None):      return self.thread.get_ids(pid or self._session.pid)
    def step(self, h_thread):                return self.thread.step(h_thread)
    def set_breakpoint(self, addr):          return self.brk_sw.set(addr)
    def remove_breakpoint(self, bp_id):      return self.brk_sw.remove(bp_id)
    def set_hw_breakpoint(self, *a):         return self.brk_hw.set(*a)
    def find_breakpoint(self, addr):         return self.brk_sw.find(addr) or self.brk_hw.find(addr)
    def exception_code_to_str(self, code):   return _exception.exception_code_to_str(code)
    def get_exception_info(self, *a):        return _exception.get_exception_info(*a)
```

## Manager Classes

### MemoryManager (memory/manager.py, ~60 lines)

```python
class MemoryManager:
    def __init__(self, session): self._s = session
    def read(self, addr, size):         return _memory.read_process_memory(self._s.process_handle, addr, size)
    def write(self, addr, data):        return _memory.write_process_memory(self._s.process_handle, addr, data)
    def query(self, addr):              return _memory.virtual_query_ex(self._s.process_handle, addr)
    def protect(self, addr, sz, prot):  return _memory.virtual_protect_ex(self._s.process_handle, addr, sz, prot)
```

### ThreadManager (thread/manager.py, ~70 lines)

```python
class ThreadManager:
    def __init__(self, session): self._s = session
    def open(self, tid):            return _thread.open_thread(tid)
    def get_context(self, h):       return _thread.get_thread_context(h)
    def set_context(self, h, ctx):  _thread.set_thread_context(h, ctx)
    def set_register(self, h, name, val):  self.set_context(h, {name.lower(): val})
    def suspend(self, h):           return _thread.suspend_thread(h)
    def resume(self, h):            return _thread.resume_thread(h)
    def enumerate(self, pid):       return _thread.enumerate_threads(pid)
    def get_ids(self, pid):         return [t['tid'] for t in self.enumerate(pid)]
    def step(self, h_thread):       # set TF in eflags
        regs = self.get_context(h_thread)
        regs['eflags'] = regs.get('eflags', 0) | 0x100
        self.set_context(h_thread, regs)
```

### SoftwareBreakpointManager (breakpoint/software.py, ~40 lines)

```python
class SoftwareBreakpointManager:
    def __init__(self, session): self._s = session
    def set(self, addr):
        original = _memory.read_process_memory(self._s.process_handle, addr, 1)
        _memory.write_process_memory(self._s.process_handle, addr, b'\xCC')
        self._s.bp_counter += 1
        bp_id = self._s.bp_counter
        self._s.breakpoints[bp_id] = ('int3', addr, original)
        return bp_id
    def remove(self, bp_id):
        if bp_id not in self._s.breakpoints: raise BreakpointError(...)
        _, addr, orig = self._s.breakpoints.pop(bp_id)
        _memory.write_process_memory(self._s.process_handle, addr, orig)
    def find(self, addr):
        for bp_id, bp_info in self._s.breakpoints.items():
            if bp_info[0] == 'int3' and bp_info[1] == addr:
                return bp_id
        return None
```

### HardwareBreakpointManager (breakpoint/hardware.py, ~40 lines)

```python
class HardwareBreakpointManager:
    def __init__(self, session): self._s = session
    def set(self, addr, condition='x', length=1, slot=0):
        # cond_map, len_map validation
        _bp.set_hw_breakpoint(self._s.thread_handle, slot, addr, ...)
        self._s.bp_counter += 1
        bp_id = self._s.bp_counter
        self._s.breakpoints[bp_id] = ('hw', addr, slot)
        return bp_id
    def clear(self, slot): _bp.clear_hw_breakpoint(self._s.thread_handle, slot)
    def find(self, addr):
        for bp_id, bp_info in self._s.breakpoints.items():
            if bp_info[0] == 'hw' and bp_info[1] == addr:
                return bp_id
        return None
```

### ModuleResolver (module/resolver.py, ~30 lines)

```python
class ModuleResolver:
    def __init__(self, session): self._s = session
    def enumerate(self):         return _memory.enum_process_modules(self._s.process_handle)
    def get_filename(self, h):   return _memory.get_module_file_name_ex(self._s.process_handle, h)
```

## Import Strategy

- Managers import directly from `pydbg.cython.*` (same as current debugger.py)
- Debugger imports Managers from their new locations
- `__init__.py` imports from `core.debugger` and `core.event`, re-exports everything
- No circular imports: dependency flows one-way → Managers → cython

## Error Handling

Managers raise the same exceptions as current code (ProcessError, MemError, ThreadError,
BreakpointError from `pydbg.exceptions`). No new exception types.

## Tests Impact

- `test_pe.py`: no changes (pure Python, no Debugger dependency)
- `test_debugger.py`: `from pydbg.debugger import DebugEvent` → `from pydbg import DebugEvent`
- All other tests: no changes (they use `from pydbg import Debugger` or `from pydbg.cython import ...`)
