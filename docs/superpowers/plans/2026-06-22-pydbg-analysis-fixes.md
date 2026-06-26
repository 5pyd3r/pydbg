# pydbg Analysis Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 3 issues found during OdenTodo analysis: missing get_teb_address, IAT resolution returning thunks, no memory monitoring for busy-wait games.

**Architecture:** Add get_teb_address to Cython extension with ctypes fallback, add resolve_import to ModuleResolver, add MemoryMonitor class to memory module.

**Tech Stack:** Python 3.10+, Cython, Win32 API (ntdll, kernel32)

---

## File Structure

```
src/pydbg/
├── cython/
│   ├── _win32types.pxd        # Modify: add NtQueryInformationThread declaration
│   └── _thread.pxi            # Modify: add get_teb_address function
├── module/
│   └── resolver.py            # Modify: add resolve_import, get_module_handle
├── memory/
│   ├── __init__.py            # Modify: export MemoryMonitor
│   └── monitor.py             # Create: MemoryMonitor, MemoryChange, Watchpoint
├── __init__.py                # Modify: export MemoryMonitor
tests/
├── test_teb.py                # Create: get_teb_address tests
├── test_module_resolver.py    # Create: resolve_import tests
└── test_memory_monitor.py     # Create: MemoryMonitor tests
```

---

## Task 1: Add get_teb_address (Cython + ctypes fallback)

**Files:**
- Modify: `src/pydbg/cython/_win32types.pxd`
- Modify: `src/pydbg/cython/_thread.pxi`
- Modify: `src/pydbg/stealth/anti_aware.py`
- Create: `tests/test_teb.py`

### Step 1: Write failing test

```python
# tests/test_teb.py
import unittest


class TestGetTebAddress(unittest.TestCase):

    def test_import_from_pydbg(self):
        """get_teb_address should be importable from _pydbg."""
        from pydbg import _pydbg
        self.assertTrue(hasattr(_pydbg, 'get_teb_address'))

    def test_returns_positive_integer(self):
        """get_teb_address should return a positive integer for a live thread."""
        from pydbg import _pydbg
        # This test requires a live thread handle — skip in CI
        import os
        if os.environ.get('CI'):
            self.skipTest("Requires live thread handle")
        h_thread = _pydbg.open_thread(os.getpid())
        try:
            teb = _pydbg.get_teb_address(h_thread)
            self.assertIsInstance(teb, int)
            self.assertGreater(teb, 0)
        finally:
            _pydbg.close_handle(h_thread)
```

Run: `python -m pytest tests/test_teb.py -v`
Expected: FAIL (get_teb_address not found)

### Step 2: Add NtQueryInformationThread to _win32types.pxd

Append to the `cdef extern from "windows.h"` block (after `WaitForSingleObject`):

```cython
    # NtQueryInformationThread for TEB access
    ctypedef long NTSTATUS
    ctypedef struct THREAD_BASIC_INFORMATION:
        NTSTATUS ExitStatus
        void* TebBaseAddress
        ULONG_PTR ClientId[2]
        ULONG_PTR AffinityMask

cdef extern from "ntdll.dll":
    NTSTATUS NtQueryInformationThread(
        HANDLE ThreadHandle,
        ULONG ThreadInformationClass,
        void* ThreadInformation,
        ULONG ThreadInformationLength,
        ULONG* ReturnLength)
```

### Step 3: Add get_teb_address to _thread.pxi

Append at the end of `_thread.pxi`:

```cython
cpdef unsigned long long get_teb_address(unsigned long long h_thread):
    """Get the TEB (Thread Environment Block) address for a thread.

    Uses NtQueryInformationThread with ThreadBasicInformation (class 0).
    Returns the TebBaseAddress as an integer.
    Raises OSError on failure.
    """
    cdef THREAD_BASIC_INFORMATION tbi
    cdef ULONG ret_len = 0
    cdef NTSTATUS status

    status = NtQueryInformationThread(
        <HANDLE><LPVOID>h_thread, 0, &tbi, sizeof(tbi), &ret_len)
    if status != 0:
        raise OSError(f"NtQueryInformationThread failed: NTSTATUS=0x{status & 0xFFFFFFFF:08X}")
    return <unsigned long long>tbi.TebBaseAddress
```

### Step 4: Add ctypes fallback to AntiAware

Modify `src/pydbg/stealth/anti_aware.py` — replace `_get_peb_address` method:

```python
def _get_peb_address(self):
    """Return the PEB address of the debugged process.

    First tries the Cython get_teb_address, then falls back to ctypes.
    """
    h_proc = getattr(self._s, "process_handle", None)
    if h_proc is None:
        return 0x7FFE_0000  # Offline / unit-test mode

    h_thread = getattr(self._s, "thread_handle", None)
    if h_thread is None:
        raise PydbgError("No thread handle available for PEB lookup")

    target_bits = getattr(self._s, "target_arch", 32)

    # Try Cython extension first
    try:
        from .. import _pydbg
        teb = _pydbg.get_teb_address(h_thread)
    except (ImportError, AttributeError, OSError):
        # Fallback: ctypes with NtQueryInformationThread
        teb = self._get_teb_address_ctypes(h_thread)

    if target_bits == 32:
        peb_ptr_offset = 0x30
        fmt = "<I"
    else:
        peb_ptr_offset = 0x60
        fmt = "<Q"

    from .. import _pydbg
    data = _pydbg.read_process_memory(h_proc, teb + peb_ptr_offset, struct.calcsize(fmt))
    return struct.unpack(fmt, data)[0]

def _get_teb_address_ctypes(self, h_thread):
    """Fallback TEB lookup using ctypes + NtQueryInformationThread."""
    import ctypes
    import ctypes.wintypes

    ntdll = ctypes.windll.ntdll
    kernel32 = ctypes.windll.kernel32

    # THREAD_BASIC_INFORMATION structure
    class THREAD_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("ExitStatus", ctypes.c_long),
            ("TebBaseAddress", ctypes.c_void_p),
            ("ClientId", ctypes.c_void_p * 2),
            ("AffinityMask", ctypes.c_void_p),
        ]

    tbi = THREAD_BASIC_INFORMATION()
    ret_len = ctypes.c_ulong(0)

    status = ntdll.NtQueryInformationThread(
        ctypes.c_void_p(h_thread),
        0,  # ThreadBasicInformation
        ctypes.byref(tbi),
        ctypes.sizeof(tbi),
        ctypes.byref(ret_len),
    )
    if status != 0:
        raise OSError(f"NtQueryInformationThread failed: NTSTATUS=0x{status & 0xFFFFFFFF:08X}")
    return tbi.TebBaseAddress
```

### Step 5: Run tests

Run: `python -m pytest tests/test_teb.py tests/test_stealth.py -v`
Expected: PASS

### Step 6: Commit

```bash
git add src/pydbg/cython/_win32types.pxd src/pydbg/cython/_thread.pxi src/pydbg/stealth/anti_aware.py tests/test_teb.py
git commit -m "fix(stealth): add get_teb_address with ctypes fallback

Cython: NtQueryInformationThread in _thread.pxi
Fallback: ctypes-based TEB lookup in AntiAware
AntiAware._get_peb_address now works without Cython rebuild"
```

---

## Task 2: Add resolve_import to ModuleResolver

**Files:**
- Modify: `src/pydbg/module/resolver.py`
- Create: `tests/test_module_resolver.py`

### Step 1: Write failing tests

```python
# tests/test_module_resolver.py
import unittest


class TestResolveImport(unittest.TestCase):

    def test_has_resolve_import_method(self):
        """ModuleResolver should have resolve_import method."""
        from pydbg.module.resolver import ModuleResolver
        from pydbg.core.session import DebugSession
        mr = ModuleResolver(DebugSession())
        self.assertTrue(hasattr(mr, 'resolve_import'))

    def test_has_get_module_handle_method(self):
        """ModuleResolver should have get_module_handle method."""
        from pydbg.module.resolver import ModuleResolver
        from pydbg.core.session import DebugSession
        mr = ModuleResolver(DebugSession())
        self.assertTrue(hasattr(mr, 'get_module_handle'))

    def test_get_module_handle_returns_int_or_none(self):
        """get_module_handle should return an int or None."""
        from pydbg.module.resolver import ModuleResolver
        from pydbg.core.session import DebugSession
        mr = ModuleResolver(DebugSession())
        # kernel32 should always be loaded
        result = mr.get_module_handle("kernel32.dll")
        # In test mode (no process), this may return None or 0
        self.assertTrue(result is None or isinstance(result, int))
```

Run: `python -m pytest tests/test_module_resolver.py -v`
Expected: FAIL

### Step 2: Implement resolve_import and get_module_handle

Append to `src/pydbg/module/resolver.py`:

```python
def resolve_import(self, import_entry, image_base=0):
    """Resolve an ImportEntry to its runtime function address.

    Strategy:
    1. Read IAT memory at (image_base + import_entry.rva) to get loader-resolved address
    2. Fall back to GetProcAddress if IAT is empty

    Args:
        import_entry: ImportEntry from pe.imports
        image_base: Base address of the PE image in the target process

    Returns:
        int: resolved function address, or None if unresolvable
    """
    from ..pe.types import ImportEntry
    if not isinstance(import_entry, ImportEntry):
        raise TypeError("Expected ImportEntry")

    h = self._s.process_handle
    if h is None:
        return None

    ptr_size = 4 if getattr(self._s, 'target_arch', 32) == 32 else 8
    iat_addr = image_base + import_entry.rva

    try:
        data = _pydbg.read_process_memory(h, iat_addr, ptr_size)
        resolved = int.from_bytes(data, 'little')
        if resolved != 0:
            return resolved
    except OSError:
        pass

    # Fallback: GetProcAddress
    return self.get_proc_address(import_entry.dll_name, import_entry.name)

def get_module_handle(self, module_name):
    """Get the handle of a loaded module by name.

    Args:
        module_name: Module name (e.g. "kernel32.dll")

    Returns:
        int: module handle, or None if not found
    """
    try:
        return _pydbg.get_module_handle(module_name)
    except OSError:
        return None

def get_proc_address(self, module_name, function_name):
    """Get the address of a function in a loaded module.

    Args:
        module_name: Module name (e.g. "kernel32.dll")
        function_name: Function name (e.g. "GetProcAddress")

    Returns:
        int: function address, or None if not found
    """
    h_mod = self.get_module_handle(module_name)
    if h_mod is None:
        return None
    try:
        return _pydbg.get_proc_address(h_mod, function_name)
    except OSError:
        return None
```

### Step 3: Run tests

Run: `python -m pytest tests/test_module_resolver.py -v`
Expected: PASS

### Step 4: Commit

```bash
git add src/pydbg/module/resolver.py tests/test_module_resolver.py
git commit -m "feat(module): add resolve_import and get_module_handle to ModuleResolver

resolve_import: reads IAT memory first, falls back to GetProcAddress
get_module_handle: wraps _pydbg.get_module_handle
get_proc_address: wraps _pydbg.get_proc_address"
```

---

## Task 3: Add MemoryMonitor

**Files:**
- Create: `src/pydbg/memory/monitor.py`
- Modify: `src/pydbg/memory/__init__.py`
- Modify: `src/pydbg/__init__.py`
- Create: `tests/test_memory_monitor.py`

### Step 1: Write failing tests

```python
# tests/test_memory_monitor.py
import struct
import unittest


class TestMemoryChange(unittest.TestCase):

    def test_dataclass(self):
        from pydbg.memory.monitor import MemoryChange
        mc = MemoryChange(address=0x40EFC0, old_value=b'\x00\x00\x00\x00',
                          new_value=b'\x01\x00\x00\x00', timestamp=1000)
        self.assertEqual(mc.address, 0x40EFC0)
        self.assertEqual(mc.old_value, b'\x00\x00\x00\x00')
        self.assertEqual(mc.new_value, b'\x01\x00\x00\x00')


class TestWatchpoint(unittest.TestCase):

    def test_dataclass(self):
        from pydbg.memory.monitor import Watchpoint
        wp = Watchpoint(addr=0x40EFC0, size=4, fmt='<I', name='InitFlag')
        self.assertEqual(wp.addr, 0x40EFC0)
        self.assertEqual(wp.size, 4)
        self.assertIsNone(wp.last_value)


class TestMemoryMonitor(unittest.TestCase):

    def test_init(self):
        from pydbg.core.session import DebugSession
        from pydbg.memory.monitor import MemoryMonitor
        session = DebugSession()
        monitor = MemoryMonitor(session)
        self.assertEqual(len(monitor._watchpoints), 0)
        self.assertEqual(len(monitor._changes), 0)

    def test_watch_adds_watchpoint(self):
        from pydbg.core.session import DebugSession
        from pydbg.memory.monitor import MemoryMonitor
        session = DebugSession()
        monitor = MemoryMonitor(session)
        monitor.watch(0x40EFC0, size=4, fmt='<I', name='InitFlag')
        self.assertIn(0x40EFC0, monitor._watchpoints)
        self.assertEqual(monitor._watchpoints[0x40EFC0].name, 'InitFlag')

    def test_unwatch_removes_watchpoint(self):
        from pydbg.core.session import DebugSession
        from pydbg.memory.monitor import MemoryMonitor
        session = DebugSession()
        monitor = MemoryMonitor(session)
        monitor.watch(0x40EFC0)
        monitor.unwatch(0x40EFC0)
        self.assertNotIn(0x40EFC0, monitor._watchpoints)

    def test_poll_detects_change(self):
        """Simulate memory change by overriding read method."""
        from pydbg.core.session import DebugSession
        from pydbg.memory.monitor import MemoryMonitor

        session = DebugSession()
        monitor = MemoryMonitor(session)

        # Track read calls
        read_values = [b'\x00\x00\x00\x00', b'\x01\x00\x00\x00']
        read_index = [0]

        def mock_read(addr, size):
            val = read_values[read_index[0]]
            read_index[0] += 1
            return val

        monitor._read_memory = mock_read
        monitor.watch(0x40EFC0, size=4, fmt='<I', name='InitFlag')

        # First poll: sets initial value, no change
        changes = monitor.poll()
        self.assertEqual(len(changes), 0)

        # Second poll: value changed
        changes = monitor.poll()
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].address, 0x40EFC0)
        self.assertEqual(changes[0].old_value, b'\x00\x00\x00\x00')
        self.assertEqual(changes[0].new_value, b'\x01\x00\x00\x00')

    def test_poll_no_change(self):
        """No change when value stays the same."""
        from pydbg.core.session import DebugSession
        from pydbg.memory.monitor import MemoryMonitor

        session = DebugSession()
        monitor = MemoryMonitor(session)

        read_values = [b'\x00\x00\x00\x00', b'\x00\x00\x00\x00']
        read_index = [0]

        def mock_read(addr, size):
            val = read_values[read_index[0]]
            read_index[0] += 1
            return val

        monitor._read_memory = mock_read
        monitor.watch(0x40EFC0)

        monitor.poll()  # initial
        changes = monitor.poll()  # same value
        self.assertEqual(len(changes), 0)

    def test_get_snapshot(self):
        from pydbg.core.session import DebugSession
        from pydbg.memory.monitor import MemoryMonitor

        session = DebugSession()
        monitor = MemoryMonitor(session)

        def mock_read(addr, size):
            return b'\x05\x00\x00\x00'

        monitor._read_memory = mock_read
        monitor.watch(0x40EFC0, size=4, fmt='<I')
        monitor.poll()

        snapshot = monitor.get_snapshot()
        self.assertIn(0x40EFC0, snapshot)

    def test_get_changes_with_filter(self):
        from pydbg.core.session import DebugSession
        from pydbg.memory.monitor import MemoryMonitor

        session = DebugSession()
        monitor = MemoryMonitor(session)

        read_values = [
            b'\x00\x00\x00\x00',  # poll 1: addr1 init
            b'\x00\x00\x00\x00',  # poll 1: addr2 init
            b'\x01\x00\x00\x00',  # poll 2: addr1 changed
            b'\x00\x00\x00\x00',  # poll 2: addr2 same
        ]
        read_index = [0]

        def mock_read(addr, size):
            val = read_values[read_index[0]]
            read_index[0] += 1
            return val

        monitor._read_memory = mock_read
        monitor.watch(0x40EFC0)
        monitor.watch(0x40EFF0)

        monitor.poll()
        monitor.poll()

        all_changes = monitor.get_changes()
        self.assertEqual(len(all_changes), 1)

        addr_changes = monitor.get_changes(addr=0x40EFC0)
        self.assertEqual(len(addr_changes), 1)

        no_changes = monitor.get_changes(addr=0x40EFF0)
        self.assertEqual(len(no_changes), 0)

    def test_clear_history(self):
        from pydbg.core.session import DebugSession
        from pydbg.memory.monitor import MemoryMonitor

        session = DebugSession()
        monitor = MemoryMonitor(session)

        def mock_read(addr, size):
            return b'\x01\x00\x00\x00'

        monitor._read_memory = mock_read
        monitor.watch(0x40EFC0)
        monitor.poll()

        self.assertEqual(len(monitor.get_changes()), 0)  # no change on first poll
        monitor.clear_history()
        self.assertEqual(len(monitor._changes), 0)


if __name__ == '__main__':
    unittest.main()
```

Run: `python -m pytest tests/test_memory_monitor.py -v`
Expected: FAIL

### Step 2: Implement MemoryMonitor

```python
# src/pydbg/memory/monitor.py
"""MemoryMonitor — periodic memory monitoring for busy-wait games."""

import time
from dataclasses import dataclass, field

from .. import _pydbg
from ..exceptions import MemError


@dataclass
class MemoryChange:
    """A detected change in monitored memory."""
    address: int
    old_value: bytes
    new_value: bytes
    timestamp: int


@dataclass
class Watchpoint:
    """A monitored memory address."""
    addr: int
    size: int
    fmt: str
    name: str
    last_value: bytes = None


class MemoryMonitor:
    """Periodic memory monitoring for processes with infrequent API calls.

    Typical usage::

        monitor = MemoryMonitor(session)
        monitor.watch(0x40EFC0, size=4, fmt='<I', name='InitFlag')
        monitor.watch(0x40EFF0, size=4, fmt='<I', name='RenderFlag')

        while True:
            changes = monitor.poll()
            for c in changes:
                print(f"0x{c.address:X}: {c.old_value.hex()} -> {c.new_value.hex()}")
            time.sleep(0.01)
    """

    def __init__(self, session):
        self._s = session
        self._watchpoints = {}  # addr -> Watchpoint
        self._changes = []      # list of MemoryChange

    def watch(self, addr, size=4, fmt='<I', name=None):
        """Add a memory address to monitor.

        Args:
            addr: Memory address to watch.
            size: Number of bytes to read (default 4).
            fmt: struct format string for display (default '<I' = uint32 LE).
            name: Human-readable name for this watchpoint.
        """
        wp = Watchpoint(addr=addr, size=size, fmt=fmt, name=name or hex(addr))
        self._watchpoints[addr] = wp

    def unwatch(self, addr):
        """Remove a memory address from monitoring."""
        self._watchpoints.pop(addr, None)

    def poll(self):
        """Read all watched addresses and detect changes.

        Returns:
            List of MemoryChange for addresses that changed since last poll.
        """
        changes = []
        now = int(time.time() * 1000)

        for addr, wp in self._watchpoints.items():
            try:
                current = self._read_memory(addr, wp.size)
            except (OSError, MemError):
                continue

            if wp.last_value is not None and current != wp.last_value:
                changes.append(MemoryChange(
                    address=addr,
                    old_value=wp.last_value,
                    new_value=current,
                    timestamp=now,
                ))

            wp.last_value = current

        self._changes.extend(changes)
        return changes

    def get_changes(self, addr=None, since=None):
        """Get recorded changes.

        Args:
            addr: Filter by address (optional).
            since: Filter by timestamp (optional).

        Returns:
            List of MemoryChange.
        """
        result = self._changes
        if addr is not None:
            result = [c for c in result if c.address == addr]
        if since is not None:
            result = [c for c in result if c.timestamp >= since]
        return result

    def get_snapshot(self):
        """Get current values of all watched addresses.

        Returns:
            Dict of addr -> last_value bytes.
        """
        return {addr: wp.last_value for addr, wp in self._watchpoints.items()
                if wp.last_value is not None}

    def clear_history(self):
        """Clear all recorded changes."""
        self._changes.clear()

    def _read_memory(self, addr, size):
        """Read process memory. Override in tests for mocking."""
        return _pydbg.read_process_memory(self._s.process_handle, addr, size)
```

### Step 3: Update exports

Modify `src/pydbg/memory/__init__.py`:
```python
from .manager import MemoryManager
from .monitor import MemoryMonitor, MemoryChange, Watchpoint

__all__ = ['MemoryManager', 'MemoryMonitor', 'MemoryChange', 'Watchpoint']
```

Add to `src/pydbg/__init__.py` imports:
```python
from .memory.monitor import MemoryMonitor, MemoryChange, Watchpoint
```

Add to `__all__`:
```python
    "MemoryMonitor", "MemoryChange", "Watchpoint",
```

### Step 4: Run tests

Run: `python -m pytest tests/test_memory_monitor.py -v`
Expected: PASS

### Step 5: Commit

```bash
git add src/pydbg/memory/monitor.py src/pydbg/memory/__init__.py src/pydbg/__init__.py tests/test_memory_monitor.py
git commit -m "feat(memory): add MemoryMonitor for periodic memory monitoring

Watches specific addresses, detects changes on poll().
Designed for busy-wait games where breakpoints rarely trigger.
Includes MemoryChange and Watchpoint dataclasses."
```

---

## Task 4: Final Verification

### Step 1: Run full test suite

```bash
python -m pytest tests/ -v --tb=short
```

Expected: All tests pass.

### Step 2: Verify new imports

```bash
PYTHONPATH=src python -c "
from pydbg import MemoryMonitor, MemoryChange, Watchpoint
from pydbg.module.resolver import ModuleResolver
print('All imports OK')
print(f'MemoryMonitor: {MemoryMonitor}')
print(f'ModuleResolver.resolve_import: {ModuleResolver.resolve_import}')
"
```

Expected: `All imports OK`

### Step 3: Commit fixes (if any)

```bash
git add -A
git commit -m "chore: final verification fixes"
```

---

## Summary

| Task | Module | Files | Tests |
|------|--------|-------|-------|
| 1 | get_teb_address | 3 modified, 1 created | 2 |
| 2 | resolve_import | 1 modified, 1 created | 3 |
| 3 | MemoryMonitor | 2 modified, 2 created | 9 |
| 4 | Verification | - | - |

**Total: 4 tasks, ~6 files changed, ~14 tests**
