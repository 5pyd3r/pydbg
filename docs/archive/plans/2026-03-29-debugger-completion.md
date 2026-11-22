# Debugger Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix naming inconsistency (`PydbgMemoryError` → `MemError`), add 3 missing high-level API methods, complete incomplete test, and add new test coverage for `DebugEvent` and exception helpers.

**Architecture:** Follow existing patterns — Cython layer raises `OSError`, Python layer converts to custom exceptions. No new Cython code needed; all 3 new methods wrap existing Cython functions.

**Tech Stack:** Python, Cython (already built), unittest

---

## File Structure

| File | Action | Purpose |
|------|--------|---------|
| `pydbg/debugger.py` | Modify | Fix `PydbgMemoryError` → `MemError` (lines 158, 163, 176, 181, 193, 198, 207, 212, 224, 229); add 3 new methods |
| `pydbg/__init__.py` | Modify | Fix `__all__`: `'MemoryError'` → `'MemError'` (line 16) |
| `tests/test_memory.py` | Modify | Complete `test_write_and_read_back` with write/read/assert |
| `tests/test_debugger.py` | Create | New test file for DebugEvent, new API methods, exception helpers |

---

### Task 1: Fix naming inconsistency — `PydbgMemoryError` → `MemError`

**Files:**
- Modify: `pydbg/debugger.py` — replace all `PydbgMemoryError` with `MemError`
- Modify: `pydbg/__init__.py` — fix `__all__`

- [ ] **Step 1: Fix `debugger.py` — replace `PydbgMemoryError` with `MemError`**

The import on line 9 already correctly imports `MemError`. The problem is that the code references `PydbgMemoryError` which is never imported. Replace all 10 occurrences.

In `pydbg/debugger.py`, replace all instances of `PydbgMemoryError` with `MemError`:

```
Lines to change (old → new):
- Line 158:  Raises:\n            PydbgMemoryError → Raises:\n            MemError
- Line 163:  raise PydbgMemoryError → raise MemError
- Line 176:  Raises:\n            PydbgMemoryError → Raises:\n            MemError
- Line 181:  raise PydbgMemoryError → raise MemError
- Line 193:  Raises:\n            PydbgMemoryError → Raises:\n            MemError
- Line 198:  raise PydbgMemoryError → raise MemError
- Line 207:  Raises:\n            PydbgMemoryError → Raises:\n            MemError
- Line 212:  raise PydbgMemoryError → raise MemError
- Line 224:  Raises:\n            PydbgMemoryError → Raises:\n            MemError
- Line 229:  raise PydbgMemoryError → raise MemError
```

Use `replace_all: true` with `old_string: "PydbgMemoryError"` and `new_string: "MemError"`.

- [ ] **Step 2: Fix `__init__.py` — change `'MemoryError'` to `'MemError'` in `__all__`**

In `pydbg/__init__.py` line 16, change `'MemoryError'` to `'MemError'`.

```python
# Before (line 16):
    'MemoryError',
# After:
    'MemError',
```

- [ ] **Step 3: Commit**

```bash
git add pydbg/debugger.py pydbg/__init__.py
git commit -m "fix: unify naming to MemError across debugger.py and __init__.py"
```

---

### Task 2: Add 3 missing methods to `Debugger` class

**Files:**
- Modify: `pydbg/debugger.py` — add `terminate_process()`, `get_exit_code()`, `protect_memory()`

- [ ] **Step 1: Add `terminate_process(exit_code=1)` method**

Add after `close_handle()` at the end of the `Debugger` class (after line 427). This wraps `_process.terminate_process()`.

```python
    def terminate_process(self, exit_code=1):
        """Terminate the debugged process.

        Args:
            exit_code: Process exit code (default 1).

        Raises:
            ProcessError: No process handle or termination failed.
        """
        if self._process_handle is None:
            raise ProcessError("No process handle")
        try:
            _process.terminate_process(self._process_handle, exit_code)
        except OSError as e:
            raise ProcessError(f"TerminateProcess failed: {e}")
```

- [ ] **Step 2: Add `get_exit_code()` method**

Add after `terminate_process()`. This wraps `_process.get_exit_code()`.

```python
    def get_exit_code(self):
        """Get the exit code of the debugged process.

        Returns:
            int: Process exit code.

        Raises:
            ProcessError: No process handle or call failed.
        """
        if self._process_handle is None:
            raise ProcessError("No process handle")
        try:
            return _process.get_exit_code(self._process_handle)
        except OSError as e:
            raise ProcessError(f"GetExitCodeProcess failed: {e}")
```

- [ ] **Step 3: Add `protect_memory(addr, size, protect)` method**

Add after `get_exit_code()`. This wraps `_memory.virtual_protect_ex()`.

```python
    def protect_memory(self, addr, size, protect):
        """Change memory protection on a region.

        Args:
            addr: Memory address (int).
            size: Region size in bytes.
            protect: New protection value (e.g. 0x40 = PAGE_EXECUTE_READWRITE).

        Returns:
            int: Previous protection value.

        Raises:
            MemError: On failure.
        """
        try:
            return _memory.virtual_protect_ex(
                self._process_handle, addr, size, protect)
        except OSError as e:
            raise MemError(f"VirtualProtectEx at 0x{addr:X}: {e}")
```

- [ ] **Step 4: Commit**

```bash
git add pydbg/debugger.py
git commit -m "feat: add terminate_process, get_exit_code, protect_memory to Debugger"
```

---

### Task 3: Complete `test_write_and_read_back` in `test_memory.py`

**Files:**
- Modify: `tests/test_memory.py` — complete the test at lines 39-56

- [ ] **Step 1: Write the complete test**

Replace the incomplete `test_write_and_read_back` method (lines 39-56) with a version that finds a committed region, writes data, reads it back, and asserts equality.

```python
    def test_write_and_read_back(self):
        """Write bytes, read back, verify."""
        from pydbg.cython import _memory

        # Get a writable region
        modules = _memory.enum_process_modules(self.h_proc)
        base = modules[0]['base_address']

        # Find a committed, writable region via VirtualQueryEx
        addr = base + 0x1000
        for _ in range(100):
            try:
                info = _memory.virtual_query_ex(self.h_proc, addr)
                if info['state'] == 0x1000:  # MEM_COMMIT
                    break
                addr = info['base_address'] + info['region_size']
            except OSError:
                break

        # Write test data
        test_data = b'\xDE\xAD\xBE\xEF'
        written = _memory.write_process_memory(self.h_proc, addr, test_data)
        self.assertGreater(written, 0)

        # Read back and verify
        read_back = _memory.read_process_memory(self.h_proc, addr, len(test_data))
        self.assertEqual(read_back[:len(test_data)], test_data)
```

- [ ] **Step 2: Commit**

```bash
git add tests/test_memory.py
git commit -m "test: complete test_write_and_read_back with write/read/assert"
```

---

### Task 4: Create `tests/test_debugger.py`

**Files:**
- Create: `tests/test_debugger.py`

- [ ] **Step 1: Create `tests/test_debugger.py` with `TestDebugEvent` class**

```python
"""Tests for DebugEvent, Debugger API completeness, and exception helpers."""

import unittest

from tests import TEST_TARGET_PATH


class TestDebugEvent(unittest.TestCase):
    """Tests for the DebugEvent wrapper class."""

    def test_debug_event_attributes(self):
        """Verify DebugEvent correctly parses event dict."""
        from pydbg.debugger import DebugEvent

        raw = {
            'event_name': 'CREATE_PROCESS',
            'pid': 1234,
            'tid': 5678,
        }
        event = DebugEvent(raw)
        self.assertEqual(event.type, 'CREATE_PROCESS')
        self.assertEqual(event.pid, 1234)
        self.assertEqual(event.tid, 5678)
        self.assertIsNone(event.exception_code)
        self.assertIsNone(event.exception_addr)
        self.assertIsNone(event.first_chance)
        self.assertEqual(event.raw, raw)

    def test_debug_event_repr(self):
        """Verify __repr__ format."""
        from pydbg.debugger import DebugEvent

        raw = {'event_name': 'EXCEPTION', 'pid': 100, 'tid': 200}
        event = DebugEvent(raw)
        self.assertEqual(repr(event), '<DebugEvent EXCEPTION pid=100 tid=200>')

    def test_debug_event_default_values(self):
        """Verify defaults for missing keys."""
        from pydbg.debugger import DebugEvent

        event = DebugEvent({})
        self.assertEqual(event.type, 'UNKNOWN')
        self.assertEqual(event.pid, 0)
        self.assertEqual(event.tid, 0)


class TestDebuggerAPICompleteness(unittest.TestCase):
    """Tests for terminate_process and get_exit_code."""

    def test_terminate_process(self):
        """Verify terminate_process kills the target."""
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        dbg.terminate_process(0)
        dbg.close_handle(dbg._process_handle)
        dbg.close_handle(dbg._thread_handle)

    def test_get_exit_code_running(self):
        """Verify get_exit_code returns STILL_ACTIVE for running process."""
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        code = dbg.get_exit_code()
        self.assertEqual(code, 259)  # STILL_ACTIVE

        dbg.terminate_process(0)
        dbg.close_handle(dbg._process_handle)
        dbg.close_handle(dbg._thread_handle)


class TestExceptionHelpers(unittest.TestCase):
    """Tests for exception_code_to_str and get_exception_info."""

    def test_exception_code_to_str(self):
        """Verify known codes map to correct names."""
        from pydbg.cython import _exception

        self.assertEqual(
            _exception.exception_code_to_str(0x80000003),
            'EXCEPTION_BREAKPOINT')
        self.assertEqual(
            _exception.exception_code_to_str(0xC0000005),
            'EXCEPTION_ACCESS_VIOLATION')
        self.assertEqual(
            _exception.exception_code_to_str(0x80000004),
            'EXCEPTION_SINGLE_STEP')

    def test_exception_code_unknown(self):
        """Verify unknown code returns formatted string."""
        from pydbg.cython import _exception

        result = _exception.exception_code_to_str(0xDEADBEEF)
        self.assertEqual(result, 'UNKNOWN_EXCEPTION(0xDEADBEEF)')


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Commit**

```bash
git add tests/test_debugger.py
git commit -m "test: add DebugEvent, API completeness, and exception helper tests"
```

---

## Verification

Run all tests to confirm nothing is broken:

```bash
cd /c/Users/spyder/Desktop/workspace/mimo_cc/pydbg
python -m pytest tests/ -v
```

Expected: all existing tests pass + new tests pass.
