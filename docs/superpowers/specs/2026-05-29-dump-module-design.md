# Dump Module Design

## Goal

Add crash dump analysis and stack walking support (`dump/`) using dbghelp.dll. Provides minidump
file reading (stream extraction) and x64 stack unwinding. No new external dependencies (dbghelp
already linked).

## Scope

Four files:

- `cython/_dump.pxi` — Cython wrappers for dbghelp.dll dump/stack APIs
- `dump/__init__.py` — package exports
- `dump/minidump.py` — `MinidumpReader`: read .dmp files, extract streams
- `dump/stackwalk.py` — `StackWalker`: x64 stack unwind with frame iteration

## Architecture

```
Win32 (dbghelp.dll) → _dump.pxi → _pydbg → dump/minidump.py
                                         → dump/stackwalk.py
```

## Cython Layer — _dump.pxi

Functions:
```cython
cpdef int mini_dump_read_dump_stream(unsigned long long base_of_dump,
    unsigned long stream_number):
    """Read a minidump stream. Returns dict with data and size."""

cpdef tuple stack_walk64(unsigned long long machine_type, unsigned long long h_process,
    unsigned long long h_thread, unsigned long long context_ptr,
    unsigned long long frame_base, unsigned long long frame_ip):
    """Walk one stack frame. Returns (frame_base, frame_ip, func_name, displacement)."""

cpdef unsigned long long sym_function_table_access64(
    unsigned long long h_process, unsigned long long addr_base):
    """Get function table access handle for stack walking."""
```

New types in `_win32types.pxd` (inside dbghelp.h extern block):
- `MINIDUMP_DIRECTORY` structure
- `MINIDUMP_MEMORY_LIST`, `MINIDUMP_THREAD_LIST`, `MINIDUMP_MODULE_LIST` streams
- `STACKFRAME64` structure
- `MiniDumpReadDumpStream`, `StackWalk64`, `SymFunctionTableAccess64`

## dump/minidump.py — MinidumpReader

```python
class MinidumpReader:
    """Read Windows minidump (.dmp) files."""

    def __init__(self, path_or_data):
        """Open minidump from file path or bytes."""

    def get_stream(self, stream_type):
        """Extract a named stream. Returns raw bytes."""

    def get_thread_list(self):
        """Extract thread list stream."""

    def get_module_list(self):
        """Extract module list stream."""

    def get_exception_info(self):
        """Extract exception stream."""

    def get_memory_list(self):
        """Extract memory stream."""
```

## dump/stackwalk.py — StackWalker

```python
class StackWalker:
    """x64 stack frame walker using dbghelp.dll."""

    def __init__(self, session):
        self._s = session

    def walk(self, h_thread, context, max_frames=64):
        """Iterate stack frames. Yields (frame_index, ip, sp, func_name)."""

    def get_call_stack(self, h_thread, max_frames=64):
        """Get call stack as list of dicts."""
```

Uses `StackWalk64` with `SymFunctionTableAccess64` — dbghelp already handles the complex
unwind codes internally.

## Public API

```python
from .dump.minidump import MinidumpReader
from .dump.stackwalk import StackWalker
# __all__: + "MinidumpReader", "StackWalker"
```

## Non-goals

- MiniDumpWriteDump (creating dumps — can add later)
- x86 stack walking (can add later)
- Custom unwind code interpreter
- Memory region extraction (just stream IDs for now)
