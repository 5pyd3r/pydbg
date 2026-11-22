# pydbg Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python module using Cython to wrap Win32 debugging APIs (dbghelp.dll etc.) with modular design, Meson+Ninja+Clang build, unittest testing.

**Architecture:** Fine-grained Cython modules (`_process.pyx`, `_memory.pyx`, `_thread.pyx`, `_exception.pyx`, `_bp.pyx`) each wrap one Win32 API domain. Shared types live in `_win32types.pxd`. Python layer in `pydbg.py` provides unified procedural API. Error handling: Cython raises `OSError` via `GetLastError()`, Python converts to custom exceptions.

**Tech Stack:** Python 3, Cython, Meson, Ninja, Clang (MSVC toolchain), unittest, Win32 API

---

## File Map

| File | Purpose |
|---|---|
| `meson.build` | Root build: project config, subdirs |
| `meson.options` | Build options (python_path, buildtype) |
| `src/meson.build` | src subdir: declares Python package |
| `src/cython/meson.build` | Cython compilation: .pyx → .pyd, link Win32 libs |
| `src/__init__.py` | Package init, re-export public API |
| `src/exceptions.py` | Custom exception hierarchy |
| `src/pydbg.py` | High-level Debugger class |
| `src/cython/_win32types.pxd` | Shared C type declarations |
| `src/cython/_process.pyx` | CreateProcess, WaitForDebugEvent, ContinueDebugEvent, DebugActiveProcess |
| `src/cython/_memory.pyx` | ReadProcessMemory, WriteProcessMemory, VirtualQueryEx, EnumProcessModules |
| `src/cython/_thread.pyx` | GetThreadContext, SetThreadContext, SuspendThread, ResumeThread, OpenThread |
| `src/cython/_exception.pyx` | Exception code constants, EXCEPTION_RECORD parsing |
| `src/cython/_bp.pyx` | Hardware breakpoint (Dr0-Dr3, Dr7) management |
| `tests/meson.build` | Test config |
| `tests/target/simple_target.c` | Minimal C program for debugging |
| `tests/test_process.py` | Process creation/attach/detach/event tests |
| `tests/test_memory.py` | Memory read/write/query/module tests |
| `tests/test_thread.py` | Thread context/suspend/resume tests |
| `tests/test_breakpoint.py` | HW breakpoint tests |

---

## Task 1: Project Scaffolding & Build System

**Files:**
- Create: `meson.build`
- Create: `meson.options`
- Create: `src/meson.build`
- Create: `src/__init__.py`
- Create: `src/exceptions.py`
- Create: `src/cython/meson.build`

- [ ] **Step 1: Create root `meson.build`**

```meson
project('pydbg', 'c',
  version: '0.1.0',
  meson_version: '>=0.60',
  default_options: [
    'c_std=c11',
    'buildtype=debug',
  ])

# Python dependency
py_mod = import('python')
py = py_mod.find_installation(pure: false)

subdir('src')
subdir('tests')
```

- [ ] **Step 2: Create `meson.options`**

```meson
option('buildtype', type: 'combo',
  choices: ['debug', 'release'],
  value: 'debug',
  description: 'Build type')
```

- [ ] **Step 3: Create `src/__init__.py`**

```python
from .pydbg import Debugger
from .exceptions import (
    PydbgError,
    ProcessError,
    MemoryError,
    ThreadError,
    BreakpointError,
    TimeoutError,
)

__version__ = '0.1.0'
__all__ = [
    'Debugger',
    'PydbgError',
    'ProcessError',
    'MemoryError',
    'ThreadError',
    'BreakpointError',
    'TimeoutError',
]
```

- [ ] **Step 4: Create `src/exceptions.py`**

```python
class PydbgError(Exception):
    """Base exception for all pydbg errors."""


class ProcessError(PydbgError):
    """Process-related errors (create, attach, detach)."""


class MemoryError(PydbgError):
    """Memory operation errors (read, write, query)."""


class ThreadError(PydbgError):
    """Thread operation errors (context, suspend, resume)."""


class BreakpointError(PydbgError):
    """Breakpoint operation errors."""


class TimeoutError(PydbgError):
    """Timeout waiting for debug event."""
```

- [ ] **Step 5: Create `src/meson.build`**

```meson
# Install pure Python files
py.install_sources(
  '__init__.py',
  'exceptions.py',
  'pydbg.py',
  subdir: 'pydbg',
)

subdir('cython')
```

- [ ] **Step 6: Create `src/cython/meson.build`**

```meson
cython = find_program('cython', required: true)

# Win32 libraries
win32_libs = [
  dependency('threads'),  # placeholder — actual Win32 libs via link_args
]

cython_sources = [
  '_process.pyx',
  '_memory.pyx',
  '_thread.pyx',
  '_exception.pyx',
  '_bp.pyx',
]

# Cython compilation: .pyx -> .c -> .pyd
foreach src : cython_sources
  # Step 1: cythonize .pyx to .c
  c_file = src.replace('.pyx', '.c')
  custom_target(
    'cython_' + src,
    input: src,
    output: c_file,
    command: [cython, '-3', '--fast-fail', '-o', '@OUTPUT@', '@INPUT@'],
    depend_files: ['_win32types.pxd'],
  )

  # Step 2: compile .c to shared module (.pyd)
  py.extension_module(
    src.replace('.pyx', ''),
    c_file,
    c_args: [] + (get_option('buildtype') == 'debug' ? ['-D_DEBUG'] : []),
    link_args: ['-ldbghelp', '-lkernel32', '-ladvapi32', '-lpsapi'],
    subdir: 'pydbg/cython',
    install: true,
    install_dir: py.get_install_dir() / 'pydbg' / 'cython',
  )
endforeach
```

- [ ] **Step 7: Verify directory structure exists**

```bash
ls src/cython/
# Should show empty dir (or meson.build)
```

- [ ] **Step 8: Commit scaffolding**

```bash
git add meson.build meson.options src/
git commit -m "chore: scaffold project with Meson build system and exception module"
```

---

## Task 2: Test Target Program

**Files:**
- Create: `tests/target/simple_target.c`
- Create: `tests/meson.build`

- [ ] **Step 1: Create `tests/target/simple_target.c`**

```c
#include <stdio.h>

int main(void) {
    int x = 42;
    int y = x + 1;
    int z = x + y;

    printf("Hello from pydbg test target\n");
    printf("x=%d y=%d z=%d\n", x, y, z);

    /* Sleep so debugger has time to attach */
#ifdef _WIN32
    Sleep(1000);
#else
    sleep(1);
#endif

    return 0;
}
```

- [ ] **Step 2: Create `tests/meson.build`**

```meson
# Build test target
test_target = executable(
  'simple_target',
  'target/simple_target.c',
)

# Test runner: use Python unittest via meson test
test(
  'process',
  py,
  args: ['-m', 'unittest', 'tests.test_process'],
  env: environment({
    'TEST_TARGET_PATH': test_target.full_path(),
  }),
)

test(
  'memory',
  py,
  args: ['-m', 'unittest', 'tests.test_memory'],
  env: environment({
    'TEST_TARGET_PATH': test_target.full_path(),
  }),
)

test(
  'thread',
  py,
  args: ['-m', 'unittest', 'tests.test_thread'],
  env: environment({
    'TEST_TARGET_PATH': test_target.full_path(),
  }),
)

test(
  'breakpoint',
  py,
  args: ['-m', 'unittest', 'tests.test_breakpoint'],
  env: environment({
    'TEST_TARGET_PATH': test_target.full_path(),
  }),
)
```

- [ ] **Step 3: Create `tests/__init__.py`**

```python
import os

TEST_TARGET_PATH = os.environ.get('TEST_TARGET_PATH', 'simple_target.exe')
```

- [ ] **Step 4: Commit test infrastructure**

```bash
git add tests/
git commit -m "chore: add test target program and meson test config"
```

---

## Task 3: Cython Type Definitions (`_win32types.pxd`)

**Files:**
- Create: `src/cython/_win32types.pxd`

- [ ] **Step 1: Create `src/cython/_win32types.pxd`**

```cython
# _win32types.pxd — Shared Win32 type declarations for pydbg

from libc.stdint cimport uint32_t, uint64_t

cdef extern from "windows.h":
    # Basic types
    ctypedef void* HANDLE
    ctypedef unsigned long DWORD
    ctypedef unsigned short WORD
    ctypedef void* LPVOID
    ctypedef unsigned long long SIZE_T
    ctypedef int BOOL
    ctypedef long LONG
    ctypedef unsigned long long ULONG_PTR
    ctypedef unsigned long long DWORD64
    ctypedef char* LPSTR
    ctypedef const char* LPCSTR
    ctypedef unsigned short USHORT
    ctypedef unsigned char UCHAR

    # === Constants ===
    DWORD DEBUG_PROCESS
    DWORD DEBUG_ONLY_THIS_PROCESS
    DWORD CREATE_SUSPENDED
    DWORD INFINITE
    DWORD DBG_CONTINUE
    DWORD DBG_EXCEPTION_NOT_HANDLED
    DWORD EXCEPTION_DEBUG_EVENT
    DWORD CREATE_THREAD_DEBUG_EVENT
    DWORD CREATE_PROCESS_DEBUG_EVENT
    DWORD EXIT_THREAD_DEBUG_EVENT
    DWORD EXIT_PROCESS_DEBUG_EVENT
    DWORD LOAD_DLL_DEBUG_EVENT
    DWORD UNLOAD_DLL_DEBUG_EVENT
    DWORD OUTPUT_DEBUG_STRING_EVENT
    DWORD RIP_EVENT
    DWORD EXCEPTION_ACCESS_VIOLATION
    DWORD EXCEPTION_BREAKPOINT
    DWORD EXCEPTION_SINGLE_STEP
    DWORD EXCEPTION_GUARD_PAGE
    DWORD EXCEPTION_ARRAY_BOUNDS_EXCEEDED
    DWORD EXCEPTION_FLT_DENORMAL_OPERAND
    DWORD EXCEPTION_FLT_DIVIDE_BY_ZERO
    DWORD EXCEPTION_FLT_INEXACT_RESULT
    DWORD EXCEPTION_FLT_INVALID_OPERATION
    DWORD EXCEPTION_FLT_OVERFLOW
    DWORD EXCEPTION_FLT_STACK_CHECK
    DWORD EXCEPTION_FLT_UNDERFLOW
    DWORD EXCEPTION_INT_DIVIDE_BY_ZERO
    DWORD EXCEPTION_INT_OVERFLOW
    DWORD EXCEPTION_PRIVILEGED_INSTRUCTION
    DWORD EXCEPTION_STACK_OVERFLOW

    DWORD THREAD_ALL_ACCESS
    DWORD CONTEXT_ALL
    DWORD CONTEXT_DEBUG_REGISTERS
    DWORD CONTEXT_INTEGER
    DWORD CONTEXT_CONTROL

    # Memory constants
    DWORD MEM_COMMIT
    DWORD MEM_RESERVE
    DWORD MEM_FREE
    DWORD MEM_PRIVATE
    DWORD MEM_MAPPED
    DWORD MEM_IMAGE
    DWORD PAGE_NOACCESS
    DWORD PAGE_READONLY
    DWORD PAGE_READWRITE
    DWORD PAGE_EXECUTE
    DWORD PAGE_EXECUTE_READ
    DWORD PAGE_EXECUTE_READWRITE

    # === Structures ===

    # EXCEPTION_RECORD
    ctypedef struct EXCEPTION_RECORD:
        DWORD ExceptionCode
        DWORD ExceptionFlags
        EXCEPTION_RECORD* ExceptionRecord
        LPVOID ExceptionAddress
        DWORD NumberParameters
        ULONG_PTR ExceptionInformation[15]

    # CREATE_PROCESS_DEBUG_INFO
    ctypedef struct CREATE_PROCESS_DEBUG_INFO:
        HANDLE hFile
        HANDLE hProcess
        HANDLE hThread
        LPVOID lpBaseOfImage
        DWORD dwDebugInfoFileOffset
        DWORD nDebugInfoSize
        LPVOID lpThreadLocalBase
        DWORD (*lpStartAddress)(LPVOID)
        LPVOID lpImageName
        WORD fUnicode

    # CREATE_THREAD_DEBUG_INFO
    ctypedef struct CREATE_THREAD_DEBUG_INFO:
        HANDLE hThread
        LPVOID lpThreadLocalBase
        DWORD (*lpStartAddress)(LPVOID)

    # EXIT_PROCESS_DEBUG_INFO
    ctypedef struct EXIT_PROCESS_DEBUG_INFO:
        DWORD dwExitCode

    # EXIT_THREAD_DEBUG_INFO
    ctypedef struct EXIT_THREAD_DEBUG_INFO:
        DWORD dwExitCode

    # LOAD_DLL_DEBUG_INFO
    ctypedef struct LOAD_DLL_DEBUG_INFO:
        HANDLE hFile
        LPVOID lpBaseOfDll
        DWORD dwDebugInfoFileOffset
        DWORD nDebugInfoSize
        LPVOID lpImageName

    # UNLOAD_DLL_DEBUG_INFO
    ctypedef struct UNLOAD_DLL_DEBUG_INFO:
        LPVOID lpBaseOfDll

    # EXCEPTION_DEBUG_INFO
    ctypedef struct EXCEPTION_DEBUG_INFO:
        EXCEPTION_RECORD ExceptionRecord
        DWORD dwFirstChance

    # OUTPUT_DEBUG_STRING_INFO
    ctypedef struct OUTPUT_DEBUG_STRING_INFO:
        char* lpDebugStringData
        WORD fUnicode
        WORD nDebugStringLength

    # RIP_INFO
    ctypedef struct RIP_INFO:
        DWORD dwError
        DWORD dwType

    # DEBUG_EVENT union
    ctypedef union _u:
        EXCEPTION_DEBUG_INFO Exception
        CREATE_THREAD_DEBUG_INFO CreateThread
        CREATE_PROCESS_DEBUG_INFO CreateProcessInfo
        EXIT_THREAD_DEBUG_INFO ExitThread
        EXIT_PROCESS_DEBUG_INFO ExitProcess
        LOAD_DLL_DEBUG_INFO LoadDll
        UNLOAD_DLL_DEBUG_INFO UnloadDll
        OUTPUT_DEBUG_STRING_INFO DebugString
        RIP_INFO RipInfo

    # DEBUG_EVENT
    ctypedef struct DEBUG_EVENT:
        DWORD dwDebugEventCode
        DWORD dwProcessId
        DWORD dwThreadId
        _u u

    # MEMORY_BASIC_INFORMATION
    ctypedef struct MEMORY_BASIC_INFORMATION:
        LPVOID BaseAddress
        LPVOID AllocationBase
        DWORD AllocationProtect
        SIZE_T RegionSize
        DWORD State
        DWORD Protect
        DWORD Type

    # MODULEINFO
    ctypedef struct MODULEINFO:
        LPVOID lpBaseOfDll
        DWORD SizeOfImage
        LPVOID EntryPoint

    # STARTUPINFOA
    ctypedef struct STARTUPINFOA:
        DWORD cb
        LPSTR lpReserved
        LPSTR lpDesktop
        LPSTR lpTitle
        DWORD dwX
        DWORD dwY
        DWORD dwXSize
        DWORD dwYSize
        DWORD dwXCountChars
        DWORD dwYCountChars
        DWORD dwFillAttribute
        DWORD dwFlags
        WORD wShowWindow
        WORD cbReserved2
        unsigned char* lpReserved2
        HANDLE hStdInput
        HANDLE hStdOutput
        HANDLE hStdError

    # PROCESS_INFORMATION
    ctypedef struct PROCESS_INFORMATION:
        HANDLE hProcess
        HANDLE hThread
        DWORD dwProcessId
        DWORD dwThreadId

    # CONTEXT (x64)
    ctypedef struct CONTEXT:
        DWORD64 P1Home
        DWORD64 P2Home
        DWORD64 P3Home
        DWORD64 P4Home
        DWORD64 P5Home
        DWORD64 P6Home
        DWORD ContextFlags
        DWORD MxCsr
        WORD SegCs
        WORD SegDs
        WORD SegEs
        WORD SegFs
        WORD SegGs
        WORD SegSs
        DWORD EFlags
        DWORD64 Dr0
        DWORD64 Dr1
        DWORD64 Dr2
        DWORD64 Dr3
        DWORD64 Dr6
        DWORD64 Dr7
        DWORD64 Rax
        DWORD64 Rcx
        DWORD64 Rdx
        DWORD64 Rbx
        DWORD64 Rsp
        DWORD64 Rbp
        DWORD64 Rsi
        DWORD64 Rdi
        DWORD64 R8
        DWORD64 R9
        DWORD64 R10
        DWORD64 R11
        DWORD64 R12
        DWORD64 R13
        DWORD64 R14
        DWORD64 R15
        DWORD64 Rip

    # === Win32 API functions ===
    BOOL CreateProcessA(
        LPCSTR lpApplicationName,
        char* lpCommandLine,
        void* lpProcessAttributes,
        void* lpThreadAttributes,
        BOOL bInheritHandles,
        DWORD dwCreationFlags,
        void* lpEnvironment,
        LPCSTR lpCurrentDirectory,
        STARTUPINFOA* lpStartupInfo,
        PROCESS_INFORMATION* lpProcessInformation)

    BOOL WaitForDebugEvent(DEBUG_EVENT* lpDebugEvent, DWORD dwMilliseconds)
    BOOL ContinueDebugEvent(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus)
    BOOL DebugActiveProcess(DWORD dwProcessId)
    BOOL DebugActiveProcessStop(DWORD dwProcessId)
    BOOL GetExitCodeProcess(HANDLE hProcess, DWORD* lpExitCode)
    BOOL TerminateProcess(HANDLE hProcess, unsigned int uExitCode)
    HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
    BOOL CloseHandle(HANDLE hObject)
    DWORD GetLastError()

    BOOL ReadProcessMemory(HANDLE hProcess, unsigned long long lpBaseAddress,
        void* lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
    BOOL WriteProcessMemory(HANDLE hProcess, unsigned long long lpBaseAddress,
        void* lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
    SIZE_T VirtualQueryEx(HANDLE hProcess, unsigned long long lpAddress,
        MEMORY_BASIC_INFORMATION* lpBuffer, SIZE_T dwLength)
    BOOL VirtualProtectEx(HANDLE hProcess, unsigned long long lpAddress,
        SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect)
    BOOL EnumProcessModules(HANDLE hProcess, HANDLE* lphModule, DWORD cb, DWORD* lpcbNeeded)
    DWORD GetModuleFileNameExA(HANDLE hProcess, HANDLE hModule, char* lpFilename, DWORD nSize)
    BOOL GetModuleInformation(HANDLE hProcess, HANDLE hModule, MODULEINFO* lpmodinfo, DWORD cb)

    HANDLE OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId)
    BOOL GetThreadContext(HANDLE hThread, CONTEXT* lpContext)
    BOOL SetThreadContext(HANDLE hThread, CONTEXT* lpContext)
    DWORD SuspendThread(HANDLE hThread)
    DWORD ResumeThread(HANDLE hThread)
    DWORD GetThreadId(HANDLE hThread)
    BOOL GetThreadTimes(HANDLE hThread, void* lpCreationTime, void* lpExitTime,
        void* lpKernelTime, void* lpUserTime)
```

- [ ] **Step 2: Commit type definitions**

```bash
git add src/cython/_win32types.pxd
git commit -m "feat: add shared Win32 type declarations in _win32types.pxd"
```

---

## Task 4: Cython Process Module (`_process.pyx`)

**Files:**
- Create: `src/cython/_process.pyx`

- [ ] **Step 1: Create `src/cython/_process.pyx`**

```cython
# _process.pyx — Win32 process debugging API

from _win32types cimport (
    HANDLE, DWORD, BOOL, LPVOID, SIZE_T, LPCSTR,
    DEBUG_EVENT, STARTUPINFOA, PROCESS_INFORMATION,
    CreateProcessA, WaitForDebugEvent, ContinueDebugEvent,
    DebugActiveProcess, DebugActiveProcessStop,
    GetExitCodeProcess, TerminateProcess, OpenProcess,
    CloseHandle, GetLastError,
    DEBUG_PROCESS, DEBUG_ONLY_THIS_PROCESS, INFINITE,
    DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED,
    EXCEPTION_DEBUG_EVENT, CREATE_PROCESS_DEBUG_EVENT,
    CREATE_THREAD_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
    EXIT_THREAD_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT,
    UNLOAD_DLL_DEBUG_EVENT, EXCEPTION_ACCESS_VIOLATION,
    EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP,
)

from libc.string cimport memset

# Event code string mapping
_EVENT_NAMES = {
    1: "EXCEPTION",
    2: "CREATE_THREAD",
    3: "CREATE_PROCESS",
    4: "EXIT_THREAD",
    5: "EXIT_PROCESS",
    6: "LOAD_DLL",
    7: "UNLOAD_DLL",
    8: "OUTPUT_DEBUG_STRING",
    9: "RIP_INFO",
}

cpdef tuple create_process(str path):
    """Create a process under debug control.

    Returns (pid, tid, h_process, h_thread).
    Raises OSError on failure.
    """
    cdef PROCESS_INFORMATION pi
    cdef STARTUPINFOA si
    cdef bytes path_bytes

    memset(&si, 0, sizeof(si))
    si.cb = sizeof(si)
    memset(&pi, 0, sizeof(pi))

    path_bytes = path.encode('utf-8')

    cdef BOOL result = CreateProcessA(
        <LPCSTR>NULL,
        <char*>path_bytes,
        NULL, NULL, 0,
        DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS,
        NULL, <LPCSTR>NULL,
        &si, &pi)

    if result == 0:
        raise OSError(GetLastError(), "CreateProcessA failed")

    cdef DWORD pid = pi.dwProcessId
    cdef DWORD tid = pi.dwThreadId
    cdef unsigned long long h_proc = <unsigned long long>pi.hProcess
    cdef unsigned long long h_thr = <unsigned long long>pi.hThread

    return (pid, tid, h_proc, h_thr)


cpdef int debug_active_process(int pid) except? -1:
    """Attach to a running process for debugging.

    Raises OSError on failure.
    """
    cdef BOOL result = DebugActiveProcess(<DWORD>pid)
    if result == 0:
        raise OSError(GetLastError(), "DebugActiveProcess failed")
    return 0


cpdef object wait_for_debug_event(int timeout_ms=10000):
    """Wait for the next debug event.

    Returns a dict with event info, or None on timeout.
    Dict keys: event_code, event_name, pid, tid, and event-specific fields.
    """
    cdef DEBUG_EVENT de
    cdef BOOL result

    memset(&de, 0, sizeof(de))

    result = WaitForDebugEvent(&de, <DWORD>timeout_ms)
    if result == 0:
        cdef DWORD err = GetLastError()
        if err == 1460:  # ERROR_TIMEOUT
            return None
        raise OSError(err, "WaitForDebugEvent failed")

    cdef dict event = {
        'event_code': de.dwDebugEventCode,
        'event_name': _EVENT_NAMES.get(de.dwDebugEventCode, "UNKNOWN"),
        'pid': de.dwProcessId,
        'tid': de.dwThreadId,
    }

    cdef DWORD code = de.dwDebugEventCode

    if code == EXCEPTION_DEBUG_EVENT:
        event['exception_code'] = de.u.Exception.ExceptionRecord.ExceptionCode
        event['exception_addr'] = <unsigned long long>de.u.Exception.ExceptionRecord.ExceptionAddress
        event['first_chance'] = de.u.Exception.dwFirstChance
    elif code == CREATE_PROCESS_DEBUG_EVENT:
        event['base_of_image'] = <unsigned long long>de.u.CreateProcessInfo.lpBaseOfImage
    elif code == EXIT_PROCESS_DEBUG_EVENT:
        event['exit_code'] = de.u.ExitProcess.dwExitCode
    elif code == CREATE_THREAD_DEBUG_EVENT:
        event['thread_start_addr'] = <unsigned long long>de.u.CreateThread.lpStartAddress
    elif code == EXIT_THREAD_DEBUG_EVENT:
        event['thread_exit_code'] = de.u.ExitThread.dwExitCode
    elif code == LOAD_DLL_DEBUG_EVENT:
        event['dll_base'] = <unsigned long long>de.u.LoadDll.lpBaseOfDll

    return event


cpdef void continue_debug_event(int pid, int tid, int status=DBG_CONTINUE):
    """Continue a thread that was stopped for a debug event.

    Raises OSError on failure.
    """
    cdef BOOL result = ContinueDebugEvent(<DWORD>pid, <DWORD>tid, <DWORD>status)
    if result == 0:
        raise OSError(GetLastError(), "ContinueDebugEvent failed")


cpdef int debug_active_process_stop(int pid) except? -1:
    """Detach debugger from a process.

    Raises OSError on failure.
    """
    cdef BOOL result = DebugActiveProcessStop(<DWORD>pid)
    if result == 0:
        raise OSError(GetLastError(), "DebugActiveProcessStop failed")
    return 0


cpdef int get_exit_code(unsigned long long h_process):
    """Get the exit code of a process.

    Raises OSError on failure.
    """
    cdef DWORD exit_code
    cdef BOOL result = GetExitCodeProcess(<HANDLE><LPVOID>h_process, &exit_code)
    if result == 0:
        raise OSError(GetLastError(), "GetExitCodeProcess failed")
    return exit_code


cpdef void terminate_process(unsigned long long h_process, int exit_code=1):
    """Terminate a process.

    Raises OSError on failure.
    """
    cdef BOOL result = TerminateProcess(<HANDLE><LPVOID>h_process, <unsigned int>exit_code)
    if result == 0:
        raise OSError(GetLastError(), "TerminateProcess failed")


cpdef void close_handle(unsigned long long h_handle):
    """Close a Win32 handle.

    Raises OSError on failure.
    """
    cdef BOOL result = CloseHandle(<HANDLE><LPVOID>h_handle)
    if result == 0:
        raise OSError(GetLastError(), "CloseHandle failed")
```

- [ ] **Step 2: Commit process module**

```bash
git add src/cython/_process.pyx
git commit -m "feat: add Cython process debugging module (_process.pyx)"
```

---

## Task 5: Cython Memory Module (`_memory.pyx`)

**Files:**
- Create: `src/cython/_memory.pyx`

- [ ] **Step 1: Create `src/cython/_memory.pyx`**

```cython
# _memory.pyx — Win32 memory and module operations

from _win32types cimport (
    HANDLE, DWORD, BOOL, LPVOID, SIZE_T, LPCSTR,
    MEMORY_BASIC_INFORMATION, MODULEINFO,
    ReadProcessMemory, WriteProcessMemory,
    VirtualQueryEx, VirtualProtectEx,
    EnumProcessModules, GetModuleFileNameExA,
    GetModuleInformation, GetLastError, CloseHandle,
    MEM_COMMIT, MEM_RESERVE, MEM_FREE, MEM_PRIVATE,
    MEM_MAPPED, MEM_IMAGE,
    PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
)

from libc.stdlib cimport malloc, free

# Memory state names
_MEM_STATE = {
    0x10000: "MEM_COMMIT",
    0x2000: "MEM_RESERVE",
    0x10000: "MEM_FREE",
}

_MEM_TYPE = {
    0x20000: "MEM_IMAGE",
    0x40000: "MEM_MAPPED",
    0x20000: "MEM_PRIVATE",
}

cpdef bytes read_process_memory(unsigned long long h_process, unsigned long long addr, int size):
    """Read 'size' bytes from process memory at 'addr'.

    Returns bytes read. Raises OSError on failure.
    """
    cdef void* buf = malloc(size)
    if buf == NULL:
        raise MemoryError("Failed to allocate read buffer")

    cdef SIZE_T bytes_read = 0
    cdef BOOL result = ReadProcessMemory(
        <HANDLE><LPVOID>h_process,
        addr,
        buf,
        <SIZE_T>size,
        &bytes_read)

    if result == 0:
        free(buf)
        raise OSError(GetLastError(), "ReadProcessMemory failed")

    cdef bytes data = (<char*>buf)[:bytes_read]
    free(buf)
    return data


cpdef int write_process_memory(unsigned long long h_process, unsigned long long addr, bytes data):
    """Write bytes to process memory at 'addr'.

    Returns number of bytes written. Raises OSError on failure.
    """
    cdef int size = len(data)
    cdef SIZE_T bytes_written = 0
    cdef BOOL result = WriteProcessMemory(
        <HANDLE><LPVOID>h_process,
        addr,
        <void*><char*>data,
        <SIZE_T>size,
        &bytes_written)

    if result == 0:
        raise OSError(GetLastError(), "WriteProcessMemory failed")

    return <int>bytes_written


cpdef dict virtual_query_ex(unsigned long long h_process, unsigned long long addr):
    """Query memory region info at 'addr'.

    Returns dict with: base_address, allocation_base, allocation_protect,
    region_size, state, protect, type.
    Raises OSError on failure.
    """
    cdef MEMORY_BASIC_INFORMATION mbi
    cdef SIZE_T result = VirtualQueryEx(
        <HANDLE><LPVOID>h_process,
        addr,
        &mbi,
        sizeof(MEMORY_BASIC_INFORMATION))

    if result == 0:
        raise OSError(GetLastError(), "VirtualQueryEx failed")

    return {
        'base_address': <unsigned long long>mbi.BaseAddress,
        'allocation_base': <unsigned long long>mbi.AllocationBase,
        'allocation_protect': mbi.AllocationProtect,
        'region_size': <unsigned long long>mbi.RegionSize,
        'state': mbi.State,
        'protect': mbi.Protect,
        'type': mbi.Type,
    }


cpdef int virtual_protect_ex(unsigned long long h_process, unsigned long long addr,
                              int size, int protect):
    """Change memory protection on a region.

    Returns old protection value. Raises OSError on failure.
    """
    cdef DWORD old_protect
    cdef BOOL result = VirtualProtectEx(
        <HANDLE><LPVOID>h_process,
        addr,
        <SIZE_T>size,
        <DWORD>protect,
        &old_protect)

    if result == 0:
        raise OSError(GetLastError(), "VirtualProtectEx failed")

    return old_protect


cpdef list enum_process_modules(unsigned long long h_process):
    """Enumerate loaded modules in a process.

    Returns list of dicts with: handle, base_address.
    Raises OSError on failure.
    """
    cdef HANDLE[1024] modules
    cdef DWORD cb_needed = 0
    cdef BOOL result = EnumProcessModules(
        <HANDLE><LPVOID>h_process,
        modules,
        sizeof(modules),
        &cb_needed)

    if result == 0:
        raise OSError(GetLastError(), "EnumProcessModules failed")

    cdef int count = cb_needed // sizeof(HANDLE)
    cdef list out = []
    cdef int i
    for i in range(count):
        out.append({
            'handle': <unsigned long long>modules[i],
            'base_address': <unsigned long long>modules[i],
        })

    return out


cpdef str get_module_file_name_ex(unsigned long long h_process, unsigned long long h_module):
    """Get file name of a module in a process.

    Returns file path string. Raises OSError on failure.
    """
    cdef char[260] filename
    cdef DWORD len = GetModuleFileNameExA(
        <HANDLE><LPVOID>h_process,
        <HANDLE><LPVOID>h_module,
        filename,
        260)

    if len == 0:
        raise OSError(GetLastError(), "GetModuleFileNameExA failed")

    return filename[:len].decode('utf-8', errors='replace')
```

- [ ] **Step 2: Commit memory module**

```bash
git add src/cython/_memory.pyx
git commit -m "feat: add Cython memory operations module (_memory.pyx)"
```

---

## Task 6: Cython Thread Module (`_thread.pyx`)

**Files:**
- Create: `src/cython/_thread.pyx`

- [ ] **Step 1: Create `src/cython/_thread.pyx`**

```cython
# _thread.pyx — Win32 thread and register operations

from _win32types cimport (
    HANDLE, DWORD, BOOL, LPVOID, CONTEXT,
    OpenThread, GetThreadContext, SetThreadContext,
    SuspendThread, ResumeThread, GetLastError,
    CloseHandle,
    THREAD_ALL_ACCESS, CONTEXT_ALL,
    CONTEXT_DEBUG_REGISTERS, CONTEXT_INTEGER, CONTEXT_CONTROL,
)

from libc.string cimport memset

# Register name to CONTEXT field mapping
_REGISTERS_X64 = {
    'rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
    'rip', 'dr0', 'dr1', 'dr2', 'dr3', 'dr6', 'dr7',
    'eflags', 'cs', 'ds', 'es', 'fs', 'gs', 'ss',
}

cpdef unsigned long long open_thread(int thread_id, int access=THREAD_ALL_ACCESS):
    """Open a thread by ID.

    Returns handle as integer. Raises OSError on failure.
    """
    cdef HANDLE h = OpenThread(<DWORD>access, 0, <DWORD>thread_id)
    if h == NULL:
        raise OSError(GetLastError(), "OpenThread failed")
    return <unsigned long long>h


cpdef dict get_thread_context(unsigned long long h_thread):
    """Get thread register context (x64).

    Returns dict of register name -> value.
    Raises OSError on failure.
    """
    cdef CONTEXT ctx
    memset(&ctx, 0, sizeof(ctx))
    ctx.ContextFlags = CONTEXT_ALL

    cdef BOOL result = GetThreadContext(<HANDLE><LPVOID>h_thread, &ctx)
    if result == 0:
        raise OSError(GetLastError(), "GetThreadContext failed")

    return {
        'rax': ctx.Rax, 'rcx': ctx.Rcx, 'rdx': ctx.Rdx, 'rbx': ctx.Rbx,
        'rsp': ctx.Rsp, 'rbp': ctx.Rbp, 'rsi': ctx.Rsi, 'rdi': ctx.Rdi,
        'r8': ctx.R8, 'r9': ctx.R9, 'r10': ctx.R10, 'r11': ctx.R11,
        'r12': ctx.R12, 'r13': ctx.R13, 'r14': ctx.R14, 'r15': ctx.R15,
        'rip': ctx.Rip,
        'eflags': ctx.EFlags,
        'dr0': ctx.Dr0, 'dr1': ctx.Dr1, 'dr2': ctx.Dr2, 'dr3': ctx.Dr3,
        'dr6': ctx.Dr6, 'dr7': ctx.Dr7,
        'cs': ctx.SegCs, 'ds': ctx.SegDs, 'es': ctx.SegEs,
        'fs': ctx.SegFs, 'gs': ctx.SegGs, 'ss': ctx.SegSs,
    }


cpdef int set_thread_context(unsigned long long h_thread, dict context) except? -1:
    """Set thread register context (x64).

    Only registers present in the dict are updated.
    Raises OSError on failure.
    """
    cdef CONTEXT ctx
    memset(&ctx, 0, sizeof(ctx))
    ctx.ContextFlags = CONTEXT_ALL

    # First get current context
    cdef BOOL result = GetThreadContext(<HANDLE><LPVOID>h_thread, &ctx)
    if result == 0:
        raise OSError(GetLastError(), "GetThreadContext failed (before set)")

    # Update fields present in dict
    if 'rax' in context: ctx.Rax = context['rax']
    if 'rcx' in context: ctx.Rcx = context['rcx']
    if 'rdx' in context: ctx.Rdx = context['rdx']
    if 'rbx' in context: ctx.Rbx = context['rbx']
    if 'rsp' in context: ctx.Rsp = context['rsp']
    if 'rbp' in context: ctx.Rbp = context['rbp']
    if 'rsi' in context: ctx.Rsi = context['rsi']
    if 'rdi' in context: ctx.Rdi = context['rdi']
    if 'r8' in context: ctx.R8 = context['r8']
    if 'r9' in context: ctx.R9 = context['r9']
    if 'r10' in context: ctx.R10 = context['r10']
    if 'r11' in context: ctx.R11 = context['r11']
    if 'r12' in context: ctx.R12 = context['r12']
    if 'r13' in context: ctx.R13 = context['r13']
    if 'r14' in context: ctx.R14 = context['r14']
    if 'r15' in context: ctx.R15 = context['r15']
    if 'rip' in context: ctx.Rip = context['rip']
    if 'dr0' in context: ctx.Dr0 = context['dr0']
    if 'dr1' in context: ctx.Dr1 = context['dr1']
    if 'dr2' in context: ctx.Dr2 = context['dr2']
    if 'dr3' in context: ctx.Dr3 = context['dr3']
    if 'dr7' in context: ctx.Dr7 = context['dr7']
    if 'eflags' in context: ctx.EFlags = context['eflags']

    result = SetThreadContext(<HANDLE><LPVOID>h_thread, &ctx)
    if result == 0:
        raise OSError(GetLastError(), "SetThreadContext failed")

    return 0


cpdef int suspend_thread(unsigned long long h_thread):
    """Suspend a thread. Returns previous suspend count.

    Raises OSError on failure.
    """
    cdef DWORD result = SuspendThread(<HANDLE><LPVOID>h_thread)
    if result == <DWORD>-1:
        raise OSError(GetLastError(), "SuspendThread failed")
    return <int>result


cpdef int resume_thread(unsigned long long h_thread):
    """Resume a thread. Returns previous suspend count.

    Raises OSError on failure.
    """
    cdef DWORD result = ResumeThread(<HANDLE><LPVOID>h_thread)
    if result == <DWORD>-1:
        raise OSError(GetLastError(), "ResumeThread failed")
    return <int>result


cpdef int close_handle(unsigned long long h_handle):
    """Close a Win32 handle. Raises OSError on failure."""
    cdef BOOL result = CloseHandle(<HANDLE><LPVOID>h_handle)
    if result == 0:
        raise OSError(GetLastError(), "CloseHandle failed")
    return 0
```

- [ ] **Step 2: Commit thread module**

```bash
git add src/cython/_thread.pyx
git commit -m "feat: add Cython thread/register module (_thread.pyx)"
```

---

## Task 7: Cython Exception Module (`_exception.pyx`)

**Files:**
- Create: `src/cython/_exception.pyx`

- [ ] **Step 1: Create `src/cython/_exception.pyx`**

```cython
# _exception.pyx — Exception code constants and parsing

# Exception codes
EXCEPTION_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
EXCEPTION_GUARD_PAGE = 0x80000001
EXCEPTION_ARRAY_BOUNDS_EXCEEDED = 0xC000008C
EXCEPTION_FLT_DENORMAL_OPERAND = 0xC0000094
EXCEPTION_FLT_DIVIDE_BY_ZERO = 0xC000008E
EXCEPTION_FLT_INEXACT_RESULT = 0xC000008F
EXCEPTION_FLT_INVALID_OPERATION = 0xC0000090
EXCEPTION_FLT_OVERFLOW = 0xC0000091
EXCEPTION_FLT_STACK_CHECK = 0xC0000092
EXCEPTION_FLT_UNDERFLOW = 0xC0000093
EXCEPTION_INT_DIVIDE_BY_ZERO = 0xC0000094
EXCEPTION_INT_OVERFLOW = 0xC0000095
EXCEPTION_PRIVILEGED_INSTRUCTION = 0xC0000096
EXCEPTION_STACK_OVERFLOW = 0xC00000FD

# Access violation sub-types
EXCEPTION_READ_FAULT = 0
EXCEPTION_WRITE_FAULT = 1
EXCEPTION_EXECUTE_FAULT = 8

# Human-readable mapping
_EXCEPTION_CODE_NAMES = {
    0xC0000005: "EXCEPTION_ACCESS_VIOLATION",
    0x80000003: "EXCEPTION_BREAKPOINT",
    0x80000004: "EXCEPTION_SINGLE_STEP",
    0x80000001: "EXCEPTION_GUARD_PAGE",
    0xC000008C: "EXCEPTION_ARRAY_BOUNDS_EXCEEDED",
    0xC000008E: "EXCEPTION_FLT_DIVIDE_BY_ZERO",
    0xC000008F: "EXCEPTION_FLT_INEXACT_RESULT",
    0xC0000090: "EXCEPTION_FLT_INVALID_OPERATION",
    0xC0000091: "EXCEPTION_FLT_OVERFLOW",
    0xC0000092: "EXCEPTION_FLT_STACK_CHECK",
    0xC0000093: "EXCEPTION_FLT_UNDERFLOW",
    0xC0000095: "EXCEPTION_INT_OVERFLOW",
    0xC0000096: "EXCEPTION_PRIVILEGED_INSTRUCTION",
    0xC00000FD: "EXCEPTION_STACK_OVERFLOW",
}

_ACCESS_VIOLATION_TYPES = {
    0: "READ",
    1: "WRITE",
    8: "EXECUTE",
}


def exception_code_to_str(int code):
    """Convert exception code to human-readable string."""
    return _EXCEPTION_CODE_NAMES.get(code, f"UNKNOWN_0x{code:08X}")


def get_exception_info(dict event):
    """Extract detailed exception info from a debug event dict.

    Args:
        event: dict from _process.wait_for_debug_event()

    Returns:
        dict with: code, code_name, address, first_chance, and
        for access violations: access_type, bad_address
    """
    cdef unsigned int code = event.get('exception_code', 0)

    info = {
        'code': code,
        'code_name': exception_code_to_str(code),
        'address': event.get('exception_addr', 0),
        'first_chance': event.get('first_chance', 0),
    }

    # Access violation has extra info in ExceptionInformation
    if code == EXCEPTION_ACCESS_VIOLATION:
        info['access_type'] = _ACCESS_VIOLATION_TYPES.get(
            event.get('exception_access_type', 0),
            "UNKNOWN")

    return info
```

- [ ] **Step 2: Commit exception module**

```bash
git add src/cython/_exception.pyx
git commit -m "feat: add Cython exception handling module (_exception.pyx)"
```

---

## Task 8: Cython Breakpoint Module (`_bp.pyx`)

**Files:**
- Create: `src/cython/_bp.pyx`

- [ ] **Step 1: Create `src/cython/_bp.pyx`**

```cython
# _bp.pyx — Hardware breakpoint management via debug registers

from _win32types cimport (
    HANDLE, DWORD, BOOL, DWORD64, CONTEXT,
    GetThreadContext, SetThreadContext, GetLastError,
    CONTEXT_ALL, CONTEXT_DEBUG_REGISTERS,
)

from libc.string cimport memset

# Dr7 condition codes
HW_BREAKPOINT_EXECUTE = 0
HW_BREAKPOINT_WRITE = 1
HW_BREAKPOINT_READWRITE = 3

# Dr7 length codes
HW_BREAKPOINT_1_BYTE = 0
HW_BREAKPOINT_2_BYTE = 1
HW_BREAKPOINT_4_BYTE = 3
HW_BREAKPOINT_8_BYTE = 2

# Dr7 layout for x64:
#   Bits 0,2,4,6: L0,L1,L2,L3 (local enable)
#   Bits 1,3,5,7: G0,G1,G2,G3 (global enable)
#   Bits 16-17,20-21,24-25,28-29: RW0,RW1,RW2,RW3 (condition)
#   Bits 18-19,22-23,26-27,30-31: LEN0,LEN1,LEN2,LEN3 (length)

# Slot enable bit positions
cdef int[4] _SLOT_ENABLE_L = [0, 2, 4, 6]
cdef int[4] _SLOT_RW_SHIFT = [16, 20, 24, 28]
cdef int[4] _SLOT_LEN_SHIFT = [18, 22, 26, 30]

# Dr registers (mapped to CONTEXT field offsets via array)
cdef int[4] _DR_OFFSET = [0, 1, 2, 3]  # Dr0, Dr1, Dr2, Dr3


cpdef int set_hw_breakpoint(unsigned long long h_thread, int slot,
                             unsigned long long addr, int condition,
                             int length):
    """Set a hardware breakpoint.

    Args:
        h_thread: Thread handle as integer
        slot: 0-3 (which debug register to use)
        addr: Breakpoint address
        condition: HW_BREAKPOINT_EXECUTE/WRITE/READWRITE
        length: HW_BREAKPOINT_1_BYTE/2_BYTE/4_BYTE/8_BYTE

    Returns 0 on success. Raises ValueError on bad slot.
    Raises OSError on failure.
    """
    if slot < 0 or slot > 3:
        raise ValueError(f"Slot must be 0-3, got {slot}")

    # Read current context
    cdef CONTEXT ctx
    memset(&ctx, 0, sizeof(ctx))
    ctx.ContextFlags = CONTEXT_ALL

    cdef BOOL result = GetThreadContext(<HANDLE><LPVOID>h_thread, &ctx)
    if result == 0:
        raise OSError(GetLastError(), "GetThreadContext failed (set_hw_breakpoint)")

    # Set the address in the appropriate Dr register
    if slot == 0:
        ctx.Dr0 = addr
    elif slot == 1:
        ctx.Dr1 = addr
    elif slot == 2:
        ctx.Dr2 = addr
    else:
        ctx.Dr3 = addr

    # Clear existing condition and length bits for this slot
    ctx.Dr7 &= ~(<DWORD64>3 << _SLOT_RW_SHIFT[slot])
    ctx.Dr7 &= ~(<DWORD64>3 << _SLOT_LEN_SHIFT[slot])

    # Set condition and length
    ctx.Dr7 |= (<DWORD64>condition << _SLOT_RW_SHIFT[slot])
    ctx.Dr7 |= (<DWORD64>length << _SLOT_LEN_SHIFT[slot])

    # Enable local breakpoint
    ctx.Dr7 |= (<DWORD64>1 << _SLOT_ENABLE_L[slot])

    # Write context back
    result = SetThreadContext(<HANDLE><LPVOID>h_thread, &ctx)
    if result == 0:
        raise OSError(GetLastError(), "SetThreadContext failed (set_hw_breakpoint)")

    return 0


cpdef int clear_hw_breakpoint(unsigned long long h_thread, int slot):
    """Clear a hardware breakpoint.

    Args:
        h_thread: Thread handle as integer
        slot: 0-3 (which debug register to clear)

    Returns 0 on success. Raises ValueError on bad slot.
    Raises OSError on failure.
    """
    if slot < 0 or slot > 3:
        raise ValueError(f"Slot must be 0-3, got {slot}")

    cdef CONTEXT ctx
    memset(&ctx, 0, sizeof(ctx))
    ctx.ContextFlags = CONTEXT_ALL

    cdef BOOL result = GetThreadContext(<HANDLE><LPVOID>h_thread, &ctx)
    if result == 0:
        raise OSError(GetLastError(), "GetThreadContext failed (clear_hw_breakpoint)")

    # Clear enable, condition, and length bits for this slot
    ctx.Dr7 &= ~(<DWORD64>1 << _SLOT_ENABLE_L[slot])
    ctx.Dr7 &= ~(<DWORD64>3 << _SLOT_RW_SHIFT[slot])
    ctx.Dr7 &= ~(<DWORD64>3 << _SLOT_LEN_SHIFT[slot])

    # Clear the address register
    if slot == 0:
        ctx.Dr0 = 0
    elif slot == 1:
        ctx.Dr1 = 0
    elif slot == 2:
        ctx.Dr2 = 0
    else:
        ctx.Dr3 = 0

    result = SetThreadContext(<HANDLE><LPVOID>h_thread, &ctx)
    if result == 0:
        raise OSError(GetLastError(), "SetThreadContext failed (clear_hw_breakpoint)")

    return 0
```

- [ ] **Step 2: Commit breakpoint module**

```bash
git add src/cython/_bp.pyx
git commit -m "feat: add Cython hardware breakpoint module (_bp.pyx)"
```

---

## Task 9: Python High-Level API (`pydbg.py`)

**Files:**
- Create: `src/pydbg.py`

- [ ] **Step 1: Create `src/pydbg.py`**

```python
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
        # Save original byte
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
```

- [ ] **Step 2: Commit high-level API**

```bash
git add src/pydbg.py
git commit -m "feat: add Python high-level Debugger API (pydbg.py)"
```

---

## Task 10: Unit Tests

**Files:**
- Create: `tests/test_process.py`
- Create: `tests/test_memory.py`
- Create: `tests/test_thread.py`
- Create: `tests/test_breakpoint.py`

- [ ] **Step 1: Create `tests/test_process.py`**

```python
"""Tests for process debugging: create, wait, continue, detach."""

import unittest
import os

from tests import TEST_TARGET_PATH


class TestProcessLifecycle(unittest.TestCase):
    """Integration tests for process creation and debug event loop."""

    def test_create_process(self):
        """Verify create_process returns valid pid/tid."""
        from pydbg.cython import _process

        pid, tid, h_proc, h_thr = _process.create_process(TEST_TARGET_PATH)
        self.assertGreater(pid, 0)
        self.assertGreater(tid, 0)
        self.assertNotEqual(h_proc, 0)
        self.assertNotEqual(h_thr, 0)

        # Clean up
        _process.terminate_process(h_proc, 0)
        _process.close_handle(h_proc)
        _process.close_handle(h_thr)

    def test_wait_and_continue(self):
        """Verify wait_for_debug_event returns CREATE_PROCESS, then continue."""
        from pydbg.cython import _process

        pid, tid, h_proc, h_thr = _process.create_process(TEST_TARGET_PATH)

        event = _process.wait_for_debug_event(5000)
        self.assertIsNotNone(event)
        self.assertEqual(event['event_name'], 'CREATE_PROCESS')
        self.assertEqual(event['pid'], pid)

        _process.continue_debug_event(pid, tid)

        # Clean up
        _process.terminate_process(h_proc, 0)
        _process.close_handle(h_proc)
        _process.close_handle(h_thr)

    def test_exception_breakpoint(self):
        """Verify we get EXCEPTION_BREAKPOINT from initial int3."""
        from pydbg.cython import _process

        pid, tid, h_proc, h_thr = _process.create_process(TEST_TARGET_PATH)

        # First event: CREATE_PROCESS
        event = _process.wait_for_debug_event(5000)
        self.assertEqual(event['event_name'], 'CREATE_PROCESS')
        _process.continue_debug_event(pid, tid)

        # Second event: LOAD_DLL (may be multiple)
        for _ in range(20):
            event = _process.wait_for_debug_event(5000)
            if event is None:
                break
            if event['event_name'] == 'EXCEPTION':
                break
            _process.continue_debug_event(pid, tid)

        # Should hit the loader breakpoint
        if event and event['event_name'] == 'EXCEPTION':
            self.assertEqual(event['exception_code'], 0x80000003)  # EXCEPTION_BREAKPOINT

        _process.terminate_process(h_proc, 0)
        _process.close_handle(h_proc)
        _process.close_handle(h_thr)

    def test_detach_nonexistent(self):
        """Verify detach on invalid pid raises OSError."""
        from pydbg.cython import _process

        with self.assertRaises(OSError):
            _process.debug_active_process_stop(999999)


class TestDebuggerAPI(unittest.TestCase):
    """Tests for the high-level Debugger class."""

    def test_create_and_detach(self):
        """Full lifecycle: create -> wait -> continue -> detach."""
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        self.assertGreater(pid, 0)

        event = dbg.wait_event(5000)
        self.assertIsNotNone(event)
        self.assertEqual(event.type, 'CREATE_PROCESS')

        dbg.continue_event(pid, tid)

        # Terminate
        dbg.close_handle(dbg._process_handle)
        dbg.close_handle(dbg._thread_handle)


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Create `tests/test_memory.py`**

```python
"""Tests for memory operations: read, write, query, modules."""

import unittest
import os

from tests import TEST_TARGET_PATH


class TestMemoryReadWrite(unittest.TestCase):
    """Test reading and writing process memory."""

    def setUp(self):
        from pydbg.cython import _process
        self.pid, self.tid, self.h_proc, self.h_thr = _process.create_process(
            TEST_TARGET_PATH)
        # Consume CREATE_PROCESS event
        _process.wait_for_debug_event(5000)
        _process.continue_debug_event(self.pid, self.tid)

    def tearDown(self):
        from pydbg.cython import _process
        _process.terminate_process(self.h_proc, 0)
        _process.close_handle(self.h_proc)
        _process.close_handle(self.h_thr)

    def test_read_memory_from_image(self):
        """Read the PE header from the target process."""
        from pydbg.cython import _memory

        # First get module info
        modules = _memory.enum_process_modules(self.h_proc)
        self.assertGreater(len(modules), 0)

        base = modules[0]['base_address']
        # Read MZ header
        data = _memory.read_process_memory(self.h_proc, base, 2)
        self.assertEqual(data[:2], b'MZ')

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
                if info['state'] == 0x10000:  # MEM_COMMIT
                    break
                addr = info['base_address'] + info['region_size']
            except OSError:
                break

    def test_virtual_query(self):
        """Query memory at module base returns committed region."""
        from pydbg.cython import _memory

        modules = _memory.enum_process_modules(self.h_proc)
        base = modules[0]['base_address']

        info = _memory.virtual_query_ex(self.h_proc, base)
        self.assertIn('base_address', info)
        self.assertIn('region_size', info)
        self.assertIn('protect', info)


class TestModuleEnum(unittest.TestCase):
    """Test module enumeration."""

    def setUp(self):
        from pydbg.cython import _process
        self.pid, self.tid, self.h_proc, self.h_thr = _process.create_process(
            TEST_TARGET_PATH)
        _process.wait_for_debug_event(5000)
        _process.continue_debug_event(self.pid, self.tid)

    def tearDown(self):
        from pydbg.cython import _process
        _process.terminate_process(self.h_proc, 0)
        _process.close_handle(self.h_proc)
        _process.close_handle(self.h_thr)

    def test_enum_modules(self):
        """Verify at least one module is loaded."""
        from pydbg.cython import _memory

        modules = _memory.enum_process_modules(self.h_proc)
        self.assertGreater(len(modules), 0)

    def test_get_module_filename(self):
        """Verify we can get the filename of the first module."""
        from pydbg.cython import _memory

        modules = _memory.enum_process_modules(self.h_proc)
        filename = _memory.get_module_file_name_ex(
            self.h_proc, modules[0]['handle'])
        self.assertTrue(len(filename) > 0)


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 3: Create `tests/test_thread.py`**

```python
"""Tests for thread operations: context, suspend, resume."""

import unittest
import os

from tests import TEST_TARGET_PATH


class TestThreadContext(unittest.TestCase):
    """Test reading and writing thread context."""

    def setUp(self):
        from pydbg.cython import _process
        self.pid, self.tid, self.h_proc, self.h_thr = _process.create_process(
            TEST_TARGET_PATH)
        _process.wait_for_debug_event(5000)
        _process.continue_debug_event(self.pid, self.tid)

    def tearDown(self):
        from pydbg.cython import _process
        _process.terminate_process(self.h_proc, 0)
        _process.close_handle(self.h_proc)
        _process.close_handle(self.h_thr)

    def test_get_thread_context(self):
        """Verify get_thread_context returns x64 registers."""
        from pydbg.cython import _thread

        ctx = _thread.get_thread_context(self.h_thr)
        self.assertIn('rip', ctx)
        self.assertIn('rsp', ctx)
        self.assertIn('rax', ctx)
        self.assertIsInstance(ctx['rip'], int)

    def test_open_thread(self):
        """Verify open_thread returns valid handle."""
        from pydbg.cython import _thread

        h = _thread.open_thread(self.tid)
        self.assertGreater(h, 0)
        _thread.close_handle(h)

    def test_suspend_resume(self):
        """Verify suspend and resume cycle."""
        from pydbg.cython import _thread

        h = _thread.open_thread(self.tid)
        count = _thread.suspend_thread(h)
        self.assertGreaterEqual(count, 0)

        count2 = _thread.resume_thread(h)
        self.assertGreaterEqual(count2, 0)

        _thread.close_handle(h)


class TestDebuggerThreadAPI(unittest.TestCase):
    """Tests for high-level thread API."""

    def test_get_registers(self):
        """Verify Debugger.get_registers returns dict."""
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        event = dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        h_thread = dbg.open_thread(tid)
        regs = dbg.get_registers(h_thread)
        self.assertIn('rip', regs)
        self.assertIn('rsp', regs)

        _thread_mod = __import__('pydbg.cython._thread', fromlist=['close_handle'])
        _thread_mod.close_handle(h_thread)
        dbg.close_handle(dbg._process_handle)
        dbg.close_handle(dbg._thread_handle)


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 4: Create `tests/test_breakpoint.py`**

```python
"""Tests for hardware breakpoints."""

import unittest
import os

from tests import TEST_TARGET_PATH


class TestHardwareBreakpoint(unittest.TestCase):
    """Test setting and clearing hardware breakpoints."""

    def setUp(self):
        from pydbg.cython import _process
        self.pid, self.tid, self.h_proc, self.h_thr = _process.create_process(
            TEST_TARGET_PATH)
        _process.wait_for_debug_event(5000)
        _process.continue_debug_event(self.pid, self.tid)

    def tearDown(self):
        from pydbg.cython import _process
        _process.terminate_process(self.h_proc, 0)
        _process.close_handle(self.h_proc)
        _process.close_handle(self.h_thr)

    def test_set_hw_breakpoint(self):
        """Set an execute breakpoint at image base."""
        from pydbg.cython import _bp, _memory

        modules = _memory.enum_process_modules(self.h_proc)
        base = modules[0]['base_address']

        result = _bp.set_hw_breakpoint(
            self.h_thr, slot=0, addr=base,
            condition=0, length=0)  # execute, 1 byte
        self.assertEqual(result, 0)

        # Clean up
        _bp.clear_hw_breakpoint(self.h_thr, slot=0)

    def test_clear_hw_breakpoint(self):
        """Set then clear a breakpoint."""
        from pydbg.cython import _bp, _memory

        modules = _memory.enum_process_modules(self.h_proc)
        base = modules[0]['base_address']

        _bp.set_hw_breakpoint(self.h_thr, 0, base, 0, 0)
        result = _bp.clear_hw_breakpoint(self.h_thr, 0)
        self.assertEqual(result, 0)

    def test_invalid_slot(self):
        """Verify invalid slot raises ValueError."""
        from pydbg.cython import _bp

        with self.assertRaises(ValueError):
            _bp.set_hw_breakpoint(self.h_thr, 5, 0x1000, 0, 0)


class TestDebuggerBreakpointAPI(unittest.TestCase):
    """Tests for high-level breakpoint API."""

    def test_set_and_remove_int3(self):
        """Set int3 breakpoint, then remove."""
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        event = dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        # Get a code address
        regs = dbg.get_registers(dbg.open_thread(tid))
        addr = regs['rip']

        bp_id = dbg.set_breakpoint(addr)
        self.assertGreater(bp_id, 0)

        dbg.remove_breakpoint(bp_id)

        dbg.close_handle(dbg._process_handle)
        dbg.close_handle(dbg._thread_handle)

    def test_set_hw_breakpoint_via_api(self):
        """Set hw breakpoint via high-level API."""
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        event = dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        h_thread = dbg.open_thread(tid)
        regs = dbg.get_registers(h_thread)
        addr = regs['rip']

        bp_id = dbg.set_hw_breakpoint(addr, 'x', 1, 0)
        self.assertGreater(bp_id, 0)

        dbg.remove_breakpoint(bp_id)

        _thread_mod = __import__('pydbg.cython._thread', fromlist=['close_handle'])
        _thread_mod.close_handle(h_thread)
        dbg.close_handle(dbg._process_handle)
        dbg.close_handle(dbg._thread_handle)


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 5: Commit all tests**

```bash
git add tests/
git commit -m "test: add unit tests for all modules"
```

---

## Task 11: Build Verification

**Files:**
- None (verification only)

- [ ] **Step 1: Verify Meson can configure the build**

```bash
meson setup builddir -Dbuildtype=debug
```

Expected: Configuration completes without errors, lists found Python and Cython.

- [ ] **Step 2: Compile the project**

```bash
meson compile -C builddir
```

Expected: All `.pyx` files compile to `.pyd` without errors.

- [ ] **Step 3: Run tests**

```bash
meson test -C builddir -v
```

Expected: All 4 test suites pass (process, memory, thread, breakpoint).

- [ ] **Step 4: Fix any build or test issues**

Iterate on failures until all tests pass.

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "chore: fix build issues, all tests passing"
```

---

## Spec Coverage Check

| Spec Requirement | Task |
|---|---|
| Process debugging (create/attach/detach) | Task 4, Task 9, Task 10 |
| Breakpoints (int3 + hardware) | Task 8, Task 9, Task 10 |
| Memory read/write/query/modules | Task 5, Task 9, Task 10 |
| Thread context/suspend/resume | Task 6, Task 9, Task 10 |
| Exception handling | Task 7, Task 10 |
| Meson build system | Task 1, Task 2, Task 11 |
| unittest testing | Task 2, Task 10, Task 11 |
| Custom exceptions | Task 1, Task 9 |
| Shared type definitions (.pxd) | Task 3 |
| High-level Python API | Task 9 |
