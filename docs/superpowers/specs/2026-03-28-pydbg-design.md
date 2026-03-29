# pydbg — Windows 二进制调试器 Python 模块设计

## 概述

pydbg 是一个使用 Cython 封装 Win32 调试 API（dbghelp.dll 等）的 Python 模块，提供模块化的二进制调试器功能。构建使用 Meson + Ninja + Clang，单元测试使用 unittest。

## 目标

- 封装 Win32 调试 API 为可用的 Python 模块
- 支持进程调试（创建/附加）、断点（int3 + 硬件）、单步执行
- 支持内存读写、模块枚举、PE 信息获取
- 支持线程上下文（寄存器）读写、调用栈获取
- 模块化设计，每个 Win32 功能域独立封装

## 非目标

- 跨平台支持（仅 Windows）
- GUI 界面
- 内核调试
- 符号解析（PDB 解析）— 后期再考虑

## 目录结构

```
pydbg/
├── meson.build                    # 根构建文件
├── meson.options                  # 构建选项
├── src/
│   ├── meson.build                # src 子构建
│   ├── __init__.py                # pydbg 包入口
│   ├── pydbg.py                   # 高层调试器 API（Python）
│   ├── exceptions.py              # 自定义异常类
│   └── cython/
│       ├── meson.build            # Cython 编译配置
│       ├── _win32types.pxd        # 公共类型定义
│       ├── _process.pyx           # 进程调试 API 封装
│       ├── _memory.pyx            # 内存操作 API 封装
│       ├── _thread.pyx            # 线程/寄存器 API 封装
│       ├── _exception.pyx         # 异常处理辅助
│       └── _bp.pyx                # 硬件断点管理
├── tests/
│   ├── meson.build
│   ├── target/
│   │   └── simple_target.c        # 测试用目标程序
│   ├── test_process.py
│   ├── test_memory.py
│   ├── test_thread.py
│   └── test_breakpoint.py
└── tools/
    └── pydbg_cli.py               # 简单命令行调试工具（可选）
```

## 设计原则

1. **细粒度 Cython 模块** — 每个 Win32 功能域一个 `.pyx`，粒度到单个 API 函数
2. **Cython 模块以 `_` 前缀命名** — 不直接暴露给用户
3. **Python 层整合** — `pydbg.py` 提供统一高层 API
4. **类型共享** — `.pxd` 定义公共类型，各 `.pyx` 通过 `cimport` 复用
5. **错误处理分层** — Cython 层捕获 `GetLastError()` raise `OSError`，Python 层转换为自定义异常

## Cython 封装层

### `_win32types.pxd` — 公共类型

定义所有模块共享的 C 类型和 Win32 结构体：

```cython
from libc.stdint cimport uint32_t, uint64_t, uintptr_t

cdef extern from "windows.h":
    ctypedef void* HANDLE
    ctypedef unsigned long DWORD
    ctypedef void* LPVOID
    ctypedef unsigned long long SIZE_T
    ctypedef int BOOL
    ctypedef unsigned long long ULONG_PTR

    # DEBUG_EVENT
    ctypedef struct EXCEPTION_RECORD:
        DWORD ExceptionCode
        DWORD ExceptionFlags
        EXCEPTION_RECORD* ExceptionRecord
        LPVOID ExceptionAddress
        DWORD NumberParameters
        ULONG_PTR ExceptionInformation[15]

    ctypedef struct DEBUG_EVENT:
        DWORD dwDebugEventCode
        DWORD dwProcessId
        DWORD dwThreadId
        # union omitted — accessed in .pyx

    ctypedef struct CONTEXT:
        DWORD64 Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi
        DWORD64 R8, R9, R10, R11, R12, R13, R14, R15
        DWORD64 Rip
        # ... 其他字段

    ctypedef struct MEMORY_BASIC_INFORMATION:
        LPVOID BaseAddress
        LPVOID AllocationBase
        DWORD AllocationProtect
        SIZE_T RegionSize
        DWORD State
        DWORD Protect
        DWORD Type
```

### `_process.pyx` — 进程调试核心

```cython
cdef extern from "windows.h":
    # CreateProcess
    BOOL CreateProcessA(
        char* lpApplicationName,
        char* lpCommandLine,
        void* lpProcessAttributes,
        void* lpThreadAttributes,
        BOOL bInheritHandles,
        DWORD dwCreationFlags,
        void* lpEnvironment,
        char* lpCurrentDirectory,
        void* lpStartupInfo,
        void* lpProcessInformation)

    # Debug event
    BOOL WaitForDebugEvent(DEBUG_EVENT* lpDebugEvent, DWORD dwMilliseconds)
    BOOL ContinueDebugEvent(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus)
    BOOL DebugActiveProcess(DWORD dwProcessId)
    BOOL DebugActiveProcessStop(DWORD dwProcessId)
    BOOL GetExitCodeProcess(HANDLE hProcess, DWORD* lpExitCode)

    # Constants
    DWORD DEBUG_PROCESS
    DWORD DEBUG_ONLY_THIS_PROCESS
    DWORD INFINITE
    DWORD DBG_CONTINUE
    DWORD DBG_EXCEPTION_NOT_HANDLED
    DWORD EXCEPTION_DEBUG_EVENT
    DWORD CREATE_PROCESS_DEBUG_EVENT
    DWORD EXIT_PROCESS_DEBUG_EVENT

cpdef tuple create_process(str path)
cpdef int debug_active_process(int pid) except? -1
cpdef object wait_for_debug_event(int timeout_ms=*)
cpdef void continue_debug_event(int pid, int tid, int status)
cpdef void debug_active_process_stop(int pid)
cpdef int get_exit_code(int h_process)
```

### `_memory.pyx` — 内存操作

```cython
cpdef bytes read_process_memory(int h_process, unsigned long long addr, int size)
cpdef int write_process_memory(int h_process, unsigned long long addr, bytes data)
cpdef dict virtual_query_ex(int h_process, unsigned long long addr)
cpdef int virtual_protect_ex(int h_process, unsigned long long addr, int size, int protect)
cpdef list enum_process_modules(int h_process)
cpdef str get_module_file_name_ex(int h_process, int h_module)
```

### `_thread.pyx` — 线程/寄存器

```cython
cpdef int open_thread(int thread_id, int access=*)
cpdef dict get_thread_context(int h_thread)
cpdef int set_thread_context(int h_thread, dict context) except? -1
cpdef int suspend_thread(int h_thread)
cpdef int resume_thread(int h_thread)
```

### `_exception.pyx` — 异常处理辅助

```cython
# 常量
EXCEPTION_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
EXCEPTION_GUARD_PAGE = 0x80000001

# 读写类型
EXCEPTION_READ_FAULT = 0
EXCEPTION_WRITE_FAULT = 1
EXCEPTION_EXECUTE_FAULT = 8

cpdef dict parse_exception_record(EXCEPTION_RECORD* record)
cpdef str exception_code_to_str(int code)
```

### `_bp.pyx` — 硬件断点

```cython
# Dr7 条件和长度编码
HW_BREAKPOINT_EXECUTE = 0
HW_BREAKPOINT_WRITE = 1
HW_BREAKPOINT_READWRITE = 3
HW_BREAKPOINT_1_BYTE = 0
HW_BREAKPOINT_2_BYTE = 1
HW_BREAKPOINT_4_BYTE = 3
HW_BREAKPOINT_8_BYTE = 2

cpdef int set_hw_breakpoint(int h_thread, int slot, unsigned long long addr, int condition, int length)
cpdef int clear_hw_breakpoint(int h_thread, int slot)
```

## Python 高层 API (`pydbg.py`)

过程式 API，用户操作 `Debugger` 实例：

```python
from pydbg import Debugger

dbg = Debugger()

# 创建并调试进程
pid, tid = dbg.create_process("target.exe")

# 附加到运行中进程
dbg.attach(pid)

# 等待调试事件
event = dbg.wait_event()

# 读写内存
data = dbg.read_memory(addr, 256)
dbg.write_memory(addr, b"\x90" * 16)

# 寄存器
regs = dbg.get_registers(tid)
dbg.set_register(tid, "Rip", new_rip)

# 断点
bp_id = dbg.set_breakpoint(addr)
hw_id = dbg.set_hw_breakpoint(addr, "rw")
dbg.remove_breakpoint(bp_id)

# 单步
dbg.step(tid)

# 分离
dbg.detach(pid)
```

### `DebugEvent` 类

```python
class DebugEvent:
    type: str          # "exception", "create_process", "exit_process", ...
    pid: int
    tid: int
    exception_code: int | None
    exception_addr: int | None
    raw: dict          # 原始事件数据
```

### `exceptions.py` — 自定义异常

```python
class PydbgError(Exception): ...
class ProcessError(PydbgError): ...
class MemoryError(PydbgError): ...
class ThreadError(PydbgError): ...
class BreakpointError(PydbgError): ...
class TimeoutError(PydbgError): ...
```

## 构建系统 (Meson + Ninja + Clang)

### `meson.build`（根目录）

```meson
project('pydbg', 'c',
  version: '0.1.0',
  default_options: ['c_std=c11', 'buildtype=debug'])

python = find_program('python3', required: true)

subdir('src')
subdir('tests')
```

### `meson.options`

```
option('python_path', type: 'string', value: '', description: 'Python interpreter path')
option('buildtype', type: 'combo', choices: ['debug', 'release'], value: 'debug')
```

### `src/cython/meson.build`

使用 Cython 将 `.pyx` 编译为 `.c`，再用 Meson 编译为 `.pyd`。链接 `dbghelp.lib`、`kernel32.lib`、`advapi32.lib`。

### 构建命令

```bash
meson setup builddir -Dbuildtype=debug
meson compile -C builddir
meson test -C builddir
```

## 测试策略

### 测试分层

1. **单元测试** — 测试 Cython 封装的单个 Win32 API 调用
2. **集成测试** — 测试完整调试流程（创建进程 → 等事件 → 断点 → 单步 → 继续）

### 测试 target

`tests/target/simple_target.c` — 一个简单的 C 程序，供调试器附加/调试：

```c
#include <stdio.h>
int main() {
    int x = 42;
    printf("Hello from target, x=%d\n", x);
    return 0;
}
```

Meson 构建时自动编译为可执行文件。

### 测试文件

- `test_process.py` — 进程创建/附加/分离/事件等待
- `test_memory.py` — 内存读写/查询/模块枚举
- `test_thread.py` — 线程上下文/挂起/恢复
- `test_breakpoint.py` — 软件断点/硬件断点/单步

### 运行测试

```bash
meson test -C builddir
# 或
python -m unittest discover tests/
```
