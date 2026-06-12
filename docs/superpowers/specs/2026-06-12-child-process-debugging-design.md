# Child Process Debugging Design

**Date:** 2026-06-12
**Status:** Approved
**Scope:** pydbg 子进程调试支持

## Problem

pydbg 当前使用 `DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS` 创建调试进程。
`DEBUG_ONLY_THIS_PROCESS` 覆盖了 `DEBUG_PROCESS`，导致子进程的调试事件被忽略。
用户无法调试目标进程创建的子进程。

## Requirements

1. **opt-in 开关** — `set_debug_children(True)` 启用，默认关闭，零破坏性变更
2. **自动跟踪** — 子进程的 CREATE_PROCESS/EXIT_PROCESS 事件自动注册/注销到 session
3. **透明访问** — 现有 Debugger 方法（read_memory, set_breakpoint 等）加可选 `pid` 参数
4. **pid 重载** — detach/terminate 通过 pid 参数操作指定子进程

## Architecture

### Data Structures

#### ChildProcessInfo (新增)

```python
@dataclass
class ChildProcessInfo:
    pid: int
    tid: int                    # 主线程 ID
    process_handle: int         # OpenProcess 返回的句柄
    thread_handle: int          # 主线程句柄
    base_of_image: int = 0      # 加载基址
    exit_code: int | None = None  # 退出后填入
```

#### DebugSession (扩展)

```python
@dataclass
class DebugSession:
    # 现有字段不变
    process_handle: int | None = None
    thread_handle: int | None = None
    pid: int | None = None
    tid: int | None = None
    host_arch: int = struct.calcsize("P") * 8
    target_arch: int = struct.calcsize("P") * 8
    bp_counter: int = 0
    breakpoints: dict = field(default_factory=dict)
    pending_single_step: dict = field(default_factory=dict)

    # 新增字段
    debug_children: bool = False
    child_processes: dict[int, ChildProcessInfo] = field(default_factory=dict)
```

#### DebugEvent (扩展)

```python
class DebugEvent:
    # 现有字段不变
    is_child: bool = False      # True 表示事件来自子进程
```

### Cython Layer

#### `_process.pxi` — create_process

```python
cpdef tuple create_process(str path, bint debug_children=False):
    cdef DWORD flags = DEBUG_PROCESS
    if not debug_children:
        flags |= DEBUG_ONLY_THIS_PROCESS
    # ... CreateProcessA(..., flags, ...)
```

默认 `debug_children=False`，行为完全不变。

#### `_process.pxi` — wait_for_debug_event

`CREATE_PROCESS_DEBUG_EVENT` 返回额外字段：

```python
elif code == CREATE_PROCESS_DEBUG_EVENT:
    event['base_of_image'] = <unsigned long long>de.u.CreateProcessInfo.lpBaseOfImage
    event['child_process_handle'] = <unsigned long long>de.u.CreateProcessInfo.hProcess
    event['child_thread_handle'] = <unsigned long long>de.u.CreateProcessInfo.hThread
```

字段名带 `child_` 前缀，不影响现有 `base_of_image`。

### Debugger API

#### 新增方法

```python
def set_debug_children(self, enabled: bool = True):
    """开启/关闭子进程调试。必须在 create_process 之前调用。"""

def get_child_processes(self) -> dict[int, ChildProcessInfo]:
    """返回所有子进程信息。"""

def get_child_process(self, pid: int) -> ChildProcessInfo | None:
    """返回指定子进程信息。"""
```

#### create_process 改动

```python
def create_process(self, path):
    pid, tid, h_proc, h_thr = _pydbg.create_process(
        path, self._session.debug_children)
    # ... 现有逻辑不变
```

#### 事件循环自动跟踪

```python
def wait_event(self, timeout_ms=10000):
    event_dict = _pydbg.wait_for_debug_event(timeout_ms)
    if event_dict is None:
        return None
    event = DebugEvent(event_dict)

    # 自动跟踪子进程
    if (self._session.debug_children and
            event.type == "CREATE_PROCESS" and
            event.pid != self._session.pid):
        self._register_child(event)

    # 自动注销退出的子进程
    if (event.type == "EXIT_PROCESS" and
            event.pid in self._session.child_processes):
        self._unregister_child(event)

    return event
```

#### 现有方法加 pid 参数

```python
def read_memory(self, addr, size, pid=None):
    h = self._get_process_handle(pid)
    return self.memory.read_handle(h, addr, size)

def write_memory(self, addr, data, pid=None):
    h = self._get_process_handle(pid)
    return self.memory.write_handle(h, addr, data)

def set_breakpoint(self, addr, pid=None):
    h = self._get_process_handle(pid)
    return self.brk_sw.set_handle(h, addr)

def detach(self, pid=None):
    target = pid or self._session.pid
    # ... 现有逻辑

def terminate_process(self, exit_code=1, pid=None):
    target_pid = pid or self._session.pid
    h = self._get_process_handle(pid)
    # ... 现有逻辑
```

内部路由：

```python
def _get_process_handle(self, pid=None):
    if pid is None or pid == self._session.pid:
        return self._session.process_handle
    child = self._session.child_processes.get(pid)
    if child is None:
        raise ProcessError(f"Unknown process pid={pid}")
    return child.process_handle
```

### Internal Components

| 组件 | 改动 |
|------|------|
| `memory/manager.py` | 加 `read_handle(h, addr, size)` / `write_handle` / `query_handle` / `protect_handle` |
| `thread/manager.py` | 不变（`open_thread` 通过 tid 工作） |
| `breakpoint/software.py` | 加 `set_handle(h, addr)` / `remove_handle` |
| `module/resolver.py` | 加 `enumerate_handle(h)` |
| `breakpoint/hardware.py` | 不变（通过 thread_handle 工作） |
| `symbol/resolver.py` | 不变（通过 process_handle 工作，用户可手动传入子进程 handle） |
| `disasm/` | 不变 |
| `hook/` | 不变 |
| `patch/` | 不变 |
| `pe/` | 不变 |
| `dump/` | 不变 |
| `trace/` | 不变 |

### File Change Summary

| File | Change Type |
|------|-------------|
| `src/pydbg/cython/_process.pxi` | Modify |
| `src/pydbg/core/session.py` | Modify |
| `src/pydbg/core/event.py` | Modify |
| `src/pydbg/core/debugger.py` | Modify |
| `src/pydbg/memory/manager.py` | Modify |
| `src/pydbg/breakpoint/software.py` | Modify |
| `src/pydbg/module/resolver.py` | Modify |
| `tests/test_child_process.py` | New |
| `tests/target/child_target.c` | New (test target that spawns child) |

### Testing

#### Test Target

`tests/target/child_target.c` — 创建子进程的测试程序：

```c
#include <windows.h>
#include <stdio.h>
int main(int argc, char* argv[]) {
    if (argc > 1 && strcmp(argv[1], "child") == 0) {
        printf("child process running\n");
        Sleep(1000);
        return 0;
    }
    // 父进程创建子进程
    STARTUPINFO si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "%s child", argv[0]);
    CreateProcessA(NULL, cmd, NULL, NULL, 0, 0, NULL, NULL, &si, &pi);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
```

#### Test Cases

| Test | Description |
|------|-------------|
| `test_set_debug_children` | 开关标志设置 |
| `test_create_with_children_flag` | create_process 传递标志 |
| `test_child_process_event_tracking` | CREATE_PROCESS 自动注册 |
| `test_child_process_exit_tracking` | EXIT_PROCESS 自动注销 |
| `test_read_child_memory` | read_memory(pid=child_pid) |
| `test_set_child_breakpoint` | set_breakpoint(pid=child_pid) |
| `test_detach_child` | detach(pid=child_pid) |
| `test_get_child_processes` | 列出所有子进程 |
| `test_is_child_event` | event.is_child 标志 |
| `test_default_no_children` | 默认不跟踪（兼容性） |
| `test_unknown_pid_raises` | 不存在的 pid 抛 ProcessError |
| `test_set_debug_children_after_create_raises` | create_process 后调用抛 ProcessError |

### Error Handling

| Scenario | Behavior |
|----------|----------|
| `set_debug_children` after `create_process` | Raise `ProcessError` |
| `pid` parameter references unknown process | Raise `ProcessError` |
| Child process handle invalid (already exited) | Raise `ProcessError` |
| `terminate()` without pid | Terminate main process; children killed by OS |
| `detach(pid=child_pid)` | Detach only that child |

### Out of Scope

- Attach to existing process tree (only create_process supported)
- Independent control of grandchild processes
- Automatic breakpoint propagation to children
- `terminate_all()` / `detach_all()` (user iterates `get_child_processes()`)
