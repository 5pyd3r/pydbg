# pydbg

Windows 原生二进制调试器 —— 基于 Cython 封装 Win32 Debug API，提供 Pythonic 的高层接口。

[![CI](https://github.com/5pyd3r/pydbg/actions/workflows/ci.yml/badge.svg)](https://github.com/5pyd3r/pydbg/actions/workflows/ci.yml)
![Platform](https://img.shields.io/badge/platform-Windows%20x64-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)

## 功能

- **进程管理** — 创建、附加、分离、终止被调试进程
- **调试事件循环** — 基于回调的高层 `run()` 循环，或手动 `wait_event()` / `continue_event()`
- **内存操作** — 读写进程内存、查询/修改页面保护
- **线程操作** — 获取/设置寄存器上下文、挂起/恢复线程、单步执行
- **断点** — 软件断点（int3）与硬件断点（调试寄存器）
- **模块枚举** — 枚举已加载模块，解析文件名
- **PE 解析器** — 纯 Python 的 PE32/PE32+ 格式解析（DOS头、NT头、节表、导出表、导入表）
- **异常信息** — 结构化解析访问违规等异常详情

## 安装

> **支持 Windows x64（可调试 WOW64 32 位目标）。** 调试 API 依赖 Win32 原生函数。
> 扩展只编译为 x64（win_amd64）；32 位目标经 WOW64 层统一调试。

```bash
pip install .
```

开发模式（可编辑安装）：

```bash
pip install meson-python cython
pip install -e . --no-build-isolation
```

## 快速开始

```python
from pydbg import Debugger

dbg = Debugger()

# 创建被调试进程
pid, tid = dbg.create_process("target.exe")

# 事件驱动调试循环
def on_event(event):
    print(f"[{event.type}] pid={event.pid} tid={event.tid}")
    if event.type == "EXCEPTION":
        print(f"  异常: {event.exception_name} at 0x{event.exception_addr:X}")

exit_code = dbg.run(on_event)

# 或手动控制事件循环
event = dbg.wait_event(timeout_ms=5000)
if event:
    dbg.continue_event(event.pid, event.tid)
```

### 常见操作

```python
# 附加到运行中的进程
dbg.attach(pid)

# 子进程调试（opt-in，默认关闭）
dbg.set_debug_children(True)
pid, tid = dbg.create_process("target.exe")
# 事件循环中通过 event.is_child 区分子进程事件
# 通过 pid 参数操作子进程：read_memory(addr, size, pid=child_pid)

# 读写内存
data = dbg.read_memory(addr, size)
dbg.write_memory(addr, b"\x90\x90")

# 设置软件断点
bp_id = dbg.set_breakpoint(addr)
dbg.remove_breakpoint(bp_id)

# 设置硬件断点（执行断点）
bp_id = dbg.set_hw_breakpoint(addr, condition="x", length=1, slot=0)

# 寄存器操作
h_thread = dbg.open_thread(tid)
regs = dbg.get_registers(h_thread)    # x64: {"rip": ..., "rax": ..., ...}
                                       # x86: {"eip": ..., "eax": ..., ...}
dbg.set_register(h_thread, "rip", new_value)
dbg.step(h_thread)                    # 单步执行

# 枚举模块
for mod in dbg.enum_modules():
    print(f"  {mod['base_address']:016X}  {dbg.get_module_filename(mod['handle'])}")
```

### 子进程调试

默认情况下 pydbg 只调试目标进程，不跟踪子进程。通过 `set_debug_children(True)` 开启：

```python
from pydbg import Debugger

dbg = Debugger()
dbg.set_debug_children(True)  # 必须在 create_process 之前调用
pid, tid = dbg.create_process("target.exe")

while True:
    event = dbg.wait_event(5000)
    if event is None:
        continue

    if event.is_child:
        print(f"[子进程] pid={event.pid} type={event.type}")

    if event.type == "CREATE_PROCESS" and event.is_child:
        # 子进程创建后可读取其内存、设置断点
        child = dbg.get_child_process(event.pid)
        data = dbg.read_memory(child.base_of_image, 2, pid=event.pid)

    if event.type == "EXIT_PROCESS":
        if event.pid == pid:
            break  # 主进程退出
        else:
            child = dbg.get_child_process(event.pid)
            print(f"子进程退出 code={child.exit_code}")

    dbg.continue_event(event.pid, event.tid)
```

支持 `pid` 参数的方法：`read_memory`、`write_memory`、`query_memory`、`protect_memory`、`set_breakpoint`、`enum_modules`、`detach`、`terminate_process`。

## API 参考

### Debugger

| 方法 | 说明 |
|------|------|
| `create_process(path)` | 以调试模式创建进程，返回 `(pid, tid)` |
| `attach(pid)` | 附加到运行中的进程 |
| `detach(pid=None)` | 分离调试器（可指定子进程 pid） |
| `terminate_process(exit_code=1, pid=None)` | 终止被调试进程（可指定子进程） |
| `get_exit_code()` | 获取进程退出码 |
| `close_handle(h)` | 关闭 Win32 句柄 |
| `wait_event(timeout_ms)` | 等待下一个调试事件，返回 `DebugEvent` 或 `None` |
| `continue_event(pid, tid)` | 继续已暂停的调试事件 |
| `run(callback, timeout_ms)` | 事件驱动调试循环，直到进程退出或回调返回 `False` |
| `set_debug_children(enabled=True)` | 开启/关闭子进程调试（必须在 create_process 前调用） |
| `get_child_processes()` | 返回所有子进程信息 `dict[pid, ChildProcessInfo]` |
| `get_child_process(pid)` | 返回指定子进程信息，或 `None` |

**内存**

| 方法 | 说明 |
|------|------|
| `read_memory(addr, size, pid=None)` | 读取进程内存（可指定子进程） |
| `write_memory(addr, data, pid=None)` | 写入进程内存（可指定子进程） |
| `query_memory(addr, pid=None)` | 查询内存区域信息（可指定子进程） |
| `protect_memory(addr, size, protect, pid=None)` | 修改页面保护（可指定子进程） |

**线程**

| 方法 | 说明 |
|------|------|
| `open_thread(tid)` | 打开线程句柄 |
| `get_registers(h_thread)` | 获取寄存器上下文（返回架构适配的寄存器名） |
| `set_registers(h_thread, ctx)` | 设置寄存器上下文（接受 x86/x64 寄存器名） |
| `set_register(h_thread, name, value)` | 设置单个寄存器 |
| `suspend_thread(h_thread)` / `resume_thread(h_thread)` | 挂起/恢复线程 |
| `step(h_thread)` | 单步执行（设置 TF 标志） |
| `enumerate_threads(pid)` | 枚举进程线程 |
| `get_thread_ids(pid)` | 获取线程 ID 列表 |

**断点**

| 方法 | 说明 |
|------|------|
| `set_breakpoint(addr, pid=None)` | 设置 int3 软件断点（可指定子进程） |
| `set_hw_breakpoint(addr, condition, length, slot, tid=None)` | 设置硬件断点（默认进程级：作用于全部线程并复制到新线程；指定 tid 仅该线程） |
| `remove_breakpoint(bp_id)` | 移除断点 |
| `find_breakpoint(addr)` | 查找地址上的断点 |

**模块 / 异常**

| 方法 | 说明 |
|------|------|
| `enum_modules(pid=None)` | 枚举已加载模块（可指定子进程） |
| `get_module_filename(h_module)` | 获取模块文件名 |
| `exception_code_to_str(code)` | 异常码 → 名称 |
| `get_exception_info(code, addr, ...)` | 解析异常详情 |

### DebugEvent

| 属性 | 说明 |
|------|------|
| `type` | 事件类型: `CREATE_PROCESS`, `EXCEPTION`, `LOAD_DLL`, `EXIT_PROCESS` 等 |
| `pid` / `tid` | 进程/线程 ID |
| `exception_code` | 异常码（仅 EXCEPTION 事件） |
| `exception_addr` | 异常地址 |
| `exception_name` | 异常名称（如 `EXCEPTION_ACCESS_VIOLATION`） |
| `exception_info` | 结构化异常信息 |
| `is_child` | `True` 表示事件来自子进程（需 `set_debug_children(True)`） |
| `raw` | 原始事件字典 |

### 异常类

```
PydbgError                    # 基类
├── ProcessError              # 进程操作错误
├── MemError                  # 内存操作错误
├── ThreadError               # 线程操作错误
├── BreakpointError           # 断点操作错误
└── TimeoutError              # 调试事件超时
```

### PE 解析器

```python
from pydbg.pe import PE

pe = PE.from_file("kernel32.dll")
print(pe.file_header.machine)          # 0x8664 (AMD64)
print(pe.optional_header.entry_point_rva)
for exp in pe.exports:
    print(exp.name)
```

## 架构

```
Debugger (core/debugger.py)           — 门面，生命周期 + 事件循环
  ├── _session: DebugSession          — 纯状态数据类，含 host_arch / target_arch (core/session.py)
  ├── memory: MemoryManager           — 读写/查询/保护 (memory/manager.py)
  ├── thread: ThreadManager           — 上下文/挂起/单步 (thread/manager.py)
  ├── brk_sw: SoftwareBreakpointManager — int3 断点 (breakpoint/software.py)
  ├── brk_hw: HardwareBreakpointManager — 调试寄存器断点 (breakpoint/hardware.py)
  └── modules: ModuleResolver         — 枚举模块、解析文件名 (module/resolver.py)
```

### 目标架构支持

宿主恒为 64 位（`win_amd64`）。扩展按**目标**架构分发上下文：

- **x64 目标** — `get_registers()` 返回 x64 寄存器名（`rax`/`rip`/`rsp`/...）。
- **WOW64（32 位）目标** — `create_process()`/`attach()` 通过 `IsWow64Process`
  检测，`get_registers()` 返回 x86 寄存器名（`eax`/`eip`/`esp`/...）。

软件断点/硬件断点/单步按目标架构正确处理（WOW64 走 `Wow64GetThreadContext` +
`STATUS_WX86_*` 事件码）；模块枚举用 `EnumProcessModulesEx(LIST_MODULES_ALL)`
同时列出 32/64 位模块，并标注 `arch` 字段。

## 开发

### 常规方式

```bash
# 安装开发依赖
pip install meson ninja cython flake8

# 构建
meson setup build --buildtype=release
meson compile -C build

# 测试
meson test -C build --print-errorlogs

# 代码风格检查
flake8 src/ tests/ --max-line-length=120
```

### 使用 Embedded Python 本地验证

```powershell
# 首次：下载并配置 embedded Python (x64)
.\devtools\setup-embedded.ps1

# 构建并测试
.\devtools\build-test.ps1
```

## License

MIT
