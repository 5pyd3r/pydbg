# pydbg — 架构

Windows 二进制分析工具箱：一个 64 位宿主进程同时驱动**动态调试**与**静态分析**，
两侧共享同一套 PE 与反汇编概念。构建：Meson + Cython（可选 LLVM 插桩后端）。

本文描述的是**代码现在的样子**，不是它曾经的样子。写于 v0.2 核心收缩之后。

## 包布局

```
src/pydbg/
├── __init__.py          公共 API 面。除注解/常量/分析外**全部惰性**（见「导入边界」）
├── constants.py         Win32 常量字面值（不依赖扩展）
├── exceptions.py        PydbgError → Process/Mem/Thread/Breakpoint/Timeout/Teardown
├── core/
│   ├── debugger.py      门面：生命周期 + 事件循环 + 原语委托
│   ├── process.py       ProcessManager：句柄解析的唯一入口
│   ├── session.py       DebugSession：状态 + 架构的唯一存储（pid_arch）
│   ├── event.py         DebugEvent
│   ├── status.py        ExitStatus / ExitReason
│   ├── windows.py       窗口探测能力对象（dbg.windows）
│   └── window_probe.py  探测实现（WindowProbeQuery / classify）
├── memory/manager.py    读/写/查询/保护；read_memory_safe 的 gaps
├── thread/manager.py    句柄/上下文/挂起/单步
├── breakpoint/
│   ├── model.py         Breakpoint：软硬统一记录
│   ├── outcome.py       HandleOutcome：NOT_MINE / HANDLED / DEGRADED
│   ├── software.py      INT3 生命周期
│   └── hardware.py      Dr0-3
├── module/resolver.py   模块枚举与文件名
├── symbol/resolver.py   dbghelp 封装（dbg.symbols）
├── pe/                  纯 Python PE 解析**与写出**（无第三方依赖）
├── pdb/                 纯 Python PDB 读取（MSF 校验 + ctypes dbghelp 离线）
├── disasm/engine.py     capstone 封装；模式**按次**判定，不锁存
├── instrument/          插桩：硬编码 stub + LLVM 动态代码生成 + BBL detour
├── hook/{iat,inline}.py IAT / inline hook（dbg.hook_iat / dbg.hook_inline）
├── trace/, dump/, patch/, analysis/
└── cython/              Win32 薄绑定（_pydbg 扩展）
```

`analysis/`（19 模块、约 5k 行）是仓库里最大的模块，单独在下方说明。
`pdb/`（6 模块）是纯 Python + ctypes dbghelp 的 PDB 读取层：`analysis` 对它是
单向依赖，`pdb` 不认识 `analysis`；导入 `pydbg.analysis` 因此不会加载 `_pydbg`，
ADR-0001 不破。

`pe/` 不再只是 parse-only：`pe/writer.py` 的 `write_pe(pe, image_bytes)` 把
`LoadedView` 读出的加载布局镜像写成文件布局的 PE，`file_layout(pe)` 是
`SizeOfImage`/`SizeOfHeaders`/每节文件偏移的唯一计算。`dump/` 在其上组链：
`dump_module`（读活内存 + gap 表）→ `rebuild_pe`（写文件布局，再用 `PE(data)`
回读自检并交出报告）。`pe/` 仍是纯 Python，且不 import `memory`/`dump`
（ADR-0001 延伸）；`import pydbg.dump` 也不加载 `pydbg.trace`（硬件观察是
`watch_writes` 内的延迟导入）。

## 分层

```
Debugger（门面）
  ├─ process / memory / thread / brk_sw / brk_hw / modules     原语，需要会话
  ├─ hook_iat / hook_inline / symbol / instrumenter / bbl_instrumenter
  │  / step_tracer / disasm / assembler                         能力对象，独立可测
  └─ windows                                                   同上
cython/_pydbg（Win32 薄封装） → Win32 / dbghelp / WoW64
```

依赖方向单向。管理器只拿到 `DebugSession`，从不反向依赖 `Debugger`（例外是
`bbl_instrumenter`：它要按门面自己的读写/线程方法装卸 detour，所以拿到门面，
但仍不反向 import `core.debugger`）。
`memory` 不只读写已有内存，也负责目标内分配：`alloc_remote` 给独立 scratch
（BBL 事件环），`alloc_near` 给需要落在地址附近的区域（5 字节 `E9 rel32`
能跳到的 stub）。调用方因此不必自己碰 `_pydbg`。

## 门面边界（ADR-0002）

`Debugger` 只保留**必须知道本会话**的东西：生命周期、事件循环、内存、线程、
断点、模块、异常辅助（46 个公开方法）。窗口探测、符号、hook、单步追踪、
反汇编/汇编通过属性访问——它们能独立构造、独立测试，就不再在门面上开洞。

## 导入边界（ADR-0001）

`import pydbg` 与 `from pydbg.analysis import ...` **不需要 Windows 扩展**。
`__init__` 只急切导入纯 Python 部分（常量、异常、analysis），其余经
`__getattr__` 首次使用时解析。`tests/test_import_boundary.py` 用 meta_path
钩子把扩展变成不可导入来断言这条边界。

## 生命周期与清理（ADR-0004）

每个会写目标的 manager 实现 `teardown()`（还原，返回失败清单，不抛）与
`discard()`（进程已死时只忘记记录）。`Debugger.close()` 按固定顺序
`hook_iat → hook_inline → instrumenter → bbl_instrumenter → brk_hw →
brk_sw → symbols` 撤销，再停止调试、释放句柄；失败聚合成一个
`TeardownError`。`detach()` 与
`terminate_process()` 是它的特例；支持 `with Debugger() as dbg:`。

## 状态与真相

| 概念 | 唯一来源 |
|---|---|
| 目标架构 | `session.pid_arch`（`target_arch` 是派生属性） |
| 线程归属 | `session.tid_pid`，线程继承其进程的架构 |
| 断点 | `session.breakpoints[bp_id]` → `Breakpoint` |
| 句柄 | `ProcessManager`（严格 / 按需 / try 三种语义） |
| 退出原因 | `run()` 返回 `ExitStatus(exit_code, reason)` |

## 事件循环

`run()`、`run_until()` 与手动 `handle_bp_manual`/`handle_ss_manual` 共用
`_dispatch_exception()`，它返回 `HandleOutcome`。`DEGRADED`（断点已重新武装
但 IP 未回退）在三条路径上都会抛 `BreakpointError`。

## 静态分析

`analysis/` 从磁盘镜像工作，入口 `analyze_file` / `analyze_bytes` /
`analyze_pe` / `analyze_process`。`ProcessSource` 是唯一接触活进程的边界
（其 `MemoryManager` 导入是函数内的）。

诚实性原则贯穿其中：
- 覆盖率与重叠成对报告，且**按节**计（各节之和 = 全局 `stats.overlap_bytes`）；
- 无法证明的区间作为 gap / unproven run 报告；
- 值集有 decided / undecided，`contains()` 在 undecided 时抛错。

## 目标架构（WOW64）

宿主恒为 x64，按**目标**分发上下文：x64 走 `CONTEXT`，32 位走 `WOW64_CONTEXT`。
每个 pid 只有一个架构值；内部统一用 RVA，VA 只在边界转换。

## 构建与测试

```bash
meson setup build --buildtype=release && meson compile -C build
meson test -C build --print-errorlogs      # 单个 pytest 入口，自动发现 tests/
```

CI：`pull_request` 与 `push(master)`；`build-and-test` 用 MSVC 构建并跑全套，
`llvm-instrument` 额外验证插桩后端。测试目标由 meson 与
`scripts/build-target32.ps1` 构建，**不入库**。

## 已知限制

- `instrument` 特性自 v0.2 冻结：不新增功能；LLVM 路径由 `-Dllvm-config`
  指定（或 PATH 上的 `llvm-config`），后端是可选构建，核心安装不链接 LLVM。
- x64 目标的 trampoline 不修正 RIP-relative 指令。
- `instrument` 的 C 子集只支持 `int`/`void`；`&&`/`||` 不保留短路求值。
- 多线程安全由调用方负责（插桩/inline hook 需自行挂起其他线程）。
- `set_hw_breakpoint` 的 8 字节校验按目标进程架构，跨架构子进程需显式传 `pid`。
