# pydbg — Python Win32 Debugger Architecture

## Overview

pydbg 是一个模块化、可扩展的 Windows 二进制调试器框架，基于 Python + Cython。
它在原生 Win32 调试原语之上提供一层 Pythonic 的高层过程式 API。

宿主平台：**Windows x64**（单一 x64 宿主调试引擎，可同时调试 64 位目标与
WOW64 32 位目标）。构建：Meson + Cython + LLVM 22（可选插桩后端）。

## Current Architecture

### 包布局

```
pydbg/
├── __init__.py         — 公共 API 面（Debugger、DebugEvent、常量、异常、各 feature 导出）
├── exceptions.py       — 异常层级（PydbgError → Process/Mem/Thread/Breakpoint/Timeout）
├── core/               — 调试核心
│   ├── debugger.py     — Debugger 门面（组合模式，生命周期 + 事件循环）
│   ├── event.py        — DebugEvent（事件封装 + 异常解析）
│   └── session.py      — DebugSession / ChildProcessInfo（纯状态数据类）
├── memory/manager.py   — 读写/查询/保护进程内存
├── thread/manager.py   — 线程句柄/寄存器上下文/挂起恢复/枚举/单步
├── breakpoint/
│   ├── software.py     — int3（0xCC）软件断点 + 生命周期（INT3↔单步↔重装）
│   └── hardware.py     — Dr0-3 调试寄存器硬件断点（进程级 + 线程级 + 复制）
├── module/resolver.py  — 模块枚举、文件名解析、PE 头 arch 判定
├── symbol/resolver.py  — dbghelp.dll 符号解析
├── pe/                 — 纯 Python PE32/PE32+ 解析器（无第三方依赖）
│   ├── types.py        — 结构体 dataclass
│   ├── source.py       — 字节源抽象（BytesSource / FileSource）
│   ├── view.py         — RVA↔文件偏移（FileView / LoadedView）
│   └── parser.py       — DOS/NT/节表/导出/导入解析
├── disasm/
│   ├── engine.py       — capstone 封装（x86/x64 模式）
│   └── analysis.py     — 基本块 / CFG / 后继分析
├── trace/
│   ├── step.py         — 单步执行（TF 标志）
│   └── calltree.py     — call/ret 调用树
├── hook/
│   ├── iat.py          — IAT（导入地址表）hook
│   └── inline.py       — inline detour（5 字节 E9 + trampoline）
├── dump/
│   ├── minidump.py     — Minidump 文件解析器
│   └── stackwalk.py    — x64 栈回溯
├── patch/assembler.py  — keystone 封装（汇编字符串 → 机器码）
├── instrument/         — 插桩（硬编码 stub + LLVM 动态代码生成）
│   ├── instrumenter.py — install / restore / active 编排
│   ├── codegen.py      — extern 扫描、符号校验、_llvm_backend 懒加载
│   ├── templates.py    — 硬编码指令模板 + 常用原语 C 源码生成
│   └── llvm_backend/   — C++ 代码生成器（clang C++ API + LLVM TargetMachine）
└── cython/             — Win32 C 绑定（_pydbg 扩展）
    ├── _pydbg.pyx      — 主扩展入口（include 各 .pxi）
    ├── _llvm_backend.pyx — LLVM 后端绑定（可选，仅 enable-llvm-instrument=true）
    ├── _win32types.pxd — 类型声明（windows.h / psapi.h / tlhelp32.h）
    └── _process/_memory/_thread/_exception/_bp/_symbol/_dump.pxi
```

### 分层图

```
┌──────────────────────────────────────────────┐
│  Debugger (core/debugger.py)                 │  ← 门面：组合各 manager，事件循环
│    ├─ memory / thread / modules / symbols    │
│    ├─ brk_sw / brk_hw / disasm / assembler   │
│    └─ step_tracer / hook_iat / hook_inline / stack_walker │
├──────────────────────────────────────────────┤
│  各 feature manager（纯 Python，构造注入     │  ← 业务逻辑层
│  DebugSession，无全局状态）                   │
├──────────────────────────────────────────────┤
│  cython/_pydbg（Win32 薄封装）               │  ← C 绑定层
├──────────────────────────────────────────────┤
│  Win32 API（kernel32, psapi, tlhelp32,       │  ← 原生 OS 层
│  dbghelp, ntdll/WoW64）                       │
└──────────────────────────────────────────────┘
```

依赖方向单向：`core（门面）← feature manager ← cython 绑定 ← Win32`。无循环 import
（跨模块引用多为函数内延迟 import）。

## 目标架构支持（WOW64 统一引擎）

宿主恒为 64 位（`win_amd64`）。扩展不按宿主位数分支，而是按**目标**架构分发：

- **x64 目标** — 原生 `CONTEXT` + `GetThreadContext`/`SetThreadContext`；寄存器名
  `rax`/`rip`/`rsp`/...。
- **WOW64（32 位）目标** — `WOW64_CONTEXT` + `Wow64GetThreadContext`/
  `Wow64SetThreadContext`；寄存器名 `eax`/`eip`/`esp`/...。

关键机制：

| 维度 | 处理 |
|------|------|
| 架构检测 | `create_process`/`attach` 用 `IsWow64Process` 设置 `session.target_arch` |
| 上下文分发 | Cython 函数带 `machine` 参数（32/64）；Python 端从 `session.target_arch` 传入 |
| 事件码 | WOW64 断点/单步上报 `STATUS_WX86_BREAKPOINT (0x4000001F)` / `STATUS_WX86_SINGLE_STEP (0x4000001E)`，与 `0x80000003/04` 同等对待，**必须 `DBG_CONTINUE`** |
| 硬件断点 | WOW64 写 Dr0-3 前先 `SuspendThread`、写后 `ResumeThread`（否则约 3/4 概率不生效） |
| 模块枚举 | `EnumProcessModulesEx(LIST_MODULES_ALL)` 同时列出 32/64 位模块，按 PE 头标注 `arch` |
| 每线程架构 | `session.tid_arch` / `pid_arch` 跟踪，供跨架构子进程/线程正确取上下文 |

## Instrument 模块（插桩）

以硬编码字节生成 stub/trampoline，用 LLVM 动态编译 C 子集为机器码 payload，注入目标进程。

```
目标进程地址空间
┌───────────────────────────────────────────┐
│ target_addr   硬编码 stub  E9 rel32 → payload │
│（被覆盖的原始指令，按指令边界取 ≥5 字节）       │
├───────────────────────────────────────────┤
│ payload（RWX，LLVM 生成机器码）              │
│   on_call(...) 入口，extern 符号编译期预绑定   │
├───────────────────────────────────────────┤
│ trampoline（RWX，硬编码）                   │
│   原始指令副本 + E9 rel32 → target+len      │
│   original_func 自动映射到 trampoline 地址   │
└───────────────────────────────────────────┘
```

流水线：`C 源码 → clang C++ AST → LLVM IR → TargetMachine → 对象文件 → 提取 .text →
按 ExternalSymbolTable 重定位 → 零重定位机器码`。链接静态 clang/LLVM 组件库，无
`libclang.dll` 依赖。

关键约定：payload 入口函数名 `on_call`；`original_func` 为保留名，自动映射到
trampoline；其余 `extern` 符号由调用方经 `symbols` 显式提供地址。C 子集只支持
`int`/`void`（指针等类型静默映射为 `i32`）。

## External Dependencies

| 库 | 版本 | 用途 |
|----|------|------|
| capstone | ≥5.0 | x86/x64 反汇编 |
| keystone | ≥0.9 | 汇编（patch/assembler） |
| LLVM 22 | 预编译 | 插桩后端（可选，`-Denable-llvm-instrument=true`） |

**Non-dependencies（by design）：**
- pefile — 自带 `pe/` 解析 PE
- pykd — 内核调试，范围外
- winappdbg — 自有框架
- distorm3 — capstone 维护更活跃
- construct / pdbparse — 符号解析走 dbghelp.dll（`symbol/resolver.py`），不解析 PDB 二进制

## Design Principles

1. **门面组合，非单体。** `Debugger` 是组合各 manager 的门面，本身只做生命周期与
   事件循环；业务逻辑分散在单一职责的 manager 中。
2. **依赖方向单向。** `core ← feature ← cython ← Win32`。无循环 import。
3. **薄 Cython 层。** `.pyx/.pxi` 是 Win32 API 的薄封装，业务逻辑（断点跟踪、事件
   分发、异常分类）留在纯 Python。例外：`instrument/llvm_backend/`（C++）因能力需求
   内聚了代码生成逻辑，但经独立 `_llvm_backend` 扩展与 `_pydbg` 隔离。
4. **可独立测试。** 每个 manager 经构造注入 `DebugSession`；Cython 层可用 mock
   隔离做单元测试，集成测试需 Windows + 编译扩展。
5. **模块边界 = 文件边界。** 一个概念一个文件，无 `utils.py` 垃圾桶。
6. **不硬耦合调试循环。** `run()` 只是事件循环的一个消费者；各模块也支持
   `wait_event()`/`continue_event()` 手动模式（`handle_bp_manual`/`handle_ss_manual`）。

## Build System

Meson + Cython：

- `meson setup build --buildtype=release` — 配置
- `meson compile -C build` — 构建 Cython 扩展
- `meson test -C build` — 运行测试
- `-Denable-llvm-instrument=true` — 启用插桩后端（定位预编译 LLVM 22 或
  `-Dllvm-config=<path>`）

产物：`_pydbg.cp<ver>-win_amd64.pyd`（主扩展）+ 可选 `_llvm_backend.cp<ver>-win_amd64.pyd`。

CI：GitHub Actions，`windows-latest`，仅 x64 宿主；32 位目标在 CI 现编译
（`scripts/build-target32.ps1`，`vcvarsall amd64_x86` 交叉编译），用于 WOW64 测试。

## 已知限制（遗留）

- x64 目标若被覆盖的首个 ≥5B 序列含 **RIP-relative** 指令，trampoline 不做重定位
  修正（x86/WOW64 无此问题）。
- `_scan_externs` 是正则启发式，非完整 C 解析器；注释中的 extern、函数指针类型的
  extern 无法可靠识别。
- 插桩 payload 类型仅支持 `int`/`void`；`&&`/`||` 不保留短路求值。
- 多线程安全性由调用方负责（插桩/inline hook 挂起其他线程）。
- `pyproject.toml` 声明 `requires-python = ">=3.8"`，但代码使用 `int | None` 等
  PEP 604 语法（实际构建/CI 用 Python 3.13+），版本声明与语法要求不一致。
