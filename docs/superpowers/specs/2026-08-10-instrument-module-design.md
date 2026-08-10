# 插桩模块设计 — pydbg Instrumentation

> 设计文档 | 2026-08-10 | pydbg
> 状态：已批准，待实现（见 plans/）

## 概述

在 pydbg 中实现**插桩（instrumentation）模块**：以**硬编码指令**生成 stub / trampoline，
以 **LLVM** 能力**动态生成插桩 payload 的机器码**并注入目标进程。

前置约束：
- **不用 Keystone** 生成 stub 指令 —— 全部用硬编码字节模板。
- **不编译 LLVM 源码仓库** —— 链接机器上已有的预编译 LLVM 17
  （`C:/Users/Spyder/AppData/Local/llvm-17`，含 X86 codegen / MCJIT / libclang）。
  > 说明：`Output/llvm-core-libs-22.1.4-*.tar.xz` 仅含 8 个 core 库
  > （无 X86 codegen / MCJIT / libclang），无法进程内生成机器码，故不采用。

实现起点：**移植本地分支 `feat/llvm-hook`**（C++ 代码生成器约 1500 行，已验证），
适配当前 master 的 WOW64 统一调试引擎，重排为 `instrument/` 模块。

## 三层架构

```
目标进程地址空间
┌───────────────────────────────────────────┐
│ target_addr   硬编码 stub   E9 rel32 ──→  payload │
│ (被覆盖的原始指令, 按指令边界取 ≥5 字节)     │
├───────────────────────────────────────────┤
│ payload (RWX, LLVM 生成机器码)            │
│   on_call(...) 入口, extern 符号编译期预绑定 │
├───────────────────────────────────────────┤
│ trampoline (RWX, 硬编码)                 │
│   原始指令副本 + E9 rel32 ──→ target+len    │
│   original_func 自动映射到 trampoline 地址  │
└───────────────────────────────────────────┘
```

| 层 | 生成方式 | 职责 |
|----|---------|------|
| **stub** | 硬编码 `E9 rel32`（5 字节绝对跳转，复用 inline.py 模板） | 目标入口改写到 payload |
| **payload** | LLVM 动态生成：C 源码 → libclang → LLVM IR → TargetMachine → 机器码 | 插桩逻辑本体 |
| **trampoline** | 硬编码：原始指令副本 + `E9 rel32` | 恢复执行；以 `original_func` 暴露给 payload |

**WOW64 适配**：`Instrumenter` 读 `session.target_arch` 选择 x86/x64 模板与 LLVM triple；
内存分配/读写走 `MemoryManager`（天然支持子进程 pid）。

## 包布局

```
src/pydbg/instrument/
├── __init__.py          — 导出 Instrumenter, InstrumentTemplates, InstrumentInfo
├── templates.py         — 硬编码指令模板 + 原语 C 源码生成器
├── instrumenter.py      — 编排 install / restore / active
├── codegen.py           — extern 扫描 / 符号校验 + _llvm_backend 懒加载调用
└── llvm_backend/        — 移植 feat/llvm-hook 的 C++ 代码生成器
    ├── meson.build
    ├── hook_compiler.h / hook_compiler.cpp
    ├── clang_to_ir.h / clang_to_ir.cpp     — libclang AST → LLVM IR
    ├── target_codegen.h / target_codegen.cpp — TargetMachine → 机器码 + 符号绑定
    └── external_symbol.h                   — ExternalSymbolTable (map<string,uint64_t>)
src/pydbg/cython/_llvm_backend.pyx          — Cython 绑定：compile_stub / resolveTriple
tests/test_instrument.py                    — 移植 tests/test_llvm_hook.py
tests/target/instrument_target.c            — 测试目标 C 源码
```

### 与现有代码的关系

- `hook/`（IATHook / InlineHook）保持不动；插桩是更高一层，可独立使用。
- `templates.py` 复用 inline.py 的绝对跳转思路，但不依赖 Keystone。
- `session` 复用 WOW64 统一会话（target_arch 分发）。

## 公共 API

```python
from pydbg.instrument import Instrumenter, InstrumentTemplates

inst = Instrumenter(session)

# 方式一：直接写 C 源码（三件套）
info = inst.install(
    target_addr=0x00401000,
    c_source=r'''
        extern int original_func(int a, int b);
        extern void Game_Log(const char* msg);
        int on_call(int a, int b) {
            Game_Log("hooked");
            return original_func(a, b) + 1;
        }
    ''',
    symbols={"Game_Log": 0x00601000},  # 可选；original_func 自动映射
)

# 方式二：使用常用原语
info = inst.install(
    target_addr=0x00401000,
    template=InstrumentTemplates.log_args(
        entry="on_call", params="int a, int b",
        log_symbol="Game_Log", externs={"Game_Log": 0x00601000},
    ),
)

inst.restore(0x00401000)
inst.active              # {addr: InstrumentInfo}
```

`install()` 必须且只能提供 `c_source` 与 `template` 二者之一，同时提供抛 `PydbgError`。

### `InstrumentInfo`

`trampoline_addr` / `trampoline_size` / `stub_addr` / `stub_size` /
`original_bytes` / `symbols` / `c_source`。

### 关键约定

- payload 入口函数名 `on_call`，签名与原始函数一致。
- `extern ... original_func(...)` 为保留名，自动映射到 trampoline 地址。
- 其余 `extern` 符号由用户通过 `symbols` 显式提供地址；缺失即报错。
- 代码基地址由 pydbg 自动分配（`VirtualAllocEx`，PAGE_EXECUTE_READWRITE）。

## 硬编码指令模板（templates.py）

```python
def build_abs_jmp(from_addr: int, to_addr: int) -> bytes:
    """5 字节 E9 rel32。范围检查 ±2GB，越界抛 PydbgError。"""

def build_stub(target_addr: int, payload_addr: int) -> bytes:
    return build_abs_jmp(target_addr, payload_addr)

def build_trampoline(original: bytes, jmp_back_addr: int) -> bytes:
    return original + build_abs_jmp(<trampoline_end>, jmp_back_addr)
```

- 无 Keystone / capstone 依赖（原始指令边界由现有 `DisasmEngine` 判定）。
- 与 inline.py 的 `_build_abs_jmp` 语义一致，实现抽到 templates.py 供两处复用。

## 常用原语（InstrumentTemplates）

全部返回 `(c_source, symbols)`，走同一条 LLVM 流水线。

| 原语 | 生成逻辑 |
|------|---------|
| `log_args(entry, params, log_symbol, externs)` | 进入时把每个参数喂给 `log_symbol`，再调 original 并返回 |
| `call_counter(entry, params, counter_addr)` | 每次调用对 `counter_addr` 指向的 `volatile int` +1，再走 original |
| `modify_return(entry, params, expr, externs)` | 调 original，将返回值套 `expr` 后返回 |

- `entry` 为用户要求的入口函数名（默认 `on_call`），与签名共同生成 C 源码。
- `symbols` 自动并入 `{entry-相关...}` 与 `original_func` 保留映射。

## LLVM 动态代码生成（llvm_backend + codegen.py）

### 流水线（移植 feat/llvm-hook）

1. `_scan_externs(c_source)` 正则提取 `extern ... name(...);` 集合（保留 `original_func`）。
2. 校验：所有 extern（除 `original_func`）必须在 `symbols` 中有地址，否则 `PydbgError` 列出缺失项。
3. `_llvm_backend.compile_stub(c_source, arch, symbols)`：
   - `HookCompiler::resolveTriple(arch)`：`x86 → i686-pc-windows-msvc`，`x64 → x86_64-pc-windows-msvc`。
   - `ClangToIRConverter`：libclang 解析 C 子集 → LLVM IR（架构无关）。
   - `TargetCodeGen`：TargetMachine 生成 object file → 提取 `.text` → 按 `ExternalSymbolTable`
     解析重定位，把 `call` 等外部符号写死为绝对地址。
   - 返回**零重定位**的机器码字节。
4. pydbg 分配 RWX stub 内存、写入机器码。
5. 硬编码 `E9 rel32` 写入 target_addr → stub。

### 支持架构

- X86（i386，32 位 WOW64 目标）与 X86_64（本机 x64 目标），均来自 LLVM 17 X86 后端。

## 构建集成

### meson

- `meson.options` 新增：`option('enable-llvm-instrument', type : 'boolean', value : false)`。
- `src/pydbg/instrument/llvm_backend/meson.build`（仅在开启时包含）：
  1. 定位 `llvm-config`：`-Dllvm-config=<path>` 优先；否则搜索
     `C:/Users/Spyder/AppData/Local/llvm-17/bin/llvm-config.exe`、
     `C:/Program Files/LLVM/bin/llvm-config.exe`。找不到 → 直接 error。
  2. 由 `llvm-config --libs core executionengine mcjit native nativecodegen x86 x86codegen ...`
     生成链接库列表；`--system-libs` 补系统库。
  3. 链接 `libclang.lib`（同目录，或 `-Dlibclang-config=`）。
  4. 链接参数追加 `/INCLUDE:LLVMInitializeX86TargetInfo /Target /TargetMC /AsmPrinter /AsmParser`
     防止 `/OPT:REF` 剥离 X86 目标符号。
- `cython/meson.build`：`enable-llvm-instrument` 时构建 `_llvm_backend` Cython 扩展，
  链接 `hook_compiler` 静态库 + LLVM/clang 依赖。
- **绝不 wrap LLVM 源码**（`subprojects/` 不放 llvm-project.wrap）。

### Python 侧懒加载

`codegen.py` 惰性 `import _llvm_backend`；模块缺失时 `install()` 抛
`PydbgError("LLVM backend not available. Rebuild with -Denable-llvm-instrument=true")`。
非 LLVM 路径（hook / 其余 pydbg 功能）完全不受影响。

## 错误处理

| 场景 | 行为 |
|------|------|
| LLVM 后端未启用 | `PydbgError`（带重建提示） |
| 编译失败 | `PydbgError`（透传 `HookCompiler::getLastError`） |
| extern 未解析 | `PydbgError`（列出缺失符号） |
| 原始代码 <5 字节 / 指令边界失败 | `PydbgError` |
| 内存分配失败 | `PydbgError`；已分配的 trampoline 一并回滚释放 |
| `restore` 不存在的地址 | 幂等 no-op |

## 测试

- `tests/test_instrument.py`（移植自 test_llvm_hook.py，188 行 + 扩展）：
  - extern 扫描、符号校验（缺失 → 报错）
  - triple 解析（x86 / x64）
  - 模板生成正确性（log_args / call_counter / modify_return 生成的 C 源码结构）
  - install / restore 往返（live target，校验 stub 跳转与 trampoline 恢复）
  - LLVM 后端未启用时的降级错误
- 测试目标 `tests/target/instrument_target.c`：导出 `on_call` 语义的 C 函数。

## 已知限制（沿用旧 non-goal）

- x64 目标若被覆盖的首个 ≥5B 序列含 **RIP-relative** 指令，trampoline 不做重定位修正。
  x86/WOW64 目标无此问题。列为 future work。
- 不做热补丁（2 字节短 JMP）。
- 多线程安全性由调用方负责（挂起其他线程）。
- LLVM 17 C++ API 与 LLVM 22 有差异，本项目固定链接 LLVM 17，不追求新版本。

## 分支与交付

- 分支：`feat/instrument-module`（worktree `Output/instrument-module`）。
- 流程：PR 提交，人工 merge，不碰 master（CLAUDE.md）。
- CI：CI 上 LLVM 不可用时跳过 LLVM 测试（记遗留）。
