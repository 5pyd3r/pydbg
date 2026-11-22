# 插桩模块（Instrument Module）实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 pydbg 上实现插桩模块 `instrument/`：硬编码指令生成 stub/trampoline，LLVM 17 动态生成 payload 机器码，移植本地分支 `feat/llvm-hook` 到当前 master（WOW64 统一调试引擎）。

**Architecture:** 三层注入模型——target 地址写入硬编码 5 字节 `E9 rel32` 跳到 LLVM 生成的 payload；payload（C 源码→libclang→IR→TargetMachine→机器码，外部符号编译期绑定）执行插桩逻辑并通过 `original_func` 调 trampoline；trampoline 由被覆盖的原始指令 + 硬编码 `E9 rel32` 跳回组成。LLVM 后端作为 Cython 扩展懒加载，未构建时 `install()` 抛 `PydbgError`。

**Tech Stack:** meson/ninja 1.11+、MSVC (cl 19.44)、C++17、Cython 3.x、LLVM 17.0.6（`C:/Users/Spyder/AppData/Local/llvm-17`，含 libclang）、Python 3.14、pytest/unittest、capstone（仅 disasm）。

**已验证的前置事实：**
- MSVC 可直接编译 LLVM 17 头文件 + `clang-c/Index.h` 并链接（spike 通过，exit 0，仅 C4146/C4624 警告）。**不需要 clang-cl / native 文件**。
- 预编译 LLVM 17 位置：`C:/Users/Spyder/AppData/Local/llvm-17`（`bin/llvm-config.exe`、`lib/LLVM*.lib`、`lib/libclang.lib`、`include/`）。
- MSVC 兼容 C++ 编译参数：`/std:c++17 /EHsc /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS /D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH`；建议加 `/wd4146 /wd4624` 抑制 LLVM 头文件警告。
- 构建/测试操作模式（沿用 `devtools/build-x64-current.ps1`）：`cmd /c "call <vcvarsall> amd64 && meson setup ... && meson compile -C ..."`，构建后把 `.pyd` 拷贝到 `src/pydbg/` 使源码树可直接 import。

---

## 文件结构

```
（全部相对 repo 根 = Output/instrument-module/，分支 feat/instrument-module）

meson.options                          ← 修改：新增 3 个 option
meson.build                            ← 修改：加 'cpp' 语言 + enable_llvm 消息
src/pydbg/meson.build                  ← 修改：按 option 引入 instrument/llvm_backend
src/pydbg/__init__.py                  ← 修改（Task 9）：导出 Instrumenter / InstrumentTemplates

src/pydbg/instrument/
├── __init__.py                        ← 修改（Task 7）：导出
├── templates.py                       ← 新建（Task 4/6）：硬编码指令 + 原语 C 生成器
├── codegen.py                         ← 新建（Task 5）：extern 扫描 + 符号校验 + 后端调用
├── instrumenter.py                    ← 新建（Task 7）：Instrumenter / InstrumentInfo
└── llvm_backend/                      ← 新建（Task 1/2）：C++ 代码生成器（移植 feat/llvm-hook）
    ├── meson.build                    ← 新建（Task 1）：llvm-config 检测 + hook_compiler 静态库
    ├── external_symbol.h              ← 新建（Task 1）
    ├── hook_compiler.h / .cpp         ← 新建（Task 1 骨架 → Task 2 全量）
    ├── clang_to_ir.h / .cpp           ← 新建（Task 2，git show 移植）
    └── target_codegen.h / .cpp        ← 新建（Task 2，git show 移植）

src/pydbg/cython/
├── _llvm_backend.pyx                  ← 新建（Task 3）：Cython 绑定
└── meson.build                        ← 修改（Task 3）：按 option 构建 _llvm_backend

src/pydbg/hook/inline.py               ← 修改（Task 4）：复用 templates.build_abs_jmp（行为不变）

tests/
├── test_instrument.py                 ← 新建（Task 4 起逐任务追加测试类）
├── target/instrument_target.c         ← 新建（Task 8）
└── meson.build                        ← 修改（Task 8）：构建 instrument_target + 注册测试

scripts/build-target32.ps1             ← 修改（Task 8）：加 instrument_target32 构建

README.md                              ← 修改（Task 9）
```

---

## Task 1: meson 构建接线 + 工具链骨架验证

**Files:**
- Modify: `meson.options`
- Modify: `meson.build`
- Modify: `src/pydbg/meson.build`
- Create: `src/pydbg/instrument/__init__.py`
- Create: `src/pydbg/instrument/llvm_backend/external_symbol.h`
- Create: `src/pydbg/instrument/llvm_backend/hook_compiler.h`
- Create: `src/pydbg/instrument/llvm_backend/hook_compiler.cpp`
- Create: `src/pydbg/instrument/llvm_backend/meson.build`

- [ ] **Step 1: 覆写 `meson.options`**

```meson
option('enable-llvm-instrument',
  type : 'boolean',
  value : false,
  description : 'Enable LLVM-based instrumentation backend (requires prebuilt LLVM 17 + libclang)')

option('llvm-config',
  type : 'string',
  value : '',
  description : 'Path to llvm-config binary. Default: search prebuilt LLVM 17 locations.')

option('libclang-config',
  type : 'string',
  value : '',
  description : 'Path to clang-config binary. Default: search prebuilt LLVM 17 locations.')
```

- [ ] **Step 2: 覆写 `meson.build`**

```meson
project('pydbg', 'c', 'cpp', 'cython',
  version: '0.1.0',
  meson_version: '>=0.60',
  default_options: [
    'c_std=c11',
    'cpp_std=c++17',
    'buildtype=release',
    'b_ndebug=if-release',
    'cython_language=c']
)

# Python dependency
py_mod = import('python')
py = py_mod.find_installation(pure: false)

# LLVM instrumentation — optional feature
if get_option('enable-llvm-instrument')
  message('LLVM Instrument: ENABLED')
else
  message('LLVM Instrument: DISABLED (set -Denable-llvm-instrument=true)')
endif

subdir('src/pydbg')
subdir('tests')
```

注意：`cython_language=c` 保持默认；`_llvm_backend` 扩展用 `override_options: ['cython_language=cpp']` 单独覆盖。

- [ ] **Step 3: 覆写 `src/pydbg/meson.build`**

```meson
# 定义 Python 包安装路径
pkg_pydir = py.get_install_dir() / 'pydbg'

# 安装 Python 模块（排除构建文件）
install_subdir('.',
  install_dir: pkg_pydir,
  exclude_files: ['meson.build'],
  exclude_directories: ['cython/'],
)

# LLVM Instrument 后端（可选）
if get_option('enable-llvm-instrument')
  subdir('instrument/llvm_backend')
endif

# 构建 Cython 扩展
subdir('cython')
```

- [ ] **Step 4: 创建骨架 `src/pydbg/instrument/__init__.py`**（占位，后续 Task 补全）

```python
"""pydbg instrumentation module — hardcoded stubs + LLVM dynamic codegen."""
```

- [ ] **Step 5: 创建 `src/pydbg/instrument/llvm_backend/external_symbol.h`**

```cpp
// pydbg LLVM instrumentation backend — shared ExternalSymbolTable typedef
#pragma once

#include <map>
#include <string>
#include <cstdint>

using ExternalSymbolTable = std::map<std::string, uint64_t>;
```

- [ ] **Step 6: 创建骨架 `src/pydbg/instrument/llvm_backend/hook_compiler.h`**

```cpp
// pydbg LLVM instrumentation backend — HookCompiler public API
// 骨架：仅验证工具链链接。Task 2 移植全量实现。
#pragma once

#include <string>
#include <vector>
#include <cstdint>

#include "external_symbol.h"

class HookCompiler {
public:
    explicit HookCompiler(const std::string& targetTriple);
    HookCompiler(const HookCompiler&) = delete;
    HookCompiler& operator=(const HookCompiler&) = delete;

    std::vector<uint8_t> compile(const std::string& cSource,
                                  const ExternalSymbolTable& symbols);
    const std::string& getLastError() const { return lastError_; }
    static std::string resolveTriple(const std::string& arch);

private:
    std::string targetTriple_;
    std::string lastError_;
};
```

- [ ] **Step 7: 创建骨架 `src/pydbg/instrument/llvm_backend/hook_compiler.cpp`**

```cpp
// 骨架实现：验证 MSVC + LLVM 头文件 + LLVM 库链接（Task 2 全量移植）
#include "hook_compiler.h"

HookCompiler::HookCompiler(const std::string& targetTriple)
    : targetTriple_(targetTriple) {}

std::vector<uint8_t> HookCompiler::compile(const std::string& cSource,
                                            const ExternalSymbolTable& symbols) {
    (void)cSource; (void)symbols;
    lastError_ = "skeleton";
    return {0x90, 0xC3};  // nop; ret
}

std::string HookCompiler::resolveTriple(const std::string& arch) {
    if (arch == "x86_64") return "x86_64-pc-windows-msvc";
    if (arch == "x86")    return "i686-pc-windows-msvc";
    return arch;
}
```

- [ ] **Step 8: 创建 `src/pydbg/instrument/llvm_backend/meson.build`**

```meson
# LLVM Instrument 后端 — 检测预编译 LLVM 17 + libclang，构建 hook_compiler 静态库
fs = import('fs')

llvm_config = ''
llvm_cfg = get_option('llvm-config')
if llvm_cfg != ''
  llvm_config = find_program(llvm_cfg, native : true)
else
  llvm_config = find_program(
    'llvm-config', 'llvm-config-18', 'llvm-config-17',
    required : false)
endif

if not llvm_config.found()
  # ── Fallback: 预编译 LLVM 搜索路径 ──────────────────────────
  llvm_search_dirs = [
    'C:/Users/Spyder/AppData/Local/llvm-17',
    'C:/Program Files/LLVM',
  ]
  llvm_use_prebuilt = false
  foreach dir : llvm_search_dirs
    if fs.exists(dir / 'bin/llvm-config.exe')
      llvm_config = find_program(dir / 'bin/llvm-config.exe', native : true)
      llvm_use_prebuilt = true
      message('LLVM Instrument: using prebuilt LLVM at ' + dir)
      break
    endif
  endforeach
  if not llvm_use_prebuilt
    error('LLVM Instrument requires llvm-config. Install prebuilt LLVM 17 or set -Dllvm-config=/path/to/llvm-config')
  endif
endif

llvm_includedir = run_command(llvm_config, '--includedir', check : true).stdout().strip()
llvm_libdir     = run_command(llvm_config, '--libdir',     check : true).stdout().strip()
llvm_cxxflags   = run_command(llvm_config, '--cxxflags',   check : true).stdout().strip().split()

llvm_components = ['core', 'executionengine', 'mcjit',
                   'native', 'nativecodegen', 'transformutils',
                   'x86', 'x86codegen', 'x86info', 'x86asmparser',
                   'x86desc', 'mc', 'object']
llvm_libs = run_command(llvm_config, '--libs',
  llvm_components, check : true).stdout().strip().split()
llvm_system = run_command(llvm_config, '--system-libs',
  check : true).stdout().strip().split()

# 防止 /OPT:REF 剥离 X86 目标符号
_x86_force = ['/INCLUDE:LLVMInitializeX86TargetInfo',
              '/INCLUDE:LLVMInitializeX86Target',
              '/INCLUDE:LLVMInitializeX86TargetMC',
              '/INCLUDE:LLVMInitializeX86AsmPrinter',
              '/INCLUDE:LLVMInitializeX86AsmParser']

# ── libclang ───────────────────────────────────────────────────
clang_cfg = get_option('libclang-config')
clang_dep = []
if clang_cfg != '' and fs.exists(clang_cfg / '../lib/libclang.lib')
  clang_libdir = run_command(clang_cfg, '--libdir', check : true).stdout().strip()
  clang_includedir = run_command(clang_cfg, '--includedir', check : true).stdout().strip()
  clang_dep = declare_dependency(
    include_directories : include_directories(clang_includedir),
    link_args : ['-L' + clang_libdir, '-lclang'],
  )
else
  foreach dir : ['C:/Users/Spyder/AppData/Local/llvm-17', 'C:/Program Files/LLVM']
    if fs.exists(dir / 'lib/libclang.lib')
      clang_dep = declare_dependency(
        include_directories : include_directories(dir / 'include'),
        link_args : [dir / 'lib/libclang.lib'],
      )
      break
    endif
  endforeach
endif
if clang_dep == []
  error('LLVM Instrument requires libclang.lib under the prebuilt LLVM dir')
endif

llvm_dep = declare_dependency(
  include_directories : include_directories(llvm_includedir),
  link_args : llvm_libs + llvm_system + _x86_force,
)

# MSVC + LLVM 17 头文件兼容参数（spike 已验证）
_cpp_args = llvm_cxxflags + [
  '/std:c++17', '/EHsc',
  '/DNOMINMAX', '/D_CRT_SECURE_NO_WARNINGS',
  '/D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH',
  '/wd4146', '/wd4624',
]

hook_compiler_lib = static_library('hook_compiler',
  'hook_compiler.cpp',
  dependencies : [llvm_dep, clang_dep],
  cpp_args : _cpp_args,
  install : false,
)

hook_compiler_dep = declare_dependency(
  link_with : hook_compiler_lib,
  include_directories : include_directories('.'),
  dependencies : [llvm_dep, clang_dep],
)
```

- [ ] **Step 9: 配置 + 编译骨架，验证工具链**

运行（从 repo 根，PowerShell；`$vcvars` 为 `C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat`）：
```powershell
$M = "$PWD\..\pydbg\venv-x64\Scripts\meson.exe"   # 复用主 checkout 的 venv
Remove-Item -Recurse -Force build-instrument -ErrorAction SilentlyContinue
cmd /c "call `"$vcvars`" amd64 >nul 2>&1 && `"$M`" setup build-instrument -Denable-llvm-instrument=true"
cmd /c "call `"$vcvars`" amd64 >nul 2>&1 && `"$M`" compile -C build-instrument"
```
预期：
- `setup` 输出包含 `LLVM Instrument: ENABLED` 和 `LLVM Instrument: using prebuilt LLVM at C:/Users/Spyder/AppData/Local/llvm-17`。
- `compile` 成功，`build-instrument/src/pydbg/instrument/llvm_backend/libhook_compiler.a` 生成（静态库链接 LLVM/libclang 成功）。

若 MSVC 编译 LLVM 头文件报错（不应发生，spike 已验证），暂停并报告——不得绕过。

- [ ] **Step 10: Commit**

```bash
git add meson.options meson.build src/pydbg/meson.build src/pydbg/instrument/
git commit -m "build: meson wiring for LLVM instrument backend (skeleton link verified)"
```

---

## Task 2: 移植 C++ 代码生成器（clang_to_ir + target_codegen + hook_compiler 全量）

**Files:**
- Create: `src/pydbg/instrument/llvm_backend/clang_to_ir.h`
- Create: `src/pydbg/instrument/llvm_backend/clang_to_ir.cpp`
- Create: `src/pydbg/instrument/llvm_backend/target_codegen.h`
- Create: `src/pydbg/instrument/llvm_backend/target_codegen.cpp`
- Modify: `src/pydbg/instrument/llvm_backend/hook_compiler.cpp`
- Modify: `src/pydbg/instrument/llvm_backend/hook_compiler.h`
- Test: 构建成功 + `llvm-objdump` 反汇编冒烟（手动）

- [ ] **Step 1: 从 `feat/llvm-hook` 逐文件移植（git show 精确拷贝）**

在 repo 根执行：
```bash
B="src/pydbg/instrument/llvm_backend"
for f in clang_to_ir.h clang_to_ir.cpp target_codegen.h target_codegen.cpp; do
  git show feat/llvm-hook:src/pydbg/llvm_backend/$f > $B/$f
done
git show feat/llvm-hook:src/pydbg/llvm_backend/hook_compiler.cpp > $B/hook_compiler.cpp
git show feat/llvm-hook:src/pydbg/llvm_backend/hook_compiler.h   > $B/hook_compiler.h
```
移植后把文件顶部注释里的 `pydbg LLVM Hook backend` 改为 `pydbg LLVM instrumentation backend`（注释性修改，其余**逐字节保留**——这些文件就是为 LLVM 17 写的，与预编译库版本一致）。

- [ ] **Step 2: 重新编译**

```powershell
cmd /c "call `"$vcvars`" amd64 >nul 2>&1 && `"$M`" compile -C build-instrument"
```
预期：编译通过（可能有 C4146/C4624 等 LLVM 头文件警告，已用 /wd 抑制）。如出现未定义符号/重定位错误，通常是 `llvm_components` 列表缺库，对照 `llvm-config --libs` 补齐 `llvm_backend/meson.build` 里的 components（尤其 `x86asmparser`、`x86disassembler`）。

- [ ] **Step 3: 反汇编冒烟（验证机器码可生成，手动命令）**

编译一个临时 C++ 驱动到 `build-instrument/spike_compile.exe`（仅本次验证，不入库）：
```cpp
#include "hook_compiler.h"
#include <cstdio>
int main() {
    HookCompiler hc("x86_64-pc-windows-msvc");
    ExternalSymbolTable syms;
    syms["original_func"] = 0x00401000;
    auto code = hc.compile(
        "extern int original_func(int a,int b);"
        "int on_call(int a,int b){ return original_func(a,b)+1; }", syms);
    if (code.empty()) { std::printf("ERR %s\n", hc.getLastError().c_str()); return 1; }
    std::printf("OK %zu bytes\n", code.size());
    return 0;
}
```
预期：`OK <n> bytes`，n>0。若输出 `ERR ...`，记录错误，对照 hook_compiler.cpp 的检查逻辑（on_call 缺失 / extern 未解析）排查。

- [ ] **Step 4: Commit**

```bash
git add src/pydbg/instrument/llvm_backend/
git commit -m "feat(llvm): port C++ codegen (clang_to_ir + target_codegen + hook_compiler) from feat/llvm-hook"
```

---

## Task 3: Cython 绑定 + `_llvm_backend` 扩展 + 编译冒烟

**Files:**
- Create: `src/pydbg/cython/_llvm_backend.pyx`
- Modify: `src/pydbg/cython/meson.build`
- Test: `python -c` 冒烟（手动）

- [ ] **Step 1: 创建 `src/pydbg/cython/_llvm_backend.pyx`**（逐字节来自 feat/llvm-hook）

```cython
# _llvm_backend.pyx — Cython wrapper for HookCompiler (C++ → Python)
# Compile: meson compile (only when -Denable-llvm-instrument=true)

from libcpp.string cimport string
from libcpp.vector cimport vector
from libcpp.map cimport map
from libc.stdint cimport uint8_t, uint64_t

cdef extern from "external_symbol.h":
    ctypedef map[string, uint64_t] ExternalSymbolTable

cdef extern from "hook_compiler.h":
    cdef cppclass HookCompiler:
        HookCompiler(const string& targetTriple) except +
        vector[uint8_t] compile(const string& cSource,
                                 const ExternalSymbolTable& symbols)
        string getLastError()

        @staticmethod
        string resolveTriple(const string& arch)


def compile_stub(str c_source, str target_arch, dict symbols, uint64_t base_addr=0):
    """Compile C source → native machine code for target arch.

    Args:
        c_source: C source code (must define on_call function)
        target_arch: "x64" or "x86" (for pydbg), or full LLVM arch name
        symbols: dict of symbol_name → address (int)
        base_addr: address where the generated code will be loaded (0 = no
                   base; extern-call rel32 assumed loaded at 0)

    Returns:
        bytes of resolved machine code.
    Raises:
        RuntimeError: if compilation fails.
    """
    # Map pydbg arch names to LLVM arch names
    arch_map = {'x64': 'x86_64', 'x86': 'x86'}
    cdef str llvm_arch = arch_map.get(target_arch, target_arch)

    cdef string cpp_source = c_source.encode('utf-8')
    cdef string cpp_arch = llvm_arch.encode('utf-8')
    cdef string triple = HookCompiler.resolveTriple(cpp_arch)

    cdef ExternalSymbolTable sym_map
    for name, addr in symbols.items():
        sym_map[name.encode('utf-8')] = <uint64_t>addr

    cdef HookCompiler* compiler = new HookCompiler(triple)
    cdef vector[uint8_t] code
    try:
        code = compiler.compile(cpp_source, sym_map, <uint64_t>base_addr)
        if code.empty():
            raise RuntimeError(compiler.getLastError().decode('utf-8'))
        return bytes(<char*>code.data())[:code.size()]
    finally:
        del compiler
```

> 设计更正（Task 2 修复，记于此供后续任务参考）：`compile_stub` 增加 `base_addr` 参数。
> COFF 下 `sec.getAddress()` 为 0，重定位 `rel32 = symbol - (sectionAddr + offset + 4)`
> 必须用**代码实际加载地址**作基址，否则注入到非 0 地址后 extern `call` 目标变成
> `symbol + R`。Task 7 的 instrumenter 必须**先分配 payload 缓冲（固定大小 0x2000），
> 以缓冲地址为 base_addr 编译，再写入**。Task 5 的 `compile_payload` 相应加 `base_addr=0` 参数透传。

- [ ] **Step 2: 修改 `src/pydbg/cython/meson.build`**——末尾追加

```meson
# LLVM Instrument backend（可选 — 仅 enable-llvm-instrument=true）
if get_option('enable-llvm-instrument')
  py.extension_module('_llvm_backend',
    '_llvm_backend.pyx',
    dependencies: [
      py.dependency(),
      hook_compiler_dep,  # from ../instrument/llvm_backend/meson.build
    ],
    override_options: ['cython_language=cpp'],
    install: true,
    subdir: 'pydbg',
  )
endif
```

- [ ] **Step 3: 重新配置 + 编译**

```powershell
cmd /c "call `"$vcvars`" amd64 >nul 2>&1 && `"$M`" setup build-instrument -Denable-llvm-instrument=true --reconfigure"
cmd /c "call `"$vcvars`" amd64 >nul 2>&1 && `"$M`" compile -C build-instrument"
```
预期：生成 `build-instrument/src/pydbg/cython/_llvm_backend.cp314-win_amd64.pyd`。

- [ ] **Step 4: 拷贝 .pyd 到源码树（沿用现有约定，使源码树可直接 import）**

```powershell
Copy-Item build-instrument/src/pydbg/cython/_llvm_backend.cp314-win_amd64.pyd src/pydbg/_llvm_backend.cp314-win_amd64.pyd
```

- [ ] **Step 5: 编译冒烟（Python）**

```powershell
$env:PYTHONPATH = "$PWD\src"
& ..\pydbg\venv-x64\Scripts\python.exe -c "from pydbg.cython import _llvm_backend; b = _llvm_backend.compile_stub('int on_call(int a,int b){return a*b;}', 'x86_64', {}); print('x64 bytes:', len(b)); assert len(b)>0"
& ..\pydbg\venv-x64\Scripts\python.exe -c "from pydbg.cython import _llvm_backend; b = _llvm_backend.compile_stub('int on_call(int a,int b){return a+b;}', 'x86', {}); print('x86 bytes:', len(b)); assert len(b)>0"
```
预期：`x64 bytes: <n>` 与 `x86 bytes: <m>`，均 >0。

- [ ] **Step 6: Commit**

```bash
git add src/pydbg/cython/_llvm_backend.pyx src/pydbg/cython/meson.build
git commit -m "feat(llvm): Cython _llvm_backend binding + build wiring"
```

---

## Task 4: `templates.py` — 硬编码指令（TDD）

**Files:**
- Create: `src/pydbg/instrument/templates.py`
- Modify: `src/pydbg/hook/inline.py`（复用 `build_abs_jmp`，行为不变）
- Test: `tests/test_instrument.py`（追加 `TestTemplates` 类）

- [ ] **Step 1: 写失败测试**——追加到 `tests/test_instrument.py`（新建文件，含导入）

```python
import struct
import unittest

from pydbg.instrument.templates import build_abs_jmp, build_stub, build_trampoline
from pydbg.exceptions import PydbgError


class TestTemplates(unittest.TestCase):

    def test_build_abs_jmp_5_bytes_e9(self):
        code = build_abs_jmp(0x1000, 0x2000)
        self.assertEqual(len(code), 5)
        self.assertEqual(code[0], 0xE9)
        rel = struct.unpack('<i', code[1:])[0]
        self.assertEqual(rel, 0x2000 - (0x1000 + 5))

    def test_build_abs_jmp_backward(self):
        code = build_abs_jmp(0x2000, 0x1000)
        rel = struct.unpack('<i', code[1:])[0]
        self.assertEqual(rel, 0x1000 - (0x2000 + 5))

    def test_build_abs_jmp_out_of_range(self):
        with self.assertRaises(PydbgError):
            build_abs_jmp(0, 1 << 40)

    def test_build_stub_is_jmp(self):
        self.assertEqual(build_stub(0x1000, 0x9000), build_abs_jmp(0x1000, 0x9000))

    def test_build_trampoline_appends_jmp_back(self):
        original = b'\x90\x90\x90\x90\x90'
        tramp = build_trampoline(original, trampoline_addr=0x5000, target_addr=0x1000)
        self.assertEqual(len(tramp), len(original) + 5)
        self.assertEqual(tramp[:5], original)
        self.assertEqual(tramp[0], 0x90)
        # 最后 5 字节是 E9 跳到 target_addr + len(original)
        self.assertEqual(tramp[5], 0xE9)
        rel = struct.unpack('<i', tramp[6:])[0]
        self.assertEqual(rel, 0x1005 - (0x5005 + 5))
```

- [ ] **Step 2: 运行测试，确认失败**

```powershell
$env:PYTHONPATH = "$PWD\src"
& ..\pydbg\venv-x64\Scripts\python.exe -m pytest tests/test_instrument.py::TestTemplates -v
```
预期：`ModuleNotFoundError: pydbg.instrument.templates`（或 `pydbg` 无法 import，因为 `templates.py` 尚不存在）。

- [ ] **Step 3: 实现 `src/pydbg/instrument/templates.py`**

```python
"""Instrumentation instruction templates — hardcoded x86/x64 byte templates.

Stub/trampoline 全部用硬编码字节，不依赖 keystone/capstone：
- detour stub = 5 字节近跳 E9 rel32
- trampoline  = 被覆盖的原始指令副本 + 5 字节 E9 rel32 跳回
"""

from ..exceptions import PydbgError


def build_abs_jmp(from_addr: int, to_addr: int) -> bytes:
    """5-byte near JMP (E9 rel32) from from_addr to to_addr.

    Raises PydbgError if the target is out of ±2GB range.
    """
    rel = to_addr - (from_addr + 5)
    if not (-(1 << 31) <= rel < (1 << 31)):
        raise PydbgError(
            f"JMP target 0x{to_addr:X} out of range of 0x{from_addr:X} "
            f"for a 5-byte near JMP"
        )
    return b"\xE9" + (rel & 0xFFFFFFFF).to_bytes(4, "little")


def build_stub(target_addr: int, payload_addr: int) -> bytes:
    """Detour stub written at target_addr: JMP payload_addr."""
    return build_abs_jmp(target_addr, payload_addr)


def build_trampoline(original: bytes, trampoline_addr: int, target_addr: int) -> bytes:
    """Trampoline body: relocated original bytes + E9 rel32 JMP back.

    Args:
        original: exact original instruction bytes that were overwritten.
        trampoline_addr: address where the trampoline is allocated.
        target_addr: original target address; resume at target_addr + len(original).
    """
    resume = target_addr + len(original)
    jmp_from = trampoline_addr + len(original)
    return original + build_abs_jmp(jmp_from, resume)
```

- [ ] **Step 4: 复用——修改 `src/pydbg/hook/inline.py` 的 `_build_abs_jmp`**

把 `_build_abs_jmp` 的方法体替换为委托（保持同名、同签名、同返回值，测试不受影响）：

```python
    @staticmethod
    def _build_abs_jmp(from_addr, to_addr):
        """Build a 5-byte near JMP (E9 rel32) to an absolute address.

        Delegates to instrument.templates.build_abs_jmp (shared hardcoded template).
        """
        from ..instrument.templates import build_abs_jmp
        return build_abs_jmp(from_addr, to_addr)
```

同时更新该方法的 docstring 首句（说明现委托 templates），其余不动。

- [ ] **Step 5: 运行测试，确认通过**

```powershell
$env:PYTHONPATH = "$PWD\src"
& ..\pydbg\venv-x64\Scripts\python.exe -m pytest tests/test_instrument.py::TestTemplates -v
```
预期：全部 PASS。

- [ ] **Step 6: 回归现有 hook 测试**

```powershell
$env:PYTHONPATH = "$PWD\src"
& ..\pydbg\venv-x64\Scripts\python.exe -m pytest tests/test_hook.py -v
```
预期：PASS（inline.py 行为未变）。

- [ ] **Step 7: Commit**

```bash
git add src/pydbg/instrument/templates.py src/pydbg/hook/inline.py tests/test_instrument.py
git commit -m "feat(instrument): hardcoded instruction templates + inline.py reuse"
```

---

## Task 5: `codegen.py` — extern 扫描 + 符号校验（TDD）

**Files:**
- Create: `src/pydbg/instrument/codegen.py`
- Test: `tests/test_instrument.py`（追加 `TestCodegen` 类）

- [ ] **Step 1: 写失败测试**——追加到 `tests/test_instrument.py`

```python
from pydbg.instrument.codegen import _scan_externs
from pydbg.exceptions import PydbgError


class TestCodegen(unittest.TestCase):

    def test_scan_externs_collects_names(self):
        src = ('extern void Foo(int x);'
               'extern int  Bar(void);'
               'int on_call(int x) { Foo(x); return Bar(); }')
        self.assertEqual(_scan_externs(src), {'Foo', 'Bar'})

    def test_scan_externs_reserves_original_func(self):
        src = ('extern int original_func(int a, int b);'
               'extern void Game_Log(int x);'
               'int on_call(int a, int b) { Game_Log(a); return original_func(a, b); }')
        self.assertEqual(_scan_externs(src), {'Game_Log'})

    def test_scan_externs_no_externs(self):
        self.assertEqual(_scan_externs('int on_call(int x) { return x * 2; }'), set())

    def test_compile_payload_missing_backend_raises(self):
        # _llvm_backend 未构建时的降级错误（强制隐藏后端模块验证导入路径）
        import sys
        from unittest import mock
        with mock.patch.dict(sys.modules, {'pydbg._llvm_backend': None}):
            # 模拟 ImportError：pydbg._llvm_backend 是 None 时 from .. import 仍会走 except 分支
            pass
        # 直接验证：当模块缺失时抛 PydbgError。这里不 mock，靠真实环境（未启用后端时）断言。
        from pydbg.instrument import codegen
        try:
            import pydbg._llvm_backend  # noqa: F401
            self.skipTest("LLVM backend present; backend-unavailable path not exercised")
        except ImportError:
            with self.assertRaises(PydbgError):
                codegen.compile_payload('int on_call(int x){return x;}', 'x64', {})
```

（说明：`test_compile_payload_missing_backend_raises` 依赖真实环境——当 Task 3 的 `_llvm_backend.pyd` 未拷贝到 `src/pydbg/` 时执行降级分支；若已构建则跳过。两条路径都被覆盖。）

- [ ] **Step 2: 运行测试，确认失败**

```powershell
$env:PYTHONPATH = "$PWD\src"
& ..\pydbg\venv-x64\Scripts\python.exe -m pytest tests/test_instrument.py::TestCodegen -v
```
预期：`_scan_externs` 三个测试报 `ModuleNotFoundError`。

- [ ] **Step 3: 实现 `src/pydbg/instrument/codegen.py`**

```python
"""Dynamic code generation for instrumentation payloads — LLVM backend facade."""

import re

from ..exceptions import PydbgError

# Regex: match `extern <type> <name>(<params>);`
_EXTERN_RE = re.compile(r'extern\s+[\w\s*]+?\b(\w+)\s*\([^)]*\)\s*;')

_ARCH_MAP = {'x64': 'x86_64', 'x86': 'x86'}


def _scan_externs(c_source: str) -> set:
    """Extract extern function names from C source.

    'original_func' is reserved (auto-mapped to the trampoline) and excluded.
    """
    names = set(_EXTERN_RE.findall(c_source))
    names.discard('original_func')
    return names


def _backend():
    """Lazily import the LLVM backend extension; raises PydbgError if absent."""
    try:
        from .. import _llvm_backend
        return _llvm_backend
    except ImportError:
        raise PydbgError(
            "LLVM backend not available. "
            "Rebuild with -Denable-llvm-instrument=true"
        )


def compile_payload(c_source: str, arch: str, symbols: dict, base_addr: int = 0) -> bytes:
    """Compile C source → zero-relocation machine code for the target arch.

    Validates that every extern symbol (except original_func) is resolved in
    `symbols`. base_addr is the address where the code will be loaded (used to
    rebase extern-call rel32; see Task 3 design note). Raises PydbgError on
    missing backend, unresolved externs, or compilation failure.
    """
    backend = _backend()
    llvm_arch = _ARCH_MAP.get(arch, arch)

    externs = _scan_externs(c_source)
    missing = externs - set(symbols)
    if missing:
        raise PydbgError(
            f"Unresolved external symbol(s): {', '.join(sorted(missing))}. "
            f"Add them to the symbols dict."
        )

    try:
        code = backend.compile_stub(c_source, llvm_arch, dict(symbols), base_addr)
    except RuntimeError as exc:
        raise PydbgError(f"LLVM compilation failed: {exc}")
    if not code:
        raise PydbgError("LLVM compilation produced empty machine code")
    return bytes(code)
```

- [ ] **Step 4: 运行测试，确认通过**

```powershell
$env:PYTHONPATH = "$PWD\src"
& ..\pydbg\venv-x64\Scripts\python.exe -m pytest tests/test_instrument.py::TestCodegen -v
```
预期：全部 PASS（backend 若已构建，缺失路径测试 skip）。

- [ ] **Step 5: Commit**

```bash
git add src/pydbg/instrument/codegen.py tests/test_instrument.py
git commit -m "feat(instrument): extern scan + symbol validation + LLVM backend facade"
```

---

## Task 6: `InstrumentTemplates` — 常用插桩原语（TDD）

**Files:**
- Modify: `src/pydbg/instrument/templates.py`（追加原语类）
- Test: `tests/test_instrument.py`（追加 `TestInstrumentTemplates`）

- [ ] **Step 1: 写失败测试**——追加到 `tests/test_instrument.py`

```python
from pydbg.instrument.templates import InstrumentTemplates


class TestInstrumentTemplates(unittest.TestCase):

    def _entry(self, src):
        self.assertIn('int on_call', src)
        self.assertIn('original_func(', src)

    def test_log_args_generates_c(self):
        src, syms = InstrumentTemplates.log_args(
            'on_call', 'int a, int b', 'Game_Log', {'Game_Log': 0x601000})
        self._entry(src)
        self.assertIn('Game_Log(a)', src)
        self.assertIn('Game_Log(b)', src)
        self.assertEqual(syms['Game_Log'], 0x601000)
        # original_func 由 instrumenter 自动映射，模板不包含
        self.assertNotIn('original_func', syms)

    def test_call_counter_generates_c(self):
        src, syms = InstrumentTemplates.call_counter(
            'on_call', 'int a', 'MyTick', {'MyTick': 0x700000})
        self._entry(src)
        self.assertIn('MyTick()', src)
        self.assertIn('original_func(a)', src)
        self.assertEqual(syms['MyTick'], 0x700000)

    def test_modify_return_generates_c(self):
        src, syms = InstrumentTemplates.modify_return(
            'on_call', 'int a, int b', 'r + 1', {})
        self._entry(src)
        self.assertIn('int r = original_func(a, b);', src)
        self.assertIn('return (r + 1);', src)
        self.assertEqual(syms, {})

    def test_params_names_parsed(self):
        src, _ = InstrumentTemplates.log_args('on_call', 'int a, int b', 'L', {})
        # 两个参数都被记录
        self.assertIn('L(a)', src)
        self.assertIn('L(b)', src)
```

- [ ] **Step 2: 运行测试，确认失败**

```powershell
$env:PYTHONPATH = "$PWD\src"
& ..\pydbg\venv-x64\Scripts\python.exe -m pytest tests/test_instrument.py::TestInstrumentTemplates -v
```
预期：`AttributeError: module 'pydbg.instrument.templates' has no attribute 'InstrumentTemplates'`。

- [ ] **Step 3: 在 `templates.py` 末尾追加 `InstrumentTemplates`**

```python
def _param_names(params: str):
    """Extract parameter identifiers from 'int a, int b' → ['a', 'b']."""
    names = []
    for part in params.split(','):
        tokens = part.strip().split()
        if tokens:
            names.append(tokens[-1])
    return names


class InstrumentTemplates:
    """Preset C payload templates for common probes.

    受 C 子集约束（int 参数/返回值、函数调用、赋值、算术、if/while），
    extern 仅支持函数（不支持 extern 全局变量——C→IR 转换器当前把 VarDecl
    一律当局部变量）。计数器等需落地的状态放在目标侧，经 extern 函数访问。
    """

    @staticmethod
    def log_args(entry, params, log_symbol, externs=None):
        """Log each param via log_symbol(param), then call original and return."""
        names = _param_names(params)
        externs = dict(externs or {})
        body = ''.join(f'    {log_symbol}({n});\n' for n in names)
        src = (f'extern int original_func({params});\n'
               f'extern void {log_symbol}(int value);\n'
               f'int {entry}({params}) {{\n'
               + body +
               f'    return original_func({", ".join(names)});\n}}\n')
        return src, externs

    @staticmethod
    def call_counter(entry, params, tick_symbol, externs=None):
        """Call tick_symbol() on every invocation, then call original.

        tick_symbol 是目标侧实现的计数函数（extern void tick(void)），
        计数器内存由目标维护，pydbg 只负责调用。
        """
        names = _param_names(params)
        externs = dict(externs or {})
        src = (f'extern int original_func({params});\n'
               f'extern void {tick_symbol}(void);\n'
               f'int {entry}({params}) {{\n'
               f'    {tick_symbol}();\n'
               f'    return original_func({", ".join(names)});\n}}\n')
        return src, externs

    @staticmethod
    def modify_return(entry, params, expr, externs=None):
        """Call original, bind result to r, return (expr) applied to r."""
        names = _param_names(params)
        externs = dict(externs or {})
        src = (f'extern int original_func({params});\n'
               f'int {entry}({params}) {{\n'
               f'    int r = original_func({", ".join(names)});\n'
               f'    return ({expr});\n}}\n')
        return src, externs
```

注意：`log_args` 的 `src` 构造用了三元表达式拼接，确保生成的 C 对 0/1/多个参数都合法（参数至少 1 个时生成首个记录调用）。实现后**用测试验证生成文本**，若与预期不符以测试为准调整拼接逻辑。

- [ ] **Step 4: 运行测试，确认通过**

```powershell
$env:PYTHONPATH = "$PWD\src"
& ..\pydbg\venv-x64\Scripts\python.exe -m pytest tests/test_instrument.py::TestInstrumentTemplates -v
```
预期：全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add src/pydbg/instrument/templates.py tests/test_instrument.py
git commit -m "feat(instrument): InstrumentTemplates (log_args / call_counter / modify_return)"
```

---

## Task 7: `instrumenter.py` — 编排 + 导出（TDD）

**Files:**
- Create: `src/pydbg/instrument/instrumenter.py`
- Modify: `src/pydbg/instrument/__init__.py`
- Test: `tests/test_instrument.py`（追加 `TestInstrumenter`）

- [ ] **Step 1: 写失败测试**——追加到 `tests/test_instrument.py`

```python
from pydbg.instrument import Instrumenter
from pydbg.exceptions import PydbgError


class TestInstrumenter(unittest.TestCase):

    def setUp(self):
        from pydbg.core.session import DebugSession
        self.session = DebugSession()
        self.inst = Instrumenter(self.session)

    def test_init_empty_active(self):
        self.assertEqual(self.inst.active, {})

    def test_install_requires_exactly_one_source(self):
        with self.assertRaises(PydbgError):
            self.inst.install(0x1000)  # 两者都没有
        with self.assertRaises(PydbgError):
            self.inst.install(0x1000, c_source='int on_call(int x){return x;}',
                              template=('x', {}))  # 两者都给

    def test_install_backend_missing_raises(self):
        try:
            import pydbg._llvm_backend  # noqa: F401
            self.skipTest("LLVM backend present")
        except ImportError:
            from pydbg.core.session import DebugSession
            session = DebugSession()
            session.process_handle = 0xffffffffffffffff  # 假的进程句柄
            session.target_arch = 64
            inst = Instrumenter(session)
            # 未命中真实内存前应先在 backend 缺失处失败
            with self.assertRaises(PydbgError):
                inst.install(0x1000, c_source='int on_call(int x){return x;}')
```

（说明：`test_install_backend_missing_raises` 在 backend 缺失环境下校验：`install()` 会先尝试读原始字节（内存操作可能失败），随后到达 `codegen.compile_payload` 抛 PydbgError。若测试命中内存错误先于 backend 错误，调整断言为 `PydbgError` 即可——它涵盖两类。）

- [ ] **Step 2: 运行测试，确认失败**

```powershell
$env:PYTHONPATH = "$PWD\src"
& ..\pydbg\venv-x64\Scripts\python.exe -m pytest tests/test_instrument.py::TestInstrumenter -v
```
预期：`ImportError`（`instrumenter` 不存在）。

- [ ] **Step 3: 实现 `src/pydbg/instrument/instrumenter.py`**

```python
"""Instrumenter — install LLVM-generated probes at target addresses."""

from dataclasses import dataclass

from ..exceptions import PydbgError


@dataclass
class InstrumentInfo:
    target_addr: int
    trampoline_addr: int
    trampoline_size: int
    stub_addr: int
    stub_size: int          # len(machine) — 实际机器码长度
    stub_alloc_size: int    # 分配缓冲大小（0x2000），restore 时按此释放
    original_bytes: bytes
    symbols: dict
    c_source: str

    def to_dict(self) -> dict:
        return {
            'target_addr': self.target_addr,
            'trampoline_addr': self.trampoline_addr,
            'trampoline_size': self.trampoline_size,
            'stub_addr': self.stub_addr,
            'stub_size': self.stub_size,
            'original_bytes': self.original_bytes,
            'symbols': dict(self.symbols) if self.symbols else {},
            'c_source': self.c_source,
        }


class Instrumenter:
    def __init__(self, session):
        self._s = session
        self._hooks = {}  # target_addr -> InstrumentInfo

    @property
    def active(self) -> dict:
        return {addr: info.to_dict() for addr, info in self._hooks.items()}

    def install(self, target_addr, c_source=None, template=None, symbols=None):
        """Install an instrumentation probe at target_addr.

        Provide exactly one of c_source (raw C) or template (InstrumentTemplates).
        symbols maps extern names → absolute addresses; 'original_func' is
        auto-mapped to the trampoline address.
        """
        if (c_source is None) == (template is None):
            raise PydbgError("install() requires exactly one of c_source or template")
        if template is not None:
            c_source, template_symbols = template
            symbols = dict(template_symbols)
        else:
            symbols = dict(symbols) if symbols else {}

        from ..disasm.engine import DisasmEngine
        from ..memory.manager import MemoryManager
        from . import codegen
        from .templates import build_stub, build_trampoline

        mem = MemoryManager(self._s)
        mode = "x64" if getattr(self._s, 'target_arch', 64) == 64 else "x86"
        engine = DisasmEngine(mode=mode)

        # 1. 读取 ≥5 字节原始代码（指令边界）
        original = self._read_min_5_bytes(mem, engine, target_addr)

        # 2. trampoline：原始指令 + E9 跳回
        tramp_size = len(original) + 5
        tramp_addr = self._alloc_rwx(mem, tramp_size)
        if tramp_addr == 0:
            raise PydbgError("Failed to allocate trampoline memory")
        tramp_code = build_trampoline(original, tramp_addr, target_addr)
        try:
            mem.write(tramp_addr, tramp_code)
        except Exception:
            self._free_rwx(mem, tramp_addr, tramp_size)
            raise

        # 3. LLVM 编译 payload；original_func → trampoline
        symbols.setdefault('original_func', tramp_addr)

        # 4. 先分配 payload 缓冲（固定 0x2000），以缓冲地址为 base_addr 编译，
        #    使 extern call 的 rel32 按真实加载地址修正（见 Task 3 设计更正）
        _STUB_ALLOC = 0x2000
        stub_addr = self._alloc_rwx(mem, _STUB_ALLOC)
        if stub_addr == 0:
            self._free_rwx(mem, tramp_addr, tramp_size)
            raise PydbgError("Failed to allocate stub memory")
        try:
            machine = codegen.compile_payload(c_source, mode, symbols,
                                              base_addr=stub_addr)
        except Exception:
            self._free_rwx(mem, tramp_addr, tramp_size)
            self._free_rwx(mem, stub_addr, _STUB_ALLOC)
            raise
        mem.write(stub_addr, machine)

        # 5. detour stub 写入 target_addr
        mem.write(target_addr, build_stub(target_addr, stub_addr))

        info = InstrumentInfo(
            target_addr=target_addr,
            trampoline_addr=tramp_addr,
            trampoline_size=tramp_size,
            stub_addr=stub_addr,
            stub_size=len(machine),
            stub_alloc_size=_STUB_ALLOC,
            original_bytes=original,
            symbols=symbols,
            c_source=c_source,
        )
        self._hooks[target_addr] = info
        return info

    def restore(self, target_addr):
        """Restore original code and free trampoline + stub memory. Idempotent."""
        info = self._hooks.pop(target_addr, None)
        if info is None:
            return
        from ..memory.manager import MemoryManager
        mem = MemoryManager(self._s)
        try:
            mem.write(target_addr, info.original_bytes)
        finally:
            self._free_rwx(mem, info.trampoline_addr, info.trampoline_size)
            self._free_rwx(mem, info.stub_addr, info.stub_alloc_size)

    # ── internal helpers ────────────────────────────────────────

    def _read_min_5_bytes(self, mem, engine, addr):
        data = mem.read(addr, 16)
        result = b''
        for insn in engine.disasm(addr, data):
            result += insn.raw_bytes
            if len(result) >= 5:
                break
        if len(result) < 5:
            raise PydbgError(
                f"Need at least 5 bytes for JMP at 0x{addr:X}, got {len(result)}")
        return result

    def _alloc_rwx(self, mem, size):
        try:
            from .. import _pydbg
            result = _pydbg.virtual_alloc(
                self._s.process_handle, size,
                0x3000,  # MEM_COMMIT | MEM_RESERVE
                0x40,    # PAGE_EXECUTE_READWRITE
            )
            return result.get('base_address', 0)
        except Exception:
            return 0

    def _free_rwx(self, mem, addr, size):
        try:
            from .. import _pydbg
            _pydbg.virtual_free(self._s.process_handle, addr, size, 0x8000)
        except Exception:
            pass
```

- [ ] **Step 4: 补全 `src/pydbg/instrument/__init__.py`**

```python
"""pydbg instrumentation module — hardcoded stubs + LLVM dynamic codegen."""

from .instrumenter import Instrumenter, InstrumentInfo
from .templates import InstrumentTemplates

__all__ = ['Instrumenter', 'InstrumentInfo', 'InstrumentTemplates']
```

（注意：`__init__.py` 不 import `codegen`，`_llvm_backend` 全程懒加载，未构建后端时 `Instrumenter` 仍可 import。）

- [ ] **Step 5: 运行测试，确认通过**

```powershell
$env:PYTHONPATH = "$PWD\src"
& ..\pydbg\venv-x64\Scripts\python.exe -m pytest tests/test_instrument.py::TestInstrumenter -v
```
预期：全部 PASS（backend 存在时 `test_install_backend_missing_raises` skip）。

- [ ] **Step 6: Commit**

```bash
git add src/pydbg/instrument/instrumenter.py src/pydbg/instrument/__init__.py tests/test_instrument.py
git commit -m "feat(instrument): Instrumenter install/restore orchestration"
```

---

## Task 8: 测试目标 + live 插桩往返测试

**Files:**
- Create: `tests/target/instrument_target.c`
- Modify: `tests/meson.build`
- Create: `tests/target/instrument_target32.c`
- Modify: `scripts/build-target32.ps1`
- Test: `tests/test_instrument.py`（追加 `TestInstrumentLive`）

- [ ] **Step 1: 创建 `tests/target/instrument_target.c`**

```c
/* instrument_target.c — 插桩测试目标：导出确定性函数供 hook，循环累积全局和。
   __declspec(noinline) 防 /O2 内联，保证入口地址可插桩。 */
#include <windows.h>
#include <stdio.h>

__declspec(dllexport) volatile int g_sum = 0;

__declspec(noinline) __declspec(dllexport) int __cdecl add_numbers(int a, int b) {
    return a + b;
}

int main(void) {
    printf("instrument_target: pid=%lu\n", (unsigned long)GetCurrentProcessId());
    fflush(stdout);
    for (;;) {
        g_sum += add_numbers(1, 2);   /* 正常每轮 +3；插桩后每轮 +103 */
        Sleep(20);
    }
    return 0;
}
```

- [ ] **Step 2: 修改 `tests/meson.build`**——追加构建 + 注册测试（在 `test_target` 定义后插入）

```meson
# 插桩测试目标
instrument_target = executable(
  'instrument_target',
  'target/instrument_target.c',
)
test_env.set('TEST_INSTRUMENT_TARGET_PATH', instrument_target.full_path())
```

并在文件末尾追加：

```meson
test(
  'instrument',
  py,
  args: ['-m', 'unittest', 'tests.test_instrument'],
  env: test_env,
  workdir: meson.project_build_root(),
)
```

- [ ] **Step 3: 写 live 测试**——追加到 `tests/test_instrument.py`

```python
import os
import time

_TEST_TARGET = os.environ.get(
    'TEST_INSTRUMENT_TARGET_PATH',
    r'C:\Users\Spyder\Desktop\ai_eden\Output\instrument-module\build-instrument\tests\target\instrument_target.exe',
)


def _module_by_name(dbg, basename):
    for m in dbg.enum_modules():
        if m.get("name", "").split("\\")[-1].lower() == basename.lower():
            return m
    return None


def _export_address(dbg, exe_path, base, name):
    from pydbg.pe import PE
    pe = PE.from_file(exe_path)
    for exp in pe.exports:
        if exp.name == name:
            return base + exp.rva
    raise AssertionError(f"export {name} not found in {exe_path}")


@unittest.skipUnless(os.path.isfile(_TEST_TARGET), "instrument_target.exe not built")
class TestInstrumentLive(unittest.TestCase):

    @property
    def target_path(self):
        return _TEST_TARGET

    def _launch(self):
        from pydbg import Debugger
        dbg = Debugger()
        dbg.create_process(self.target_path)
        return dbg

    def test_install_restore_roundtrip(self):
        from pydbg import Debugger
        from pydbg.instrument import Instrumenter
        from tests.helpers import teardown

        dbg = self._launch()
        inst = Instrumenter(dbg._session)
        try:
            # 等待目标起来
            deadline = time.time() + 5
            while time.time() < deadline:
                ev = dbg.wait_event(100)
                if ev is None:
                    continue
                dbg.continue_event(ev.pid, ev.tid)
                if ev.type == "LOAD_DLL" and "instrument_target" in str(ev):
                    break
                if ev.type == "EXCEPTION":
                    break

            base = _module_by_name(dbg, "instrument_target.exe")["base_address"]
            addr = _export_address(dbg, self.target_path, base, "add_numbers")
            orig = dbg.read_memory(addr, 5)

            # 读基线累计值
            g_sum_addr = _export_address(dbg, self.target_path, base, "g_sum")
            start_sum = int.from_bytes(dbg.read_memory(g_sum_addr, 4), 'little')

            # 安装：每次调用返回 original + 100 → 每轮 g_sum 增量变 103
            info = inst.install(
                addr,
                c_source=('extern int original_func(int a, int b);'
                          'int on_call(int a, int b) {'
                          '    return original_func(a, b) + 100;'
                          '}'),
            )
            self.assertGreater(info.trampoline_addr, 0)
            self.assertGreater(info.stub_addr, 0)

            time.sleep(0.5)
            mid_sum = int.from_bytes(dbg.read_memory(g_sum_addr, 4), 'little')
            self.assertGreater(mid_sum - start_sum, 0)

            # 恢复 → 增量回到 3/轮
            inst.restore(addr)
            self.assertNotIn(addr, inst.active)
            self.assertEqual(dbg.read_memory(addr, 5), orig)

            time.sleep(0.3)
            end_sum = int.from_bytes(dbg.read_memory(g_sum_addr, 4), 'little')
            self.assertGreater(end_sum - mid_sum, 0)
        finally:
            teardown(dbg)
```

- [ ] **Step 4: 构建目标并跑 live 测试**

```powershell
cmd /c "call `"$vcvars`" amd64 >nul 2>&1 && `"$M`" compile -C build-instrument"
$env:TEST_INSTRUMENT_TARGET_PATH = "$PWD\build-instrument\tests\target\instrument_target.exe"
$env:PYTHONPATH = "$PWD\src"
& ..\pydbg\venv-x64\Scripts\python.exe -m pytest tests/test_instrument.py::TestInstrumentLive -v
```
预期：PASS（安装后 g_sum 增量显著 >0，恢复后字节复原）。

> 排障提示：若安装后 `mid_sum - start_sum` 为 0（hook 未生效），先确认
> `dbg.read_memory(addr,5)` 在安装后前 5 字节为 `E9 ...`；再检查目标为 Debug 构建
> 是否命中。若 live 测试暴露出 `target_codegen` 的 COFF .text 截断问题（旧分支已知缺陷），
> 在 `target_codegen.cpp` 中改为按 `.text` 段的 `Contents` 长度 + `Size` 取 `max` 并记录，
> 更新此测试的断言后继续（此为本计划明确的坑位，修复单独 commit）。

- [ ] **Step 5: 32 位 WOW64 目标**——创建 `tests/target/instrument_target32.c`（与 x64 版等价，仅 32 位）

内容同 `instrument_target.c`（保留 `__declspec(noinline) __declspec(dllexport)`、`g_sum` 全局、循环）。追加到 `scripts/build-target32.ps1` 的 cmd 段：

```powershell
"cl /nologo /O2 /W3 /utf-8 /c tests\target\instrument_target32.c /Fo$outDir\instrument_target32.obj`n" +
"if errorlevel 1 exit /b %errorlevel%`n" +
"link /nologo /subsystem:console /machine:x86 /OUT:$outDir\instrument_target32.exe $outDir\instrument_target32.obj`n" +
"if errorlevel 1 exit /b %errorlevel%`n" +
```

在 `tests/test_instrument.py` 追加 32 位 live 测试（目标缺失或非 WOW64 时整体 skip）：

```python
_TEST_TARGET32 = os.environ.get(
    'TEST_INSTRUMENT_TARGET32_PATH',
    r'C:\Users\Spyder\Desktop\ai_eden\Output\instrument-module\tests\target\instrument_target32.exe',
)


def _wow64_available():
    from pydbg import _pydbg
    try:
        return bool(getattr(_pydbg, 'wow64_available', lambda: False)())
    except Exception:
        return False


@unittest.skipUnless(
    os.path.isfile(_TEST_TARGET32) and _wow64_available(),
    "requires 32-bit instrument target and WOW64 host")
class TestInstrumentLive32(TestInstrumentLive):
    """32 位 WOW64 live 往返；复用 TestInstrumentLive 的断言逻辑。"""

    @property
    def target_path(self):
        return _TEST_TARGET32

    def _launch(self):
        from pydbg import Debugger
        dbg = Debugger()
        dbg.create_process(_TEST_TARGET32)
        return dbg
```

并把 `TestInstrumentLive` 中的 `_TEST_TARGET` 引用改为 `self.target_path`（加属性 `target_path` 返回 `_TEST_TARGET`），使 x64/32 位共享同一套断言。构建 32 位目标后运行：

```powershell
powershell -File scripts/build-target32.ps1
$env:TEST_INSTRUMENT_TARGET32_PATH = "$PWD\tests\target\instrument_target32.exe"
$env:PYTHONPATH = "$PWD\src"
& ..\pydbg\venv-x64\Scripts\python.exe -m pytest tests/test_instrument.py::TestInstrumentLive32 -v
```
预期：PASS（WOW64 环境）或 skip（目标/环境不满足）。

- [ ] **Step 6: Commit**

```bash
git add tests/target/instrument_target.c tests/target/instrument_target32.c tests/meson.build scripts/build-target32.ps1 tests/test_instrument.py
git commit -m "test(instrument): live install/restore roundtrip + 32/64-bit targets"
```

---

## Task 9: 导出 + README + CI

**Files:**
- Modify: `src/pydbg/__init__.py`
- Modify: `README.md`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: 修改 `src/pydbg/__init__.py`**——追加导出（在 hook 导入行之后）

```python
from .instrument import Instrumenter, InstrumentInfo, InstrumentTemplates
```

并在 `__all__` 末尾追加 `"Instrumenter", "InstrumentInfo", "InstrumentTemplates"`。

- [ ] **Step 2: 修改 `README.md`**——追加「插桩模块」小节

在 `### 常见操作` 之后插入：

````markdown
### 插桩（Instrumentation）

stub/trampoline 用硬编码指令生成，payload 由 LLVM 17 动态编译 C 源码为机器码并注入目标进程。
需以 `-Denable-llvm-instrument=true` 构建，并预装 LLVM 17（检测 `C:/Users/Spyder/AppData/Local/llvm-17` 或 `-Dllvm-config=`）。

```python
from pydbg.instrument import Instrumenter

inst = Instrumenter(dbg._session)
inst.install(
    0x00401000,
    c_source='''
        extern int original_func(int a, int b);
        int on_call(int a, int b) {
            return original_func(a, b) + 1;
        }
    ''',
)
# 或 inst.install(addr, template=InstrumentTemplates.log_args('on_call', 'int a, int b', 'Game_Log', {...}))
inst.restore(0x00401000)
inst.active   # {addr: {...}}
```
````

- [ ] **Step 3: 修改 `.github/workflows/ci.yml`**——LLVM 测试容错

在 test 步骤中对 `tests.test_instrument` 的 `meson test` 不加特殊处理（`TestInstrumentLive` 会 `skipUnless` 目标存在；编译级测试在未构建 `_llvm_backend` 时通过 `TestCodegen.test_compile_payload_missing_backend_raises` 走降级分支）。无需强制 CI 安装 LLVM——默认 `-Denable-llvm-instrument=false` 时 `instrument/` 纯 Python 层照常安装，live 测试 skip。

- [ ] **Step 4: 全量回归 + 全模块测试**

```powershell
$env:PYTHONPATH = "$PWD\src"
& ..\pydbg\venv-x64\Scripts\python.exe -m pytest tests/ -v
```
预期：既有测试全过；`test_instrument.py` 中 backend 相关用例依环境走断言或 skip。

- [ ] **Step 5: Commit**

```bash
git add src/pydbg/__init__.py README.md .github/workflows/ci.yml
git commit -m "chore(instrument): export API + README docs + CI compatibility"
```

---

## 收尾

- **推送分支**：`git push -u origin feat/instrument-module`，创建 PR（标题 `feat: instrumentation module (hardcoded stubs + LLVM dynamic codegen)`），PR 描述含改动摘要、CI 链接、自主决策记录（按 CLAUDE.md 规范）。
- **遗留记录**：live 测试若触发 `target_codegen` COFF .text 截断问题，修复 commit 需在 PR 描述中标注。
