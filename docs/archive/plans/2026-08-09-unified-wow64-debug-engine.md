# pydbg 统一 64 位调试引擎实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 pydbg 归一成单一 x64 宿主调试引擎 —— 用 64 位 Debug API 统一调试 x64 原生目标与 WOW64(32 位) 目标（上下文按目标架构分发、WX86 事件码、硬件断点挂起先行、模块枚举含 32 位模块），并彻底消除 x86 宿主环境依赖。

**Architecture:** Cython 上下文辅助函数改为 machine 感知（`machine==32` 走 `WOW64_CONTEXT` + `Wow64GetThreadContext/SetThreadContext`，否则原生 `CONTEXT` + `GetThreadContext`）。Python 各 manager 把 `session.target_arch` 作为 `machine` 显式传入（方案 1，显式参数）。扩展只编 x64（`win_amd64`），移除 `#ifdef _WIN32` 分支。模块枚举改 `EnumProcessModulesEx(LIST_MODULES_ALL)` + 按 PE 头判定模块 `arch`。事件循环识别 WX86 码 `0x4000001F/0x4000001E`。新增 32 位测试目标（CI 现编译）与 `tests/test_wow64.py` 验证。

**Tech Stack:** Cython 3 + C（MSVC x64）、Meson/Ninja、Python 3.8+（实测 cp314）、Win32 Debug API、psapi、`pydbg.pe` 解析器。

---

## 环境与常用命令（所有任务共用）

- **Worktree**：`C:\Users\Spyder\Desktop\ai_eden\Output\pydbg-wow64-unified`（分支 `feat/unified-wow64-debug-api`）。所有文件改动都在此目录内。
- **构建 Python**：主仓库的 `C:\Users\Spyder\Desktop\ai_eden\Output\pydbg\venv-x64\Scripts\python.exe`（含 meson/ninja/cython/capstone）。
- **构建扩展**（改 Cython 后执行）：
  ```bash
  cd /c/Users/Spyder/Desktop/ai_eden/Output/pydbg-wow64-unified
  ../pydbg/venv-x64/Scripts/meson.exe setup build --buildtype=release
  ../pydbg/venv-x64/Scripts/meson.exe compile -C build
  cp build/src/pydbg/cython/_pydbg.cp314-win_amd64.pyd src/pydbg/
  ```
- **运行测试**（cwd 必须是 worktree 根，`tests` 包才能导入）：
  ```bash
  cd /c/Users/Spyder/Desktop/ai_eden/Output/pydbg-wow64-unified
  PYTHONPATH=src ../pydbg/venv-x64/Scripts/python.exe -m unittest tests.test_thread -v
  ```
  说明：`pydbg` 从 `src/pydbg/__init__.py` 导入，`from ._pydbg import` 需要 `src/pydbg/_pydbg.cp314-win_amd64.pyd`（就是上面 `cp` 拷贝的顶层 .pyd）。venv 的 site-packages 里是陈旧版，PYTHONPATH=src 优先覆盖。
- **构建 32 位测试目标**：`powershell -File scripts/build-target32.ps1`（产物 `tests/target/simple_target32.exe`，被 `.gitignore` 的 `*.exe` 覆盖，不入库）。
- **PowerShell 替代写法**：`$env:PYTHONPATH='src'; ../pydbg/venv-x64/Scripts/python.exe -m unittest tests.test_wow64 -v`

---

### Task 1: 32 位 WOW64 测试目标 + 交叉编译脚本

**Files:**
- Create: `tests/target/simple_target32.c`
- Create: `scripts/build-target32.ps1`
- Modify: `tests/meson.build`

- [ ] **Step 1: 写 32 位测试目标源码**

创建 `tests/target/simple_target32.c`（镜像 `../wow64-dbg-demo/demo/target32/target32.c`：`__declspec(dllexport)` 导出确定性函数 + `noinline` 防内联 + volatile 全局防常量折叠 + 保活循环）：

```c
/* simple_target32.c — 32 位 (WOW64) 测试目标：导出确定性函数供断点/硬件断点/远程校验。
   镜像 wow64-dbg-demo 的 target32.c：__declspec(noinline) 防止 /O2 把导出函数内联/常量
   折叠，否则打在函数入口的 int3/硬件断点永不命中。 */
#include <windows.h>
#include <stdio.h>

__declspec(dllexport) volatile int g_counter = 0;
__declspec(dllexport) volatile unsigned g_tick = 0;
__declspec(dllexport) volatile int g_sum = 0;

__declspec(noinline) __declspec(dllexport) int __cdecl target_add(int a, int b) {
    return a + b;
}
__declspec(noinline) __declspec(dllexport) int __cdecl target_mul_store(int a, int b) {
    g_counter += a * b;
    return g_counter;
}
__declspec(noinline) __declspec(dllexport) int __cdecl target_get_global(void) {
    return g_counter;
}
__declspec(noinline) __declspec(dllexport) void __cdecl target_sleep(int ms) {
    Sleep(ms);
}

int main(void) {
    printf("simple_target32: base=0x%08X pid=%lu\n",
           (unsigned)(DWORD_PTR)GetModuleHandleW(NULL), GetCurrentProcessId());
    fflush(stdout);
    for (;;) {
        Sleep(200);
        target_mul_store(2, 1);
        g_sum += target_add((int)(g_tick & 1), 4);
        g_tick++;
    }
    return 0;
}
```

- [ ] **Step 2: 写交叉编译脚本**

创建 `scripts/build-target32.ps1`（对齐 demo 的 build.ps1：vswhere → `vcvarsall amd64_x86` → cl 编 x86）：

```powershell
# build-target32.ps1 — 用 MSVC x64→x86 交叉工具链编译 32 位 WOW64 测试目标。
# 产物 tests/target/simple_target32.exe 不提交进仓库（*.exe 已 gitignore）。
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) { Write-Host '[error] vswhere not found'; exit 1 }
$vs = & $vswhere -latest -property installationPath
if (-not $vs) { Write-Host '[error] Visual Studio not found'; exit 1 }
$outDir = Join-Path $root 'tests\target'
New-Item -ItemType Directory -Force $outDir | Out-Null
$tmp = Join-Path $root '.build-target32.cmd'
try {
    $bat = "@echo off`n" +
           "call `"$vs\VC\Auxiliary\Build\vcvarsall.bat`" amd64_x86 >nul 2>&1`n" +
           "cd /d `"$root`"`n" +
           "cl /nologo /O2 /W3 /utf-8 /c tests\target\simple_target32.c /Fo$outDir\simple_target32.obj`n" +
           "if errorlevel 1 exit /b %errorlevel%`n" +
           "link /nologo /subsystem:console /machine:x86 /OUT:$outDir\simple_target32.exe $outDir\simple_target32.obj`n" +
           "if errorlevel 1 exit /b %errorlevel%`n" +
           "echo BUILD_OK"
    Set-Content -Path $tmp -Value $bat -Encoding ascii
    & cmd /c "`"$tmp`""
    if ($LASTEXITCODE -ne 0) { Write-Host '[error] build-target32 failed'; exit 1 }
} finally {
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}
Write-Host "[ok] built $outDir\simple_target32.exe"
```

- [ ] **Step 3: 接入 meson 测试环境变量**

修改 `tests/meson.build`，在 `test_env.set('TEST_TARGET_PATH', ...)` 之后加一行：

```meson
test_env.set('TEST_WOW64_TARGET_PATH',
  meson.project_source_root() / 'tests' / 'target' / 'simple_target32.exe')
```

- [ ] **Step 4: 构建目标并验证是 PE32 (x86)**

```bash
cd /c/Users/Spyder/Desktop/ai_eden/Output/pydbg-wow64-unified
powershell -File scripts/build-target32.ps1
../pydbg/venv-x64/Scripts/python.exe -c "import struct; d=open('tests/target/simple_target32.exe','rb').read(); lfanew=struct.unpack_from('<I',d,0x3c)[0]; m=struct.unpack_from('<H',d,lfanew+4)[0]; print('machine=0x%04X'%m); assert m==0x14c, 'expected x86 (0x14c)'"
```
Expected: `machine=0x014C` 且无断言错误（若脚本找不到 VS，先报错排查环境，不跳过）。

- [ ] **Step 5: 提交**

```bash
git add tests/target/simple_target32.c scripts/build-target32.ps1 tests/meson.build
git commit -m "test: add 32-bit WOW64 test target + cross-compile script"
```

---

### Task 2: Cython 上下文层 machine 化（WOW64 路径 + x64 回归）

**Files:**
- Modify: `src/pydbg/cython/_win32types.pxd`
- Modify: `src/pydbg/cython/_thread.pxi`
- Modify: `src/pydbg/cython/_bp.pxi`
- Modify: `src/pydbg/cython/_memory.pxi`

这一步把扩展改成「单一 x64 宿主、按 machine 分发」的基础。完成后 x64 路径行为不变（machine 默认 64），现有测试必须全绿。**含 WOW64 (machine=32) 路径的完整实现**（后续任务无需再改 Cython，只需 Python 端把 machine 传进来）。

- [ ] **Step 1: `_win32types.pxd` — 新增 WOW64 声明**

在 windows.h extern 块（`BOOL GetThreadContext(...)` 附近）加：

```cython
    DWORD WOW64_CONTEXT_ALL
    BOOL Wow64GetThreadContext(HANDLE hThread, void* lpContext)
    BOOL Wow64SetThreadContext(HANDLE hThread, void* lpContext)
```

在 psapi extern 块（`EnumProcessModules` 附近）加：

```cython
    DWORD LIST_MODULES_ALL
    BOOL EnumProcessModulesEx(HANDLE hProcess, HMODULE* lphModule,
                              DWORD cb, DWORD* lpcbNeeded, DWORD dwFilterFlag)
```

- [ ] **Step 2: `_win32types.pxd` — 上下文辅助函数改为 machine 感知**

把 `cdef extern from *:` 内联 C 块整体替换为下面内容（**每个读写函数加 `int machine` 参数**；`machine==32` 按 `WOW64_CONTEXT`（x86 布局）读写，否则按原生 `CONTEXT`（AMD64 布局））：

```c
    #include <windows.h>
    #include <string.h>

    /* 缓冲尺寸：x64 原生 CONTEXT 或 WOW64 (x86) CONTEXT 中较大的一个。
       扩展只编 x64，sizeof(CONTEXT) > sizeof(WOW64_CONTEXT)。 */
    typedef union {
        CONTEXT native;
        WOW64_CONTEXT wow64;
    } pydbg_ctx_buf_t;

    static inline int pydbg_ctx_sizeof(void) { return (int)sizeof(pydbg_ctx_buf_t); }

    /* machine: 32 = WOW64/x86 布局，其它 = x64 布局 */
    static inline void pydbg_ctx_init(void* pctx, int machine, unsigned long flags) {
        memset(pctx, 0, sizeof(pydbg_ctx_buf_t));
        if (machine == 32) ((WOW64_CONTEXT*)pctx)->ContextFlags = flags;
        else ((CONTEXT*)pctx)->ContextFlags = flags;
    }
    static inline unsigned long pydbg_ctx_get_flags(void* pctx, int machine) {
        return machine == 32 ? ((WOW64_CONTEXT*)pctx)->ContextFlags
                             : ((CONTEXT*)pctx)->ContextFlags;
    }
    static inline void pydbg_ctx_set_flags(void* pctx, int machine, unsigned long f) {
        if (machine == 32) ((WOW64_CONTEXT*)pctx)->ContextFlags = f;
        else ((CONTEXT*)pctx)->ContextFlags = f;
    }

    static inline unsigned long long pydbg_ctx_get_ip(void* pctx, int machine) {
        return machine == 32 ? (unsigned long long)((WOW64_CONTEXT*)pctx)->Eip
                             : ((CONTEXT*)pctx)->Rip;
    }
    static inline void pydbg_ctx_set_ip(void* pctx, int machine, unsigned long long v) {
        if (machine == 32) ((WOW64_CONTEXT*)pctx)->Eip = (DWORD)v;
        else ((CONTEXT*)pctx)->Rip = v;
    }
    static inline unsigned long long pydbg_ctx_get_sp(void* pctx, int machine) {
        return machine == 32 ? (unsigned long long)((WOW64_CONTEXT*)pctx)->Esp
                             : ((CONTEXT*)pctx)->Rsp;
    }
    static inline void pydbg_ctx_set_sp(void* pctx, int machine, unsigned long long v) {
        if (machine == 32) ((WOW64_CONTEXT*)pctx)->Esp = (DWORD)v;
        else ((CONTEXT*)pctx)->Rsp = v;
    }
    static inline unsigned long long pydbg_ctx_get_bp(void* pctx, int machine) {
        return machine == 32 ? (unsigned long long)((WOW64_CONTEXT*)pctx)->Ebp
                             : ((CONTEXT*)pctx)->Rbp;
    }
    static inline void pydbg_ctx_set_bp(void* pctx, int machine, unsigned long long v) {
        if (machine == 32) ((WOW64_CONTEXT*)pctx)->Ebp = (DWORD)v;
        else ((CONTEXT*)pctx)->Rbp = v;
    }
    static inline unsigned long pydbg_ctx_get_eflags(void* pctx, int machine) {
        return machine == 32 ? ((WOW64_CONTEXT*)pctx)->EFlags : ((CONTEXT*)pctx)->EFlags;
    }
    static inline void pydbg_ctx_set_eflags(void* pctx, int machine, unsigned long v) {
        if (machine == 32) ((WOW64_CONTEXT*)pctx)->EFlags = v;
        else ((CONTEXT*)pctx)->EFlags = v;
    }

    /* GP 寄存器索引表（两架构统一）：
       x86: 0=Eax 1=Ecx 2=Edx 3=Ebx 4=Esp 5=Ebp 6=Esi 7=Edi
       x64: 0=Rax 1=Rcx 2=Rdx 3=Rbx 4=Rsp 5=Rbp 6=Rsi 7=Rdi 8=R8..15=R15 */
    static inline unsigned long long pydbg_ctx_get_gp(void* pctx, int machine, int idx) {
        if (machine == 32) {
            WOW64_CONTEXT* c = (WOW64_CONTEXT*)pctx;
            switch (idx) {
                case 0: return c->Eax;  case 1: return c->Ecx;
                case 2: return c->Edx;  case 3: return c->Ebx;
                case 4: return c->Esp;  case 5: return c->Ebp;
                case 6: return c->Esi;  case 7: return c->Edi;
            }
            return 0;
        }
        CONTEXT* c = (CONTEXT*)pctx;
        switch (idx) {
            case 0:  return c->Rax;  case 1:  return c->Rcx;
            case 2:  return c->Rdx;  case 3:  return c->Rbx;
            case 4:  return c->Rsp;  case 5:  return c->Rbp;
            case 6:  return c->Rsi;  case 7:  return c->Rdi;
            case 8:  return c->R8;   case 9:  return c->R9;
            case 10: return c->R10;  case 11: return c->R11;
            case 12: return c->R12;  case 13: return c->R13;
            case 14: return c->R14;  case 15: return c->R15;
        }
        return 0;
    }
    static inline void pydbg_ctx_set_gp(void* pctx, int machine, int idx, unsigned long long v) {
        if (machine == 32) {
            WOW64_CONTEXT* c = (WOW64_CONTEXT*)pctx;
            switch (idx) {
                case 0: c->Eax = (DWORD)v; break;  case 1: c->Ecx = (DWORD)v; break;
                case 2: c->Edx = (DWORD)v; break;  case 3: c->Ebx = (DWORD)v; break;
                case 4: c->Esp = (DWORD)v; break;  case 5: c->Ebp = (DWORD)v; break;
                case 6: c->Esi = (DWORD)v; break;  case 7: c->Edi = (DWORD)v; break;
            }
            return;
        }
        CONTEXT* c = (CONTEXT*)pctx;
        switch (idx) {
            case 0:  c->Rax = v; break;  case 1:  c->Rcx = v; break;
            case 2:  c->Rdx = v; break;  case 3:  c->Rbx = v; break;
            case 4:  c->Rsp = v; break;  case 5:  c->Rbp = v; break;
            case 6:  c->Rsi = v; break;  case 7:  c->Rdi = v; break;
            case 8:  c->R8  = v; break;  case 9:  c->R9  = v; break;
            case 10: c->R10 = v; break;  case 11: c->R11 = v; break;
            case 12: c->R12 = v; break;  case 13: c->R13 = v; break;
            case 14: c->R14 = v; break;  case 15: c->R15 = v; break;
        }
    }

    /* 调试寄存器 Dr0-3, Dr6, Dr7（索引 0,1,2,3,6,7） */
    static inline unsigned long long pydbg_ctx_get_dr(void* pctx, int machine, int reg) {
        WOW64_CONTEXT* w = (WOW64_CONTEXT*)pctx;
        CONTEXT* n = (CONTEXT*)pctx;
        if (machine == 32) {
            switch (reg) {
                case 0: return w->Dr0;  case 1: return w->Dr1;
                case 2: return w->Dr2;  case 3: return w->Dr3;
                case 6: return w->Dr6;  case 7: return w->Dr7;
            }
            return 0;
        }
        switch (reg) {
            case 0: return n->Dr0;  case 1: return n->Dr1;
            case 2: return n->Dr2;  case 3: return n->Dr3;
            case 6: return n->Dr6;  case 7: return n->Dr7;
        }
        return 0;
    }
    static inline void pydbg_ctx_set_dr(void* pctx, int machine, int reg, unsigned long long v) {
        if (machine == 32) {
            WOW64_CONTEXT* c = (WOW64_CONTEXT*)pctx;
            switch (reg) {
                case 0: c->Dr0 = (DWORD)v; break;  case 1: c->Dr1 = (DWORD)v; break;
                case 2: c->Dr2 = (DWORD)v; break;  case 3: c->Dr3 = (DWORD)v; break;
                case 6: c->Dr6 = (DWORD)v; break;  case 7: c->Dr7 = (DWORD)v; break;
            }
            return;
        }
        CONTEXT* c = (CONTEXT*)pctx;
        switch (reg) {
            case 0: c->Dr0 = v; break;  case 1: c->Dr1 = v; break;
            case 2: c->Dr2 = v; break;  case 3: c->Dr3 = v; break;
            case 6: c->Dr6 = v; break;  case 7: c->Dr7 = v; break;
        }
    }

    /* 段寄存器：0=CS 1=DS 2=ES 3=FS 4=GS 5=SS */
    static inline unsigned short pydbg_ctx_get_seg(void* pctx, int machine, int reg) {
        WOW64_CONTEXT* w = (WOW64_CONTEXT*)pctx;
        CONTEXT* n = (CONTEXT*)pctx;
        switch (reg) {
            case 0: return machine == 32 ? w->SegCs : n->SegCs;
            case 1: return machine == 32 ? w->SegDs : n->SegDs;
            case 2: return machine == 32 ? w->SegEs : n->SegEs;
            case 3: return machine == 32 ? w->SegFs : n->SegFs;
            case 4: return machine == 32 ? w->SegGs : n->SegGs;
            case 5: return machine == 32 ? w->SegSs : n->SegSs;
        }
        return 0;
    }

    /* 宿主架构：扩展只编 x64，恒为 64 */
    static inline int pydbg_host_arch(void) { return 64; }
    """

把对应声明块（`int pydbg_ctx_sizeof()` 到 `int pydbg_host_arch()`）替换为：

```cython
    int pydbg_ctx_sizeof()
    void pydbg_ctx_init(void* pctx, int machine, unsigned long flags)
    unsigned long pydbg_ctx_get_flags(void* pctx, int machine)
    void pydbg_ctx_set_flags(void* pctx, int machine, unsigned long f)
    unsigned long long pydbg_ctx_get_ip(void* pctx, int machine)
    void pydbg_ctx_set_ip(void* pctx, int machine, unsigned long long v)
    unsigned long long pydbg_ctx_get_sp(void* pctx, int machine)
    void pydbg_ctx_set_sp(void* pctx, int machine, unsigned long long v)
    unsigned long long pydbg_ctx_get_bp(void* pctx, int machine)
    void pydbg_ctx_set_bp(void* pctx, int machine, unsigned long long v)
    unsigned long pydbg_ctx_get_eflags(void* pctx, int machine)
    void pydbg_ctx_set_eflags(void* pctx, int machine, unsigned long v)
    unsigned long long pydbg_ctx_get_gp(void* pctx, int machine, int idx)
    void pydbg_ctx_set_gp(void* pctx, int machine, int idx, unsigned long long v)
    unsigned long long pydbg_ctx_get_dr(void* pctx, int machine, int reg)
    void pydbg_ctx_set_dr(void* pctx, int machine, int reg, unsigned long long v)
    unsigned short pydbg_ctx_get_seg(void* pctx, int machine, int reg)
    int pydbg_host_arch()
```

- [ ] **Step 3: `_thread.pxi` — machine 感知的 get/set_thread_context**

把 cimport 块加 `Wow64GetThreadContext, Wow64SetThreadContext, WOW64_CONTEXT_ALL`。

替换 `get_thread_context`（第 50-94 行）为：

```cython
cpdef dict get_thread_context(unsigned long long h_thread, int machine=64):
    """Get thread register context.

    machine: 32 = WOW64 (x86) target, 64 = native x64 target (default).
    Returns dict of register name -> value with architecture-appropriate
    names (rax/rsp/rip on x64, eax/esp/eip on x86) plus 'arch'.
    Raises OSError on failure.
    """
    cdef int ctx_size = pydbg_ctx_sizeof()
    cdef void* ctx = malloc(ctx_size)
    if ctx == NULL:
        raise MemoryError("Failed to allocate CONTEXT")
    cdef unsigned long flags
    cdef BOOL result
    if machine == 32:
        flags = WOW64_CONTEXT_ALL
        pydbg_ctx_init(ctx, machine, flags)
        result = Wow64GetThreadContext(<HANDLE><LPVOID>h_thread, ctx)
    else:
        flags = CONTEXT_ALL
        pydbg_ctx_init(ctx, machine, flags)
        result = GetThreadContext(<HANDLE><LPVOID>h_thread, ctx)
    if result == 0:
        free(ctx)
        raise OSError(GetLastError(), "GetThreadContext failed")

    cdef list gp_names
    cdef str ip_name
    cdef str arch
    if machine == 32:
        gp_names = _GP_NAMES_X86
        ip_name = 'eip'
        arch = 'x86'
    else:
        gp_names = _GP_NAMES_X64
        ip_name = 'rip'
        arch = 'x64'

    cdef dict out = {}
    cdef int i
    for i in range(len(gp_names)):
        out[gp_names[i]] = pydbg_ctx_get_gp(ctx, machine, i)
    out[ip_name] = pydbg_ctx_get_ip(ctx, machine)
    out['eflags'] = pydbg_ctx_get_eflags(ctx, machine)
    for dr in _DR_SLOTS:
        out[f'dr{dr}'] = pydbg_ctx_get_dr(ctx, machine, dr)
    for i, name in enumerate(_SEG_NAMES):
        out[name] = pydbg_ctx_get_seg(ctx, machine, i)
    out['arch'] = arch
    free(ctx)
    return out
```

替换 `set_thread_context`（第 97-157 行）为：

```cython
cpdef int set_thread_context(unsigned long long h_thread, dict context, int machine=64) except? -1:
    """Set thread register context.

    machine: 32 = WOW64 (x86) target, 64 = native x64 target (default).
    Accepts both x64 (rax/rip/...) and x86 (eax/eip/...) register names;
    only registers present in the dict are updated.
    Raises OSError on failure.
    """
    cdef int ctx_size = pydbg_ctx_sizeof()
    cdef void* ctx = malloc(ctx_size)
    if ctx == NULL:
        raise MemoryError("Failed to allocate CONTEXT")
    cdef unsigned long flags
    cdef BOOL result
    if machine == 32:
        flags = WOW64_CONTEXT_ALL
        pydbg_ctx_init(ctx, machine, flags)
        result = Wow64GetThreadContext(<HANDLE><LPVOID>h_thread, ctx)
    else:
        flags = CONTEXT_ALL
        pydbg_ctx_init(ctx, machine, flags)
        result = GetThreadContext(<HANDLE><LPVOID>h_thread, ctx)
    if result == 0:
        free(ctx)
        raise OSError(GetLastError(), "GetThreadContext failed (before set)")

    cdef list gp_names
    if machine == 32:
        gp_names = _GP_NAMES_X86
    else:
        gp_names = _GP_NAMES_X64

    # IP / SP / BP / GP by machine
    if machine == 32:
        if 'eip' in context: pydbg_ctx_set_ip(ctx, machine, context['eip'])
        if 'esp' in context: pydbg_ctx_set_sp(ctx, machine, context['esp'])
        if 'ebp' in context: pydbg_ctx_set_bp(ctx, machine, context['ebp'])
    else:
        if 'rip' in context: pydbg_ctx_set_ip(ctx, machine, context['rip'])
        if 'rsp' in context: pydbg_ctx_set_sp(ctx, machine, context['rsp'])
        if 'rbp' in context: pydbg_ctx_set_bp(ctx, machine, context['rbp'])

    for i, name in enumerate(gp_names):
        if name in context:
            pydbg_ctx_set_gp(ctx, machine, i, context[name])

    if 'eflags' in context:
        pydbg_ctx_set_eflags(ctx, machine, context['eflags'])

    for dr in _DR_SLOTS:
        key = f'dr{dr}'
        if key in context:
            pydbg_ctx_set_dr(ctx, machine, dr, context[key])

    if machine == 32:
        result = Wow64SetThreadContext(<HANDLE><LPVOID>h_thread, ctx)
    else:
        result = SetThreadContext(<HANDLE><LPVOID>h_thread, ctx)
    free(ctx)
    if result == 0:
        raise OSError(GetLastError(), "SetThreadContext failed")
    return 0
```

（注意：`set_thread_context` 不再写段寄存器 —— 原实现也不写，段名仅 get 返回。）

- [ ] **Step 4: `_bp.pxi` — machine 感知的硬件断点**

把 cimport 块加 `Wow64GetThreadContext, Wow64SetThreadContext, WOW64_CONTEXT_ALL`。

替换 `_get_context`（第 31-41 行）为：

```cython
cdef void* _get_context(HANDLE h_thread, int machine):
    """Get thread CONTEXT with debug registers. Caller must free()."""
    cdef int ctx_size = pydbg_ctx_sizeof()
    cdef void* ctx = malloc(ctx_size)
    if ctx == NULL:
        raise MemoryError("Failed to allocate CONTEXT")
    if machine == 32:
        pydbg_ctx_init(ctx, machine, WOW64_CONTEXT_ALL)
        if Wow64GetThreadContext(h_thread, ctx) == 0:
            free(ctx)
            raise OSError(GetLastError(), "Wow64GetThreadContext failed")
    else:
        pydbg_ctx_init(ctx, machine, CONTEXT_DEBUG_REGISTERS)
        if GetThreadContext(h_thread, ctx) == 0:
            free(ctx)
            raise OSError(GetLastError(), "GetThreadContext failed")
    return ctx
```

替换 `set_hw_breakpoint` 签名与内部调用（第 43-101 行）为（只改签名、`_get_context`/`pydbg_ctx_set_dr`/`pydbg_ctx_get_dr`/`pydbg_ctx_set_flags`/`SetThreadContext` 的调用）：

```cython
cpdef int set_hw_breakpoint(unsigned long long h_thread, int slot, unsigned long long addr,
                             int condition, int length, int machine=64) except? -1:
    """Set a hardware breakpoint.

    Args:
        h_thread: Thread handle.
        slot: Debug register slot (0-3).
        addr: Breakpoint address.
        condition: 0=execute, 1=write, 3=read/write.
        length: 0=1 byte, 1=2 bytes, 3=4 bytes, 2=8 bytes.
        machine: 32 = WOW64 (x86) target, 64 = native x64 target (default).

    Returns:
        0 on success.

    Raises:
        ValueError: Invalid slot/condition/length.
        OSError: Win32 API failure.
    """
    if slot < 0 or slot > 3:
        raise ValueError(f"slot must be 0-3, got {slot}")
    if condition not in (0, 1, 3):
        raise ValueError(f"condition must be 0, 1, or 3, got {condition}")
    if length not in (0, 1, 2, 3):
        raise ValueError(f"length must be 0, 1, 2, or 3, got {length}")
    if condition == 0 and length != 0:
        raise ValueError("execute breakpoints must be 1 byte")

    cdef void* ctx = _get_context(<HANDLE><LPVOID>h_thread, machine)

    pydbg_ctx_set_dr(ctx, machine, slot, addr)

    cdef unsigned long long dr7 = pydbg_ctx_get_dr(ctx, machine, 7)
    cdef unsigned long long mask = <unsigned long long>(0xF << (16 + slot * 4))
    dr7 &= ~mask
    dr7 |= <unsigned long long>(condition << (16 + slot * 4))
    dr7 |= <unsigned long long>(length << (18 + slot * 4))
    dr7 |= <unsigned long long>(1 << (slot * 2))

    pydbg_ctx_set_dr(ctx, machine, 7, dr7)
    pydbg_ctx_set_dr(ctx, machine, 6, 0)

    cdef int set_result
    if machine == 32:
        pydbg_ctx_set_flags(ctx, machine, WOW64_CONTEXT_ALL)
        set_result = Wow64SetThreadContext(<HANDLE><LPVOID>h_thread, ctx)
    else:
        pydbg_ctx_set_flags(ctx, machine, CONTEXT_DEBUG_REGISTERS)
        set_result = SetThreadContext(<HANDLE><LPVOID>h_thread, ctx)
    free(ctx)
    if set_result == 0:
        raise OSError(GetLastError(), "SetThreadContext failed")
    return 0
```

替换 `clear_hw_breakpoint`（第 104-144 行）为：

```cython
cpdef int clear_hw_breakpoint(unsigned long long h_thread, int slot, int machine=64) except? -1:
    """Clear a hardware breakpoint.

    Args:
        h_thread: Thread handle.
        slot: Debug register slot (0-3).
        machine: 32 = WOW64 (x86) target, 64 = native x64 target (default).

    Returns:
        0 on success.

    Raises:
        ValueError: Invalid slot.
        OSError: Win32 API failure.
    """
    if slot < 0 or slot > 3:
        raise ValueError(f"slot must be 0-3, got {slot}")

    cdef void* ctx = _get_context(<HANDLE><LPVOID>h_thread, machine)

    pydbg_ctx_set_dr(ctx, machine, slot, 0)

    cdef unsigned long long dr7 = pydbg_ctx_get_dr(ctx, machine, 7)
    cdef unsigned long long mask = <unsigned long long>(0xF << (16 + slot * 4))
    dr7 &= ~mask
    dr7 &= ~<unsigned long long>(1 << (slot * 2))
    pydbg_ctx_set_dr(ctx, machine, 7, dr7)

    cdef int set_result
    if machine == 32:
        pydbg_ctx_set_flags(ctx, machine, WOW64_CONTEXT_ALL)
        set_result = Wow64SetThreadContext(<HANDLE><LPVOID>h_thread, ctx)
    else:
        pydbg_ctx_set_flags(ctx, machine, CONTEXT_DEBUG_REGISTERS)
        set_result = SetThreadContext(<HANDLE><LPVOID>h_thread, ctx)
    free(ctx)
    if set_result == 0:
        raise OSError(GetLastError(), "SetThreadContext failed")
    return 0
```

- [ ] **Step 5: `_memory.pxi` — EnumProcessModulesEx**

把 cimport 块加 `EnumProcessModulesEx, LIST_MODULES_ALL`（替换 `EnumProcessModules`）。

替换 `enum_process_modules`（第 114-140 行）中的调用为：

```cython
    cdef BOOL result = EnumProcessModulesEx(
        <HANDLE>h_process,
        modules,
        sizeof(modules),
        &cb_needed,
        LIST_MODULES_ALL)
```

并把失败消息改为 `"EnumProcessModulesEx failed"`。其余（dict 的 handle/base_address 循环）不变。

- [ ] **Step 6: 重建扩展 + x64 回归**

```bash
cd /c/Users/Spyder/Desktop/ai_eden/Output/pydbg-wow64-unified
../pydbg/venv-x64/Scripts/meson.exe setup build --buildtype=release
../pydbg/venv-x64/Scripts/meson.exe compile -C build
cp build/src/pydbg/cython/_pydbg.cp314-win_amd64.pyd src/pydbg/
PYTHONPATH=src ../pydbg/venv-x64/Scripts/python.exe -m unittest tests.test_thread tests.test_breakpoint tests.test_process tests.test_memory -v
```
Expected: 全部 PASS（x64 路径行为不变，machine 默认 64）。若编译报错，检查 `_win32types.pxd` 的 WOW64 声明/辅助函数签名与调用点是否一致。

- [ ] **Step 7: 提交**

```bash
git add src/pydbg/cython/
git commit -m "refactor: machine-aware context/breakpoint in Cython (WOW64 support foundation)"
```

---

### Task 3: Python 端 machine 贯穿 + WOW64 寄存器测试

**Files:**
- Modify: `src/pydbg/thread/manager.py`
- Modify: `src/pydbg/breakpoint/software.py`
- Create: `tests/test_wow64.py`（本任务先加寄存器/寄存器写入两个用例）
- Modify: `tests/meson.build`（注册 wow64 测试）

- [ ] **Step 1: 写失败的 WOW64 寄存器测试**

创建 `tests/test_wow64.py`：

```python
"""WOW64 (32-bit target on 64-bit host) integration tests."""

import os
import struct
import sys
import unittest

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_WOW64_TARGET = os.environ.get(
    "TEST_WOW64_TARGET_PATH",
    os.path.join(_TEST_DIR, "target", "simple_target32.exe"),
)
_HAS_TARGET = os.path.exists(TEST_WOW64_TARGET)


def _wow64_available():
    """True only on 64-bit Windows (a 32-bit host cannot debug WOW64)."""
    return struct.calcsize("P") == 8 and sys.platform == "win32"


def _launch(dbg, target=None):
    """Launch target under debug, consume events until first EXCEPTION (loader bp)."""
    pid, tid = dbg.create_process(target or TEST_WOW64_TARGET)
    event = dbg.wait_event(5000)
    if event is not None:
        dbg.continue_event(event.pid, event.tid)
    for _ in range(50):
        event = dbg.wait_event(2000)
        if event is None or event.type == "EXIT_PROCESS":
            break
        if event.type == "EXCEPTION":
            break
        dbg.continue_event(event.pid, event.tid)
    return pid, tid


def _module_by_name(dbg, basename):
    """Return module dict by basename (case-insensitive) or None."""
    for m in dbg.enum_modules():
        if m.get("name", "").split("\\")[-1].lower() == basename.lower():
            return m
    return None


def _export_address(dbg, exe_path, base, name):
    """Resolve exported function's absolute address from the on-disk PE."""
    from pydbg.pe import PE
    pe = PE.from_file(exe_path)
    for exp in pe.exports:
        if exp.name == name:
            return base + exp.rva
    raise AssertionError(f"export {name} not found in {exe_path}")


@unittest.skipUnless(_HAS_TARGET and _wow64_available(),
                     "requires 32-bit target and 64-bit host")
class TestWow64Registers(unittest.TestCase):
    def test_get_registers_returns_x86_names(self):
        from pydbg import Debugger
        from tests.helpers import teardown

        dbg = Debugger()
        try:
            _pid, tid = _launch(dbg)
            h = dbg.open_thread(tid)
            regs = dbg.get_registers(h)
            dbg.close_handle(h)
            self.assertEqual(regs["arch"], "x86")
            self.assertIn("eip", regs)
            self.assertIn("eax", regs)
            self.assertIn("esp", regs)
            self.assertNotIn("rip", regs)
            self.assertLess(regs["eip"], 0x100000000)
        finally:
            teardown(dbg)

    def test_set_register_x86(self):
        from pydbg import Debugger
        from tests.helpers import teardown

        dbg = Debugger()
        try:
            _pid, tid = _launch(dbg)
            h = dbg.open_thread(tid)
            regs = dbg.get_registers(h)
            old = regs["eax"]
            dbg.set_register(h, "eax", 0x12345678)
            regs2 = dbg.get_registers(h)
            dbg.set_register(h, "eax", old)  # restore
            dbg.close_handle(h)
            self.assertEqual(regs2["eax"], 0x12345678)
        finally:
            teardown(dbg)
```

在 `tests/meson.build` 的最后一个 `test(...)` 之后加：

```meson
test(
  'wow64',
  py,
  args: ['-m', 'unittest', 'tests.test_wow64'],
  env: test_env,
  workdir: meson.project_build_root(),
)
```

- [ ] **Step 2: 运行测试，确认失败**

```bash
cd /c/Users/Spyder/Desktop/ai_eden/Output/pydbg-wow64-unified
PYTHONPATH=src ../pydbg/venv-x64/Scripts/python.exe -m unittest tests.test_wow64 -v
```
Expected: FAIL —— 因为 `ThreadManager.get_context` 还没把 machine 传给 `_pydbg.get_thread_context`（默认 64），`regs["arch"]` 是 `"x64"` 不是 `"x86"`。

- [ ] **Step 3: ThreadManager 传 machine**

修改 `src/pydbg/thread/manager.py` 的 `get_context`/`set_context`/`set_register`：

```python
    def get_context(self, h_thread):
        try:
            return _pydbg.get_thread_context(h_thread, self._s.target_arch)
        except OSError as e:
            raise ThreadError(f"GetThreadContext: {e}")

    def set_context(self, h_thread, context):
        try:
            _pydbg.set_thread_context(h_thread, context, self._s.target_arch)
        except OSError as e:
            raise ThreadError(f"SetThreadContext: {e}")

    def set_register(self, h_thread, name, value):
        self.set_context(h_thread, {name.lower(): value})
```

`step` 不变（它调用 get_context/set_context，已透传 machine）。

- [ ] **Step 4: SoftwareBreakpointManager 传 machine**

修改 `src/pydbg/breakpoint/software.py` 的 `handle_breakpoint_hit`（第 93-101 行）：

```python
        try:
            h_thread = _pydbg.open_thread(tid)
            machine = self._s.target_arch
            regs = _pydbg.get_thread_context(h_thread, machine)
            regs["eflags"] = regs.get("eflags", 0) | 0x100
            if "rip" in regs:
                regs["rip"] -= 1
            elif "eip" in regs:
                regs["eip"] -= 1
            _pydbg.set_thread_context(h_thread, regs, machine)
            _pydbg.close_handle(h_thread)
        except OSError:
            self._write_int3_handle(h_process, bp_addr)
            return True
```

- [ ] **Step 5: 重跑测试，确认通过**

```bash
cd /c/Users/Spyder/Desktop/ai_eden/Output/pydbg-wow64-unified
PYTHONPATH=src ../pydbg/venv-x64/Scripts/python.exe -m unittest tests.test_wow64 -v
```
Expected: 两个用例 PASS（`arch=="x86"`、`eip<4GB`、`eax` 写入回读一致）。

同时跑 x64 回归确认没破坏：

```bash
PYTHONPATH=src ../pydbg/venv-x64/Scripts/python.exe -m unittest tests.test_thread tests.test_breakpoint tests.test_process -v
```
Expected: 全部 PASS。

- [ ] **Step 6: 提交**

```bash
git add src/pydbg/thread/manager.py src/pydbg/breakpoint/software.py tests/test_wow64.py tests/meson.build
git commit -m "feat: WOW64 register context via target_arch machine plumbing"
```

---

### Task 4: WX86 事件码 + WOW64 软件断点测试

**Files:**
- Modify: `src/pydbg/cython/_exception.pxi`
- Modify: `src/pydbg/__init__.py`
- Modify: `src/pydbg/core/debugger.py`
- Modify: `tests/test_wow64.py`

- [ ] **Step 1: 写失败的 WOW64 软件断点测试（验证 run() 自动处理生命周期）**

在 `tests/test_wow64.py` 加类（文件末尾）。这个测试验证 `run()` 收到 WX86 断点码后自动走「移除 int3 → 回调交付」路径 —— 改动前 int3 不会被移除，`read_memory == orig` 断言会失败：

```python
@unittest.skipUnless(_HAS_TARGET and _wow64_available(),
                     "requires 32-bit target and 64-bit host")
class TestWow64SoftwareBreakpoint(unittest.TestCase):
    def test_run_auto_handles_wx86_breakpoint(self):
        from pydbg import Debugger
        from tests.helpers import teardown

        dbg = Debugger()
        try:
            pid, tid = _launch(dbg)
            base = _module_by_name(dbg, "simple_target32.exe")["base_address"]
            addr = _export_address(dbg, TEST_WOW64_TARGET, base, "target_add")
            orig = dbg.read_memory(addr, 1)
            bp_id = dbg.set_breakpoint(addr)

            seen = []
            count = [0]

            def on_event(event):
                count[0] += 1
                if count[0] > 50:
                    return False  # safety bound
                if event.type == "EXCEPTION":
                    seen.append((event.exception_code, event.exception_addr))
                    if event.exception_code in (0x4000001F, 0x80000003):
                        return False  # stop at our breakpoint
                return None

            dbg.run(on_event, timeout_ms=3000)

            self.assertTrue(
                any(c in (0x4000001F, 0x80000003) for c, _ in seen),
                "WX86 breakpoint not delivered via run()",
            )
            # int3 removed at delivery time -> original byte restored
            self.assertEqual(dbg.read_memory(addr, 1), orig)
            dbg.remove_breakpoint(bp_id)
        finally:
            teardown(dbg)
```

- [ ] **Step 2: 运行测试，确认失败**

```bash
cd /c/Users/Spyder/Desktop/ai_eden/Output/pydbg-wow64-unified
PYTHONPATH=src ../pydbg/venv-x64/Scripts/python.exe -m unittest tests.test_wow64 -v
```
Expected: FAIL —— 断点命中后 `ev.exception_code` 是 `0x4000001F`，`run()` 不识别它（只认 `0x80000003`），不会调用 `handle_breakpoint_hit`，所以 `read_memory(addr, 1)` 仍是 `b"\xcc"`（int3 未移除），`self.assertEqual(dbg.read_memory(addr, 1), orig)` 失败。

- [ ] **Step 3: `_exception.pxi` 加 WX86 常量与名称映射**

在 `src/pydbg/cython/_exception.pxi` 顶部常量区（`EXCEPTION_STACK_OVERFLOW = ...` 之后）加：

```python
STATUS_WX86_BREAKPOINT = 0x4000001F
STATUS_WX86_SINGLE_STEP = 0x4000001E
```

在 `_EXCEPTION_NAMES` dict 加两行：

```python
    0x4000001F: "STATUS_WX86_BREAKPOINT",
    0x4000001E: "STATUS_WX86_SINGLE_STEP",
```

- [ ] **Step 4: `pydbg/__init__.py` 导出常量**

在 `from ._pydbg import (` 块里加：

```python
    STATUS_WX86_BREAKPOINT,
    STATUS_WX86_SINGLE_STEP,
```

在 `__all__` 加：

```python
    "STATUS_WX86_BREAKPOINT",
    "STATUS_WX86_SINGLE_STEP",
```

- [ ] **Step 5: `core/debugger.py` run() 识别 WX86 码**

在 `run()`（第 247-267 行）中，把两个 `code == 0x...` 判断改为：

```python
                if code == _pydbg.EXCEPTION_BREAKPOINT or code == _pydbg.STATUS_WX86_BREAKPOINT:
                    # Remove INT3, rewind IP, set TF for single-step.
                    if self.brk_sw.handle_breakpoint_hit(event.tid, addr):
                        result = callback(event)
                        if result is False:
                            break
                        self.continue_event(event.pid, event.tid)
                        continue
                elif code == _pydbg.EXCEPTION_SINGLE_STEP or code == _pydbg.STATUS_WX86_SINGLE_STEP:
                    # Restore INT3 if this was from our breakpoint lifecycle
                    if self.brk_sw.handle_single_step(event.tid):
                        self.continue_event(event.pid, event.tid)
                        continue  # Don't deliver internal single-step to user
```

（`_pydbg.EXCEPTION_BREAKPOINT` 等已存在；`_pydbg` 已在文件顶部 `from .. import _pydbg`。）

- [ ] **Step 6: 重建扩展 + 重跑测试**

改 Cython 后需重建（`_exception.pxi` 属于扩展）：

```bash
cd /c/Users/Spyder/Desktop/ai_eden/Output/pydbg-wow64-unified
../pydbg/venv-x64/Scripts/meson.exe compile -C build
cp build/src/pydbg/cython/_pydbg.cp314-win_amd64.pyd src/pydbg/
PYTHONPATH=src ../pydbg/venv-x64/Scripts/python.exe -m unittest tests.test_wow64 -v
```
Expected: 全部 PASS（软件断点生命周期在 WOW64 目标上成立）。

- [ ] **Step 7: 提交**

```bash
git add src/pydbg/cython/_exception.pxi src/pydbg/__init__.py src/pydbg/core/debugger.py tests/test_wow64.py
git commit -m "feat: handle WX86 breakpoint/single-step codes for WOW64 targets"
```

---

### Task 5: 硬件断点 WOW64（挂起先行）+ 测试

**Files:**
- Modify: `src/pydbg/breakpoint/hardware.py`
- Modify: `tests/test_wow64.py`

- [ ] **Step 1: 写失败的 WOW64 硬件断点测试**

在 `tests/test_wow64.py` 末尾加：

```python
@unittest.skipUnless(_HAS_TARGET and _wow64_available(),
                     "requires 32-bit target and 64-bit host")
class TestWow64HardwareBreakpoint(unittest.TestCase):
    def test_dr0_execute_breakpoint(self):
        from pydbg import Debugger
        from tests.helpers import teardown

        dbg = Debugger()
        try:
            pid, tid = _launch(dbg)
            base = _module_by_name(dbg, "simple_target32.exe")["base_address"]
            addr = _export_address(dbg, TEST_WOW64_TARGET, base, "target_add")
            h = dbg.open_thread(tid)
            bp_id = dbg.set_hw_breakpoint(addr, "x", 1, 0)
            dbg.continue_event(pid, tid)

            hit = False
            for _ in range(100):
                ev = dbg.wait_event(2000)
                if ev is None:
                    break
                if ev.type == "EXCEPTION":
                    if ev.exception_code in (0x80000004, 0x4000001E):
                        regs = dbg.get_registers(h)
                        self.assertTrue(regs["dr6"] & 1, "Dr6 slot0 not set")
                        self.assertEqual(regs["eip"], addr)
                        hit = True
                        dbg.brk_hw.clear(0)  # clear before continue (avoid re-trap)
                        dbg.continue_event(ev.pid, ev.tid)
                        break
                dbg.continue_event(ev.pid, ev.tid)
                if ev.type == "EXIT_PROCESS":
                    break
            self.assertTrue(hit, "Dr0 breakpoint was not hit")
            try:
                dbg.remove_breakpoint(bp_id)
            except Exception:
                pass
            dbg.close_handle(h)
        finally:
            teardown(dbg)
```

- [ ] **Step 2: 运行测试，确认失败**

```bash
cd /c/Users/Spyder/Desktop/ai_eden/Output/pydbg-wow64-unified
PYTHONPATH=src ../pydbg/venv-x64/Scripts/python.exe -m unittest tests.test_wow64 -v
```
Expected: FAIL —— `HardwareBreakpointManager.set` 还没把 machine 传给 `_pydbg.set_hw_breakpoint`（默认 64，Dr0 写进 x64 原生 CONTEXT），WOW64 线程执行时不触发。

- [ ] **Step 3: HardwareBreakpointManager 传 machine + 挂起先行**

修改 `src/pydbg/breakpoint/hardware.py`：

```python
    def set(self, addr, condition="x", length=1, slot=0):
        if condition not in self.COND_MAP:
            raise BreakpointError(f"Invalid condition '{condition}', use x/w/rw")
        if length not in self.LEN_MAP:
            raise BreakpointError(f"Invalid length {length}, use 1/2/4/8")

        machine = self._s.target_arch
        # WOW64 平台怪癖：运行中的线程直接 Wow64SetThreadContext 写 Dr0-3
        # 约 3/4 概率不生效，须先 SuspendThread。净挂起计数保持 0。
        suspended = False
        if machine == 32:
            _pydbg.suspend_thread(self._s.thread_handle)
            suspended = True
        try:
            _pydbg.set_hw_breakpoint(
                self._s.thread_handle,
                slot,
                addr,
                self.COND_MAP[condition],
                self.LEN_MAP[length],
                machine,
            )
        except (OSError, ValueError) as e:
            raise BreakpointError(f"set_hw_breakpoint: {e}")
        finally:
            if suspended:
                _pydbg.resume_thread(self._s.thread_handle)

        self._s.bp_counter += 1
        bp_id = self._s.bp_counter
        self._s.breakpoints[bp_id] = ("hw", addr, slot)
        return bp_id

    def clear(self, slot):
        machine = self._s.target_arch
        suspended = False
        if machine == 32:
            _pydbg.suspend_thread(self._s.thread_handle)
            suspended = True
        try:
            _pydbg.clear_hw_breakpoint(self._s.thread_handle, slot, machine)
        except (OSError, ValueError) as e:
            raise BreakpointError(f"clear_hw_breakpoint: {e}")
        finally:
            if suspended:
                _pydbg.resume_thread(self._s.thread_handle)
```

（`hardware.py` 顶部已有 `from .. import _pydbg`。）

- [ ] **Step 4: 重跑测试，确认通过**

```bash
cd /c/Users/Spyder/Desktop/ai_eden/Output/pydbg-wow64-unified
PYTHONPATH=src ../pydbg/venv-x64/Scripts/python.exe -m unittest tests.test_wow64 -v
```
Expected: 全部 PASS（Dr0 命中：`dr6 & 1` 且 `eip == addr`）。

- [ ] **Step 5: 提交**

```bash
git add src/pydbg/breakpoint/hardware.py tests/test_wow64.py
git commit -m "feat: WOW64 hardware breakpoints with suspend-first DR write"
```

---

### Task 6: 模块枚举 arch 字段 + WOW64 模块测试

**Files:**
- Modify: `src/pydbg/module/resolver.py`
- Modify: `tests/test_wow64.py`

- [ ] **Step 1: 写失败的 WOW64 模块枚举测试**

在 `tests/test_wow64.py` 末尾加：

```python
@unittest.skipUnless(_HAS_TARGET and _wow64_available(),
                     "requires 32-bit target and 64-bit host")
class TestWow64Modules(unittest.TestCase):
    def test_enum_modules_sees_x86_exe_and_ntdll32(self):
        from pydbg import Debugger
        from tests.helpers import teardown

        dbg = Debugger()
        try:
            _pid, _tid = _launch(dbg)
            mods = dbg.enum_modules()
            exe = _module_by_name(dbg, "simple_target32.exe")
            self.assertIsNotNone(exe, "32-bit exe not enumerated")
            self.assertEqual(exe["arch"], "x86")
            self.assertLess(exe["base_address"], 0x100000000)
            ntdll32 = [m for m in mods
                       if m.get("name", "").endswith("ntdll.dll")
                       and m["arch"] == "x86"]
            self.assertTrue(ntdll32, "32-bit ntdll not enumerated")
        finally:
            teardown(dbg)
```

- [ ] **Step 2: 运行测试，确认失败**

```bash
cd /c/Users/Spyder/Desktop/ai_eden/Output/pydbg-wow64-unified
PYTHONPATH=src ../pydbg/venv-x64/Scripts/python.exe -m unittest tests.test_wow64 -v
```
Expected: FAIL —— `resolver.enumerate()` 返回的 dict 没有 `arch` 键（KeyError 或断言失败）。

- [ ] **Step 3: resolver 加 arch 检测**

修改 `src/pydbg/module/resolver.py`：顶部加 `import struct`；类内加方法：

```python
    @staticmethod
    def _module_arch(h_proc, base):
        """Determine a module's architecture by reading its PE header machine."""
        try:
            dos = _pydbg.read_process_memory(h_proc, base, 0x40)
            if len(dos) < 0x40 or dos[:2] != b"MZ":
                return "unknown"
            e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
            nt = _pydbg.read_process_memory(h_proc, base + e_lfanew, 6)
            if len(nt) < 6 or nt[:2] != b"PE":
                return "unknown"
            machine = struct.unpack_from("<H", nt, 2)[0]
            return {0x14C: "x86", 0x8664: "x64"}.get(machine, "unknown")
        except OSError:
            return "unknown"
```

在 `enumerate_handle`（第 33-45 行）的模块循环里加一行：

```python
        for m in modules:
            m["arch"] = self._module_arch(h_process, m["base_address"])
            try:
                m['name'] = _pydbg.get_module_file_name_ex(h_process, m['handle'])
            except OSError:
                m['name'] = ''
        return modules
```

（`enumerate()` 已委托 `enumerate_handle`，自动获得 arch。）

- [ ] **Step 4: 重跑测试，确认通过**

```bash
cd /c/Users/Spyder/Desktop/ai_eden/Output/pydbg-wow64-unified
PYTHONPATH=src ../pydbg/venv-x64/Scripts/python.exe -m unittest tests.test_wow64 -v
```
Expected: 全部 PASS（能看到 `simple_target32.exe`（arch=x86, base<4GB）与 32 位 ntdll）。

- [ ] **Step 5: 提交**

```bash
git add src/pydbg/module/resolver.py tests/test_wow64.py
git commit -m "feat: module arch detection (x86/x64) for WOW64 enumeration"
```

---

### Task 7: WOW64 附加模式测试

**Files:**
- Modify: `tests/test_wow64.py`

- [ ] **Step 1: 写 WOW64 附加测试**

在 `tests/test_wow64.py` 末尾加：

```python
@unittest.skipUnless(_HAS_TARGET and _wow64_available(),
                     "requires 32-bit target and 64-bit host")
class TestWow64Attach(unittest.TestCase):
    def test_attach_to_running_x86_target(self):
        import subprocess

        from pydbg import Debugger
        from tests.helpers import teardown

        proc = subprocess.Popen(
            [TEST_WOW64_TARGET],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        dbg = Debugger()
        try:
            dbg.attach(proc.pid)
            self.assertEqual(dbg._session.target_arch, 32)

            tid = None
            event = dbg.wait_event(5000)
            if event is not None:
                tid = event.tid
                dbg.continue_event(event.pid, event.tid)
            for _ in range(50):
                event = dbg.wait_event(2000)
                if event is None or event.type == "EXIT_PROCESS":
                    break
                if tid is None:
                    tid = event.tid
                if event.type == "EXCEPTION":
                    break
                dbg.continue_event(event.pid, event.tid)

            self.assertIsNotNone(tid, "no thread id from attach")
            h = dbg.open_thread(tid)
            regs = dbg.get_registers(h)
            dbg.close_handle(h)
            self.assertEqual(regs["arch"], "x86")
            self.assertLess(regs["eip"], 0x100000000)
        finally:
            try:
                dbg.detach()
            except Exception:
                pass
            proc.kill()
            proc.wait()
```

- [ ] **Step 2: 运行测试，确认通过**

```bash
cd /c/Users/Spyder/Desktop/ai_eden/Output/pydbg-wow64-unified
PYTHONPATH=src ../pydbg/venv-x64/Scripts/python.exe -m unittest tests.test_wow64 -v
```
Expected: 全部 PASS（附加后 `target_arch==32`、寄存器 x86 名、EIP<4GB）。若 `DebugActiveProcessStop` 报 ACCESS_DENIED，detach 已 try/except，测试仍通过。

- [ ] **Step 3: 提交**

```bash
git add tests/test_wow64.py
git commit -m "test: WOW64 attach mode register verification"
```

---

### Task 8: CI 只跑 x64 + 编译 32 位目标

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: 移除 x86 matrix，加 target32 构建步骤**

把 `.github/workflows/ci.yml` 的 job 改为（去掉 `matrix`，新增 target32 步骤）：

```yaml
name: CI

on:
  pull_request:
    branches: [master, main]

jobs:
  build-and-test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
          architecture: x64

      - uses: ilammy/msvc-dev-cmd@v1
        with:
          arch: amd64

      - name: Install build deps
        run: pip install meson meson-python ninja cython flake8 'capstone>=5.0' keystone-engine

      - name: Lint
        run: flake8 src/ tests/ --max-line-length=120

      - name: Configure
        run: meson setup build --buildtype=release

      - name: Build
        run: meson compile -C build

      - name: Build 32-bit WOW64 test target
        run: powershell -File scripts/build-target32.ps1

      - name: Test
        run: |
          pip install -e . --no-build-isolation
          meson test -C build --print-errorlogs
```

- [ ] **Step 2: 验证 CI 语法**

```bash
cd /c/Users/Spyder/Desktop/ai_eden/Output/pydbg-wow64-unified
../pydbg/venv-x64/Scripts/python.exe -c "import yaml" 2>/dev/null && ../pydbg/venv-x64/Scripts/python.exe -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('YAML OK')" || echo "pyyaml not available — 人工检查缩进"
```
Expected: `YAML OK`（或提示人工检查）。CI 实跑由 GitHub Actions 验证（本机 github.com 被屏蔽，push 时说明）。

- [ ] **Step 3: 提交**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: x64-only matrix + build 32-bit WOW64 test target"
```

---

### Task 9: devtools / README / 文档清理

**Files:**
- Modify: `devtools/build-test.ps1`
- Modify: `devtools/setup-embedded.ps1`
- Modify: `README.md`
- Modify: `docs/architecture.md`（如涉及宿主/目标架构描述）

- [ ] **Step 1: `devtools/build-test.ps1` 去掉 x86**

把整个文件改为只支持 x64（去掉 `-Arch`/`all` 逻辑）：

```powershell
# build-test.ps1 — Build and test with the x64 embedded Python (WOW64 targets supported).
# Usage:
#   .\devtools\build-test.ps1

$ErrorActionPreference = "Stop"

$DEVTOOLS_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$ROOT_DIR = Split-Path -Parent $DEVTOOLS_DIR

$python = Join-Path $DEVTOOLS_DIR "python-x64\python.exe"
if (-not (Test-Path $python)) {
    Write-Host "[error] python-x64 not found. Run setup-embedded.ps1 first." -ForegroundColor Red
    exit 1
}

$build = Join-Path $ROOT_DIR "build-x64"
if (Test-Path $build) { Remove-Item -Recurse -Force $build }

Write-Host "[configure] meson setup build-x64" -ForegroundColor Yellow
& $python -m meson setup $build $ROOT_DIR --buildtype=release
if ($LASTEXITCODE -ne 0) { Write-Host "[fail] configure" -ForegroundColor Red; exit 1 }

Write-Host "[build] meson compile" -ForegroundColor Yellow
& $python -m meson compile -C $build
if ($LASTEXITCODE -ne 0) { Write-Host "[fail] build" -ForegroundColor Red; exit 1 }

Write-Host "[build] 32-bit WOW64 test target" -ForegroundColor Yellow
& powershell -File (Join-Path $ROOT_DIR "scripts\build-target32.ps1")
if ($LASTEXITCODE -ne 0) { Write-Host "[fail] build-target32" -ForegroundColor Red; exit 1 }

Write-Host "[pip] install capstone" -ForegroundColor Yellow
& $python -m pip install "capstone>=5.0" 2>&1 | Out-Null

Write-Host "[install] pip install -e ." -ForegroundColor Yellow
Push-Location $ROOT_DIR
& $python -m pip install -e . --no-build-isolation 2>&1 | Out-Null
Pop-Location
if ($LASTEXITCODE -ne 0) { Write-Host "[fail] install" -ForegroundColor Red; exit 1 }

Write-Host "[test] meson test" -ForegroundColor Yellow
& $python -m meson test -C $build --print-errorlogs
if ($LASTEXITCODE -ne 0) { Write-Host "[fail] test" -ForegroundColor Red; exit 1 }

Write-Host "[pass] python-x64 OK" -ForegroundColor Green
```

- [ ] **Step 2: `devtools/setup-embedded.ps1` 只下载 x64**

把第 10-11 行的并行数组改为只含 amd64/x64：

```powershell
$ARCHES = @("amd64")
$NAMES = @("x64")
```

（第 13 行 `for ($i = 0; $i -lt $ARCHES.Length; $i++)` 循环逻辑不变，循环体只跑一次，不再下载 python-x86。）文件顶部注释 `# Download and configure embedded Python for x86/x64` 改为 `# Download and configure embedded Python for x64 (WOW64 targets supported)`。

- [ ] **Step 3: README 更新**

修改 `README.md`（精确替换）：
- 第 6 行 badge：`![Platform](https://img.shields.io/badge/platform-Windows%20x64%20%7C%20x86-blue)` → `![Platform](https://img.shields.io/badge/platform-Windows%20x64-blue)`
- 第 22-23 行：`> **支持 Windows x64 和 x86。** 调试 API 依赖 Win32 原生函数。\n> 扩展根据 Python 解释器位数自动编译为对应架构。` → `> **支持 Windows x64（可调试 WOW64 32 位目标）。** 调试 API 依赖 Win32 原生函数。\n> 扩展只编译为 x64（win_amd64）；32 位目标经 WOW64 层统一调试。`
- 「### 32/64 位支持」小节（约第 238-256 行）整体改为：

```markdown
### 目标架构支持

宿主恒为 64 位（`win_amd64`）。扩展按**目标**架构分发上下文：

- **x64 目标** — `get_registers()` 返回 x64 寄存器名（`rax`/`rip`/`rsp`/...）。
- **WOW64（32 位）目标** — `create_process()`/`attach()` 通过 `IsWow64Process`
  检测，`get_registers()` 返回 x86 寄存器名（`eax`/`eip`/`esp`/...）。

软件断点/硬件断点/单步按目标架构正确处理（WOW64 走 `Wow64GetThreadContext` +
`STATUS_WX86_*` 事件码）；模块枚举用 `EnumProcessModulesEx(LIST_MODULES_ALL)`
同时列出 32/64 位模块，并标注 `arch` 字段。
```

- 「使用 Embedded Python 本地验证双架构」小节（约第 279-296 行）改为只验证 x64：

```markdown
### 使用 Embedded Python 本地验证

```powershell
# 首次：下载并配置 embedded Python (x64)
.\devtools\setup-embedded.ps1

# 构建并测试
.\devtools\build-test.ps1
```
```

- 「构建并测试当前架构」/「-Arch x86/x64/all」相关示例删除。

- [ ] **Step 4: 全量测试确认无回归**

```bash
cd /c/Users/Spyder/Desktop/ai_eden/Output/pydbg-wow64-unified
PYTHONPATH=src ../pydbg/venv-x64/Scripts/python.exe -m unittest tests.test_process tests.test_thread tests.test_breakpoint tests.test_memory tests.test_module tests.test_wow64 -v
```
Expected: 全部 PASS。

- [ ] **Step 5: 提交**

```bash
git add devtools/ README.md docs/architecture.md
git commit -m "chore: drop x86 host build/devtools, document WOW64 support"
```

---

### Task 10: 全量回归 + KNOWN_ISSUES 更新

**Files:**
- Modify: `docs/KNOWN_ISSUES.md`

- [ ] **Step 1: 全量回归**

```bash
cd /c/Users/Spyder/Desktop/ai_eden/Output/pydbg-wow64-unified
PYTHONPATH=src ../pydbg/venv-x64/Scripts/python.exe -m unittest discover -s tests -t . -v 2>&1 | tail -30
```
Expected: 除 skip 外全部 PASS。若个别非 WOW64 测试失败，确认是本次改动引入还是预先存在（对比 master 行为），先修本次引入的问题。

- [ ] **Step 2: KNOWN_ISSUES 追加 WOW64 平台特性**

在 `docs/KNOWN_ISSUES.md` 末尾加一节：

```markdown
## WOW64 (32 位目标) 调试平台特性

- **WX86 异常码**：32 位代码的断点/单步经 WoW64 层上报为
  `STATUS_WX86_BREAKPOINT (0x4000001F)` / `STATUS_WX86_SINGLE_STEP (0x4000001E)`。
  事件循环把两者当"已处理"继续（DBG_CONTINUE）；不得传 DBG_EXCEPTION_NOT_HANDLED，
  否则目标进程会被终止。
- **硬件断点写入**：WOW64 线程直接 `Wow64SetThreadContext` 写 Dr0-3 约 3/4 概率不生效，
  `HardwareBreakpointManager.set/clear` 会先 `SuspendThread` 再写。
- **执行型硬件断点**：命中后须先清除断点再 `ContinueDebugEvent`，否则同地址反复重陷阱
  （WOW64 与 x64 通用）。
- **模块枚举**：WOW64 进程同时存在 32/64 位模块（两套 ntdll）。pydbg 用
  `EnumProcessModulesEx(LIST_MODULES_ALL)` + 按 PE 头判定 `arch`。主镜像不产生
  LOAD_DLL 事件，模块枚举须在加载器初始化完成后调用。
- **附加模式**：`DebugActiveProcessStop` 在目标主线程挂起时可能返回
  `ERROR_ACCESS_DENIED`（瞬态），必要时重试；句柄槽可能被调试子系统复用，用
  `GetProcessId` 校验。
```

- [ ] **Step 3: 提交**

```bash
git add docs/KNOWN_ISSUES.md
git commit -m "docs: record WOW64 debugging platform characteristics"
```

---

## 自审记录（计划编写时已核对）

- **Spec 覆盖**：§2.1→Task2；§2.2→Task3；§2.3→Task4；§2.4→Task5；§2.5→Task6；§2.6→Task8/9；§2.7→Task1/3-7；§5/§8 已知特性→Task10 记录。
- **类型一致性**：`machine` 参数统一为 `int`，`32`=WOW64、其它=64；`_pydbg.get_thread_context(h, machine)`、`set_thread_context(h, dict, machine)`、`set/clear_hw_breakpoint(h, slot, addr, cond, len, machine)` 三处签名全计划一致。`regs["eip"]/["rip"]` 按 machine 决定。
- **已知边界**：子进程调试假设子进程与主进程同架构（`session.target_arch` 单值，逐进程 machine 是未来扩展）；不做远程调用/三模块框架/WOW64 栈回溯（YAGNI，见 spec §7）。
