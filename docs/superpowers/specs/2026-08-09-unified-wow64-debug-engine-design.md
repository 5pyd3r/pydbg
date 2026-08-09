# pydbg 统一 64 位调试引擎设计

> 日期：2026-08-09
> 分支：`feat/unified-wow64-debug-api`（基于 master `3be28aa`）
> 状态：已批准
> 宿主平台：Windows 10 x64（10.0.19045）

## 1. 背景与目标

### 1.1 现状问题

pydbg 当前把宿主架构当成目标架构处理，Cython 扩展按宿主 Python 位数编译（`#ifdef _WIN64`），存在以下缺陷：

1. **上下文错误**：`get_thread_context`/`set_thread_context` 用原生 `GetThreadContext` + 宿主 `CONTEXT`。x64 宿主调试 WOW64（32 位）目标时拿到的是 x64 原生上下文（RIP/RAX），不是 32 位代码上下文（EIP/EAX）——这正是参考文档强调的坑。
2. **目标架构只存不用**：`session.target_arch` 用 `IsWow64Process` 检测后未参与任何分发。
3. **WX86 异常码未处理**：事件循环只识别 `0x80000003/0x80000004`。WOW64 目标断点/单步经 WoW64 层上报为 `STATUS_WX86_BREAKPOINT (0x4000001F)` / `STATUS_WX86_SINGLE_STEP (0x4000001E)`，被当未处理异常导致目标进程被终止。
4. **模块枚举缺 32 位模块**：`EnumProcessModules`（psapi）在 x64 宿主列 WOW64 进程时默认只返回 64 位模块，看不到 32 位 exe/DLL。
5. **x86 宿主环境依赖**：CI matrix（x64+x86）、devtools（`-Arch x86`、embedded python-x86）、`build-x86/`、`venv-x86/`、Cython 代码 `#ifdef _WIN32` 分支。

### 1.2 目标

- 把 pydbg 归一成**单一 x64 宿主调试引擎**：用 64 位 Debug API（`WaitForDebugEvent`/`ContinueDebugEvent`/`ReadProcessMemory`/`WriteProcessMemory`）统一调试两类目标：
  - **x64 原生目标**：原生 `CONTEXT` + `GetThreadContext`/`SetThreadContext`。
  - **WOW64（32 位）目标**：`WOW64_CONTEXT` + `Wow64GetThreadContext`/`Wow64SetThreadContext`。
- 上下文/寄存器按**目标**架构分发；寄存器名跟随目标（x64：`rip/rax/...`；WOW64：`eip/eax/...`）。
- WOW64 软件断点 / 硬件断点 / 事件码 / 模块枚举 / 附加模式正确处理。
- 彻底消除 x86 宿主环境依赖（构建、CI、devtools、代码分支）。

### 1.3 已确认决策

| 决策点 | 结论 |
|--------|------|
| WOW64 覆盖深度 | 现有 Debugger API 全量对齐：上下文/寄存器、软件断点(WX86码)、硬件断点(挂起先行)、模块枚举、附加模式 |
| 验证策略 | 新增专用 32 位测试目标（`/EXPORT` 导出确定性函数）+ 新增 `tests/test_wow64.py`；CI 只跑 x64 宿主，用 32 位目标验证 WOW64 |
| 目标编译方式 | 32 位目标在 CI **现编译**（`vcvarsall amd64_x86` 交叉编译），不提交预编译产物 |
| 上下文分发机制 | **方案 1**：Cython 函数显式 `machine` 参数（默认 64），Python 端从 `session.target_arch` 传入 |
| 模块枚举 | `EnumProcessModulesEx(LIST_MODULES_ALL)`（比 PEB32 手动遍历简单，pydbg 已有 psapi 依赖） |

## 2. 架构设计

### 2.1 Cython 上下文层（`src/pydbg/cython/_win32types.pxd`、`_thread.pxi`、`_bp.pxi`）

**新增 Win32 声明**（`cdef extern from "windows.h"`）：
- `WOW64_CONTEXT` 结构体。
- `Wow64GetThreadContext(HANDLE, WOW64_CONTEXT*)`、`Wow64SetThreadContext(HANDLE, WOW64_CONTEXT*)`。
- WOW64 标志位常量：`WOW64_CONTEXT_ALL` 等（i386 值，`WOW64_CONTEXT_ALL = 0x0001003F`；注意与 x64 的 `CONTEXT_ALL = 0x0010003F` 不同）。

**现有 `pydbg_ctx_*` 内联辅助函数全部加 `machine` 参数**（`int machine`：`32` = WOW64/x86 布局，否则 = x64 布局）：

```
pydbg_ctx_get_ip(pctx, machine)    // machine==32 → ((WOW64_CONTEXT*)pctx)->Eip，否则 ((CONTEXT*)pctx)->Rip
pydbg_ctx_set_ip(pctx, v, machine)
pydbg_ctx_get_sp / set_sp           // Esp vs Rsp
pydbg_ctx_get_bp / set_bp           // Ebp vs Rbp
pydbg_ctx_get_eflags / set_eflags   // EFlags 双布局同字段名
pydbg_ctx_get_gp / set_gp           // x86: 0=Eax..7=Edi；x64: 0=Rax..15=R15（现有索引表统一）
pydbg_ctx_get_dr / set_dr           // Dr0-3/6/7 双布局同字段名
pydbg_ctx_get_seg                    // SegCs..SegSs 双布局同字段名
```

扩展只编 x64，**移除全部 `#ifdef _WIN32` / `#else` 分支**。

**`_thread.pxi`**：
- `get_thread_context(h_thread, machine=64)`：
  - `machine==32`：分配 `WOW64_CONTEXT`，`ContextFlags = WOW64_CONTEXT_ALL`，`Wow64GetThreadContext`，返回 x86 寄存器名（`eax/ecx/edx/ebx/esp/ebp/esi/edi/eip/eflags/dr0-7/cs..ss`），`arch='x86'`。
  - `machine==64`：现有逻辑（`CONTEXT` + `GetThreadContext`），返回 x64 寄存器名，`arch='x64'`。
- `set_thread_context(h_thread, context, machine=64)`：同分发；`eip/esp/ebp`（x86）或 `rip/rsp/rbp`（x64）按 machine 决定。
- `get_host_arch()` 保留（恒为 64）。
- 缓冲按 `max(sizeof(CONTEXT), sizeof(WOW64_CONTEXT))` 分配，避免结构大小不同越界。

**`_bp.pxi`**：
- `set_hw_breakpoint(h_thread, slot, addr, condition, length, machine=64)`、`clear_hw_breakpoint(h_thread, slot, machine=64)`：Dr0-3/6/7 按 machine 读写对应结构（WOW64 走 `WOW64_CONTEXT` + `Wow64Get/SetThreadContext`）。

### 2.2 会话目标架构贯穿（`src/pydbg/core/`、各 manager）

- `session.target_arch` 已是数据字段。`Debugger._detect_target_arch` 用 `IsWow64Process`（可保留；升级 `IsWow64Process2` 可选）。
- `create_process` / `attach` 后已设置 `session.target_arch`。
- `ThreadManager.get_context/set_context/set_register/step` 把 `self._s.target_arch` 作为 `machine` 传给 Cython。
- `HardwareBreakpointManager.set/clear` 把 `self._s.target_arch` 作为 `machine` 传入。
- `SoftwareBreakpointManager.handle_breakpoint_hit` 里读取/回退 IP 走 machine 感知的上下文（现有 `'rip' in regs` / `'eip' in regs` 判断保持有效，因为 `get_thread_context` 已按 machine 返回正确寄存器名）。

### 2.3 事件循环 WX86 码（`src/pydbg/core/debugger.py`、`_exception.pxi`）

- 新增常量：`STATUS_WX86_BREAKPOINT = 0x4000001F`、`STATUS_WX86_SINGLE_STEP = 0x4000001E`。
- `run()` 中 `0x4000001F` 按断点生命周期（`handle_breakpoint_hit`）、`0x4000001E` 按单步（`handle_single_step`）处理，与 `0x80000003/04` 同等。
- `_exception.pxi.exception_code_to_str` 增加两个码映射。
- **硬约束**：WX86 码必须 `DBG_CONTINUE`，否则目标进程被终止（demo 实测）。默认 continue 状态已满足，但不得对这两个码做 `DBG_EXCEPTION_NOT_HANDLED`。

### 2.4 硬件断点 WOW64（`src/pydbg/breakpoint/hardware.py`、`_bp.pxi`）

- WOW64 目标写 DR 前**先 `SuspendThread`，写完 `ResumeThread`**（demo 实测直接写约 3/4 概率不生效）。此逻辑放在 `HardwareBreakpointManager.set/clear`（`machine==32` 时挂起先行）。
- 执行型 hw 断点命中后若不清除断点就继续，会在同地址反复重陷阱（demo 实测，x64/WOW64 通用）。pydbg 交互模型下由 WOW64 测试流程遵循"命中→验证→清除→继续"实践；`run()` 不为此新增逻辑。

### 2.5 模块枚举（`src/pydbg/module/resolver.py`、`_process.pxi`、`_win32types.pxd`）

- psapi 加声明：`EnumProcessModulesEx(HANDLE, HMODULE*, DWORD, DWORD*, DWORD)` + `LIST_MODULES_ALL = 0x03`。
- `enum_process_modules` 改用 `EnumProcessModulesEx(..., LIST_MODULES_ALL)`（x64 目标行为同现）。
- 模块 dict 增加 `arch` 字段：读各模块基址 PE 头 machine（PE32→`x86`，PE32+→`x64`），供上层/测试区分 32 位 ntdll 等。
- 保留 `GetModuleFileNameExA` 解析路径；`GetModuleInformation` 已有。

### 2.6 消除 x86 宿主环境

- **CI**（`.github/workflows/ci.yml`）：matrix 去掉 `x86`，只跑 x64；`ilammy/msvc-dev-cmd` 用 `arch: amd64`；新增一步运行 `scripts/build-target32.ps1` 后跑 WOW64 测试。
- **devtools**（`build-test.ps1`）：去掉 `-Arch x86` / `all` 分支，只跑 x64；测试前调用 `scripts/build-target32.ps1`。`setup-embedded.ps1` 只下载 x64 embedded Python。
- **README**：badge 改为「Windows x64（可调试 WOW64 32 位目标）」；安装/架构说明更新。
- **代码**：`_win32types.pxd` 移除 `#ifdef _WIN32` 分支。
- 删除 `build-x86/`、`venv-x86/`（如有）；`.gitignore` 相应条目可保留。
- **测试寄存器名 helper**：宿主恒为 64 后，现有 `tests/__init__.py` / `tests/conftest.py` 的 `IP_REG/SP_REG/GP_REG`（`rip/rsp/rax`）对 x64 目标已正确，**保持不变**；新增 `tests/test_wow64.py` 内显式使用 x86 寄存器名（`eip/esp/eax`），不依赖 host helper。

### 2.7 测试资产（CI 现编译）

- 新 `tests/target/simple_target32.c`（32 位控制台）：
  - `__declspec(dllexport)` 导出确定性函数：`target_add(int a, int b)`、`target_mul_store(int a, int b)`（累加进全局 `g_counter`）、`target_get_global(void)`、`target_sleep(int ms)`。
  - 全部 `__declspec(noinline)`，防止 /O2 内联/常量折叠导致入口断点永不命中（镜像 demo `target32.c`）。
  - main 循环保活：`Sleep(200)` + 周期调用导出函数 + 用 volatile 全局阻止常量折叠。
- 新 `scripts/build-target32.ps1`：`vswhere` 定位 VS → `call vcvarsall.bat amd64_x86`（x64→x86 交叉工具链）→ `cl.exe /c` + `link /SUBSYSTEM:CONSOLE /MACHINE:X86` → 产出 `tests/target/simple_target32.exe`。**不提交产物**（`*.exe` 已在 `.gitignore`）。
- `tests/meson.build`：`test_env.set('TEST_WOW64_TARGET_PATH', ...)`。
- 新 `tests/test_wow64.py`（unittest）：exe 不存在时 `@skipUnless(os.path.exists(...))`（对齐 `test_child_process` 模式）。

## 3. 数据流

```
                 Debugger (core/debugger.py)
                    │  session.target_arch (IsWow64Process)
     ┌──────────────┴─────────────────────────────┐
     │                                             │
 ThreadManager / SoftwareBP / HardwareBP          │  machine = target_arch
     │                                             │
     ▼                                             ▼
 Cython: get_thread_context(h, machine)   Cython: set_hw_breakpoint(h, slot, addr, ..., machine)
     │                                             │
     ├─ machine==32 → WOW64_CONTEXT + Wow64Get/SetThreadContext   (WOW64 目标)
     └─ machine==64 → CONTEXT + Get/SetThreadContext              (x64 目标)
     │                                             │
     ▼                                             ▼
 事件循环 run(): WX86 码 0x4000001F/1E ≡ 断点/单步生命周期 → 全部 DBG_CONTINUE
     │
     ▼
 模块枚举: EnumProcessModulesEx(LIST_MODULES_ALL) → 含 32 位 exe/DLL + arch 字段
```

## 4. 错误处理与边界

- Cython 函数 `machine` 参数非法值（非 32/64）→ 默认按 64 处理，或抛出 `ValueError`（与现有 slot 校验一致，倾向抛错更安全）。
- `Wow64GetThreadContext` 失败（如线程已退出）→ `OSError`，沿用现有异常路径。
- WOW64 目标线程在 `Wow64SetThreadContext` 写 DR 前必须 SuspendThread，失败则抛 `ThreadError` 并恢复。
- 执行型 hw 断点命中后清断点失败 → 抛 `BreakpointError`，但不得阻止 `ContinueDebugEvent`（避免目标卡死）。
- `DebugActiveProcessStop` 在主线程挂起时可能返回 `ERROR_ACCESS_DENIED`（demo 实测）——记录为已知限制，必要时重试。

## 5. 已知平台特性（源自 wow64-dbg-demo 实测）

| 特性 | 处理 |
|------|------|
| WX86 异常码 `0x4000001F`/`0x4000001E` 必须 DBG_CONTINUE | 事件循环默认 continue；绝不 NOT_HANDLED |
| WOW64 `Wow64SetThreadContext` 写 Dr0-3 对运行中线程约 3/4 概率不生效 | 写前 `SuspendThread`，写后 `ResumeThread` |
| 执行型 hw 断点命中后必须清除再继续，否则同地址重陷阱 | 命中路径先清除 |
| attach 模式句柄槽可能复用（GetProcessId 校验） | 记录为已知问题；pydbg 已有 `open_process` 逻辑 |
| WOW64 进程存在两套 ntdll（64 位高位 / 32 位低位 <4GB） | 模块 arch 字段按 PE 头判定 |

## 6. 验证目标

1. 现有 x64 测试全绿（CI + 本地）。
2. 新增 `tests/test_wow64.py` 在 x64 CI 上绿：
   - `get_registers` 对 32 位目标返回 x86 名（`eip/eax/esp`）、`arch='x86'`、EIP < 4GB。
   - 导出函数 int3 软件断点：WX86 码 → 断点生命周期正确（IP 回退→恢复→单步→重装），命中后验寄存器/栈。
   - Dr0 硬件断点：下导出函数，命中验证。
   - 模块枚举：能看到 32 位 exe + 32 位 ntdll（base < 4GB），arch 字段正确。
   - 附加模式：附加运行中的 32 位目标。
3. x86 CI job / devtools x86 移除后无残留引用（`grep -ri "x86"` 仅剩目标名/描述）。

## 7. 不做（YAGNI）

- 远程调用引擎（`wdbg_call`、远程加载 32 位 DLL）——pydbg 无此能力，非本次目标。
- 三模块框架（Debugger / Analysis / Instrumentation）——参考文档的长期愿景，未来单独设计。
- WOW64 栈回溯 / 符号解析（`StackWalk64(IMAGE_FILE_MACHINE_I386)`）——后续迭代。
- PEB32 手动模块枚举——用 `EnumProcessModulesEx` 替代。

## 8. 风险与回退

- **WX86 行为因 Windows 版本而异**：Win10 x64 上报 WX86 码已实测；若个别环境直接上报 `0x80000003/04`，事件循环两者都处理（现有逻辑天然覆盖），无回退风险。
- **`EnumProcessModulesEx` 在极老系统缺失**：Windows Vista+ 均支持，无回退需要。
- **交叉编译脚本环境差异**：`scripts/build-target32.ps1` 依赖 vswhere；找不到 VS 时打印明确错误并在 CI/本地跳过 WOW64 测试（`skipUnless` 兜底）。
- **`IsWow64Process` 保持兼容**：升级 `IsWow64Process2` 需 SDK 足够新；本次保留 `IsWow64Process`，注释说明可升级。
