# Known Issues

*No known issues at this time.*

## Resolved

### PE Parser (6 tests)
**Fixed in #9.** PE32+ optional header had incorrect `NumberOfRvaAndSizes` offset (read from 92 instead of 108), wrong section header struct format (`<IIIIIIIHH` → `<IIIIIIHHI`), and test data used PE32 layout (96 bytes) instead of PE32+ (112 bytes). All 20 PE tests pass.

### ContinueDebugEvent Error 87 (5 tests)
**Fixed in #9.** Cross-test event pollution: `terminate_process` and `run()` left unconsumed `EXIT_PROCESS` debug events, poisoning subsequent tests' `wait_event` calls. Fixed by draining debug events after process termination and consuming events until initial breakpoint before interacting with target process.

### Software Breakpoint WriteProcessMemory Error 998
**Fixed in #9.** `SoftwareBreakpointManager.set()` failed with `ERROR_NOACCESS` when writing int3 byte to code pages without write permission. Fixed by calling `VirtualProtectEx` to set `PAGE_EXECUTE_READWRITE` before writing.

### All @unittest.skip Decorators
**Removed in #9.** All 26 skips removed after fixing the underlying issues.

### Silent failure modes (found by three independent binary-analysis sessions)

Analysing three real 32-bit targets (SpaceSniffer, OllyDbg, μTorrent) surfaced a
family of defects that share a symptom: **the library reports success, or simply
spins, while nothing is progressing.** A silent failure is worse than a loud one
because the caller cannot tell it apart from a target that is merely busy.

- **`run()` spun forever when `WaitForDebugEvent` kept timing out.** `timeout_ms`
  only bounds each individual wait; on timeout the loop simply continued. An
  idle or modal-blocked GUI target produces no events at all, so "idle", "done"
  and "wedged" were indistinguishable, and `run()` never returned. Fixed by
  adding `run(..., max_idle_timeouts=N)`, which raises `TimeoutError` after N
  consecutive empty waits. Defaults to `None` — existing behaviour is unchanged.
- **A breakpoint whose IP could not be rewound reported success.** When setting
  TF or rewinding the instruction pointer failed, `handle_breakpoint_hit()`
  re-armed the INT3 and returned `True`, leaving the IP one byte past the
  breakpoint and the caller believing the hit was handled. The re-arm contract is
  kept (it is deliberate and separately tested), but the failure is now recorded
  in `SoftwareBreakpointManager.degraded_hits` / `.last_error`, and `run()`
  raises `BreakpointError` instead of resuming from mid-instruction.
- **`get_registers()` / `set_registers()` / `set_register()` / `step()` silently
  rejected thread ids.** They take a thread `HANDLE`, but `DebugEvent` carries a
  `tid`, and both are plain Python `int`s — so the mistake is undetectable from
  the signature and surfaces only at runtime as `ERROR_INVALID_HANDLE` (errno 6),
  which points nowhere near the cause. All four now accept either, opening (and
  closing) a handle when given a thread id of the current target.
- **`attach()` left the session without a thread id**, unlike `create_process()`,
  so anything relying on a default thread had nothing to work with. It now
  records the first enumerated thread; this is best-effort and never fatal.

Verified against `tests.test_debugger.TestFailureIsVisible`.

### Installs that silently ran stale code

**Fixed.** `venv-x64` held a non-editable *wheel copy* of pydbg, and
`devtools/build-x64-current.ps1` deployed by copying only the compiled `.pyd`
into site-packages — never the Python layer. Pure-Python edits were therefore
invisible: the source tree showed the fix, `inspect.signature` on the installed
package showed the old signature.

This was not theoretical. A set of fixes was written and tested against the
source tree, then reported complete, while every analysis script importing
`pydbg` from the venv kept running the unfixed build — one of them losing a
session to a `run()` that spun forever instead of raising.

`devtools/rebuild-install.ps1` replaces it and installs **editable**, so the venv
points at the source tree and Python edits take effect on the next import. The
script verifies against the *installed* package with a bare interpreter, because
importing from the source tree passes even with a stale install.

Two things to know about the current setup:

- The editable install currently resolves to the `fix/silent-failures` worktree
  (`.worktrees/silent-failures`). Removing that worktree will break `import pydbg`.
  After the branch is merged, re-run `devtools/rebuild-install.ps1` from the main
  checkout to repoint it.
- meson-python's editable loader regenerates on import, but only needs a compiler
  when a source file actually changed. The venv's `Scripts` dir must be on `PATH`
  at import time so `meson` is findable — i.e. the venv must be activated.

Still open, recorded rather than fixed:

- `enum_modules()` raises `ERROR_PARTIAL_COPY` (299) while a target sits on the
  loader breakpoint — precisely when module info is first wanted. The
  `CREATE_PROCESS` event already carries `lpBaseOfImage`; a `module_at(addr)`
  accessor built on that would avoid the enumeration entirely.
- `create_process()` cannot pass a command line, which forces callers onto the
  `attach()` path (and so loses all startup-time breakpoints) for any target
  configured by argv.
- Software breakpoints are silently lost when the target overwrites them
  (self-unpacking code does this by design); `find_breakpoint()` cannot report
  that state.
- `read_memory()` discards partial results across uncommitted pages
  (`ERROR_PARTIAL_COPY`) rather than returning what it did read.

## WOW64 (32 位目标) 调试平台特性

- **WX86 异常码**：32 位代码的断点/单步经 WoW64 层上报为
  `STATUS_WX86_BREAKPOINT (0x4000001F)` / `STATUS_WX86_SINGLE_STEP (0x4000001E)`。
  事件循环把两者当"已处理"继续（DBG_CONTINUE）；不得传 DBG_EXCEPTION_NOT_HANDLED，
  否则异常会传给目标 SEH 链，普通目标（无断点处理器）会因此终止。
- **硬件断点写入**：WOW64 线程直接 `Wow64SetThreadContext` 写 Dr0-3 约 3/4 概率不生效
  （demo 实测），`HardwareBreakpointManager.set/clear` 会先 `SuspendThread` 再写。
- **执行型硬件断点**：命中后须先清除断点再 `ContinueDebugEvent`，否则同地址反复重陷阱
  （WOW64 与 x64 通用）。
- **模块枚举**：WOW64 进程同时存在 32/64 位模块（两套 ntdll）。pydbg 用
  `EnumProcessModulesEx(LIST_MODULES_ALL)` + 按 PE 头判定 `arch`。主镜像不产生
  LOAD_DLL 事件，模块枚举须在加载器初始化完成后调用（WOW64 首个断点发生在 64 位
  bootstrap、32 位镜像映射之前，此时 `enum_modules` 看不到 32 位 exe）。
- **附加模式**：`DebugActiveProcessStop` 在目标主线程挂起时可能返回
  `ERROR_ACCESS_DENIED`（瞬态），必要时重试；句柄槽可能被调试子系统复用，调用方需用
  `GetProcessId` 校验（当前未自动处理）。
