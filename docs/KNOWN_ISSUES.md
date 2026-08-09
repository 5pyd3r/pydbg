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
