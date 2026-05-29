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
