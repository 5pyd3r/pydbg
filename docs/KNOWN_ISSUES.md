# Known Issues

*No known issues at this time.*

## Resolved

### PE Parser (6 tests)
**Fixed in #9.** PE32+ optional header had incorrect `NumberOfRvaAndSizes` offset (read from 92 instead of 108), wrong section header struct format (`<IIIIIIIHH` → `<IIIIIIHHI`), and test data used PE32 layout (96 bytes) instead of PE32+ (112 bytes). All 20 PE tests pass.

> **Correction (2026-09-19): the section header format was NOT fixed by #9.**
> `parser.py` still read `<IIIIIIIHH` — one dword too many and a word too few —
> so `SectionHeader.characteristics` held only its high 16 bits. A section
> declared `0x60000020` came back as `0x6000`, which meant
> `IMAGE_SCN_MEM_EXECUTE` (0x20000000) never matched and **no section was ever
> executable** to any consumer. It went unnoticed because the fixtures build
> `SectionHeader` objects directly and none of them asserted on the field;
> only reading a real image through the parser shows it. Fixed in #47, with
> the round-trip now covered by a test.
>
> The general lesson is worth more than the fix: a "fixed in #N" note is a
> claim about the *parser*, and #9's evidence was a set of tests that bypass
> the parser for this field. The note was read as settled for months.

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

- meson-python's editable loader regenerates on import, but only needs a compiler
  when a source file actually changed. The venv's `Scripts` dir must be on `PATH`
  at import time so `meson` is findable — i.e. the venv must be activated. Without
  it the error is `re-building the pydbg meson-python editable wheel package
  failed`, which points away from the actual cause.

Two traps that bite when rebuilding in a checkout that has been built before,
both of which surface as misleading errors:

- **`src/pydbg/_pydbg.cp314-win_amd64.pyd` shadows the editable build.** It is
  placed there by `scripts/build_venv.py` and gitignored, so it is easy to forget.
  An out-of-date copy makes the import fail with
  `cannot import name 'STATUS_WX86_BREAKPOINT'` — which reads like a broken build,
  when the fresh build is fine and merely hidden. Copy the newly built extension
  from `build/cp314/src/pydbg/cython/` over it.
- **A stale `build/cp314/` from a 32-bit build** fails the link with
  `LNK1112: module machine type 'x64' conflicts with target machine type 'x86'`.
  Remove `build/cp314` and reconfigure.

Neither is visible from the source tree. Both are caught by importing the
*installed* package with a bare interpreter, which is what the verify step in
`devtools/rebuild-install.ps1` does.

### Dynamic-analysis gaps (found by the same three analysis sessions)

The same three targets surfaced a second family: capabilities whose absence
pushed every caller into hand-rolling a workaround. Recorded in
`targets/pydbg-gaps.md` §C and fixed here.

- **`enum_modules()` raised `ERROR_PARTIAL_COPY` (299) on the loader
  breakpoint** — precisely when module info is first wanted. `CREATE_PROCESS`
  and `LOAD_DLL` name every image the loader maps, so those bases are now
  recorded from the events and `module_at(addr)` answers from that table with
  no syscall. `enum_modules()` falls back to it too, and merges in images PSAPI
  cannot see (on WOW64 the 32-bit image is not mapped at the first breakpoint).
- **`create_process()` could not pass a command line**, forcing callers onto
  the `attach()` path — and so losing every startup-time breakpoint — for any
  target configured by argv. It now takes `cmdline=`, passed verbatim with
  `lpApplicationName` naming the image.
- **Software breakpoints went silent when the target overwrote them.**
  Self-unpacking code does this by design; one session had the OEP overwritten
  by the unpacker's own output and the breakpoint simply stopped firing. There
  is no event to hang detection on, so `verify_breakpoints()` answers on
  request instead of the state being unknowable.
- **`read_memory()` discarded partial results** across uncommitted pages
  (`ERROR_PARTIAL_COPY`), losing the bytes it had already read.
  `read_memory_safe()` walks regions, keeps everything readable, and reports
  the rest as `gaps`.
- **No memory region enumeration** (`VirtualQueryEx` chain) and **no
  `run_until(addr, timeout)`** — "did it get there?" was a wall-clock guess,
  with a 90s and a 210s run both unable to distinguish "never reached" from
  "reached and quiet". Both now exist; `run_until` raises `TimeoutError`
  carrying the last instruction pointer.

One coupling this broke, worth remembering: `tests/test_wow64.py::_launch` used
`enum_modules()` **raising** `ERROR_PARTIAL_COPY` as its signal that the loader
had not yet mapped the 32-bit image — it was reading the bug as a feature, and
so the sequencing of the WOW64 tests depended on it. The event-table fallback
removed the raise and the helper broke out of its loop one loader breakpoint
too early. It now asks PSAPI explicitly — `enumerate_handle()` without
`allow_event_fallback` — instead of inferring from a failure. Note that "the
image's PE header is readable" is *not* a substitute: that becomes true long
before PSAPI will report the module.

Two bugs were found in the same code while fixing these:

- `create_process()` passed the path to `CreateProcessA` as UTF-8 into an ANSI
  API, and handed it a Python `bytes` object's buffer as `lpCommandLine` —
  which Win32 may modify in place. Both fixed (ANSI code page, heap buffer).
- `run()` raised `TimeoutError` without `core/debugger.py` ever importing it,
  so the class callers actually got was the **builtin**, not the
  `pydbg.exceptions.TimeoutError` documented in the README and exported from
  `__all__`. `except pydbg.exceptions.TimeoutError` never fired. It now raises
  the documented class.

### Two control-flow graphs, one exported surface

`pydbg.analysis.cfg` replaced the older CFG in `disasm/analysis.py` — explicit
`indirect`/`ret` markers, a `complete` flag, and calls kept out of the
intra-function flow instead of modelled as flow into the callee. The old one
was never removed, so `pydbg.build_cfg` and `pydbg.analysis` both answered
"what does this function's control flow look like" and callers got whichever
they reached for first. The old one parsed branch targets out of the
disassembler's *text* output and walked with recursion.

Removed, along with its exports and the 29 tests that covered it — an API break
that was signed off before it was made. What those tests were protecting is
covered against the surviving implementation in
`test_analysis_runtime.py::TestFunctionCFG`.

The residue is worth naming: **a re-added alias fails nothing.** Both graphs
build, both return blocks, both have edges; only their answers differ, and
nothing compares them. `TestOnlyOneControlFlowGraph` exists so that the
removal stays done and says why.

### Reads that returned short instead of failing

`FileSource.read(offset, size)` past the end of a file returned a short slice,
where `BytesSource` raised `ValueError`. A short slice is indistinguishable
from data at the call site, so a caller that did not check `len()` parsed a
truncated structure and had nothing to notice. `Source.try_read` normalised
both into `None` and every directory walk went through it, which is why this
survived: the one path that papered over the disagreement was the one
everything used.

Both sources raise now. `try_read` keeps its length check anyway, because it
is the single place that decides what leniency means to the `pe/` callers.

The same shape appeared twice more in this round: `parse_rich_header` returned
`None` both for "this image has no Rich header" and for "it has one that does
not decode" — the second being the interesting one, since it means a
nonstandard or deliberately mangled stub. It now returns a `RichHeader` with
`malformed` set for the second case, and `xor_key` is `None` rather than a
made-up zero when the key itself was truncated.

### A test that only ran under an optional backend

`Instrumenter._alloc_near` scans ±2GB of the target's address space for a free
region. Its only coverage was the live instrument round-trip tests, and those
are skipped unless the LLVM backend is built — so in a default local build the
entire scan never executed. Rewriting it onto `MemoryManager.regions_handle`
would have been verified only in CI's `llvm-instrument` job.

`TestAllocNear` covers it without the backend: the allocation lands inside the
window, is 64KB-aligned (the E9 rel32 range check depends on that), and two
successive calls do not return the same address.

The general lesson is the one §D of `targets/pydbg-gaps.md` keeps re-teaching:
**"covered by a test" and "covered in the configuration you are running" are
different claims**, and a `skipUnless` on an optional backend silently moves a
test from the first to the second.

### An unbounded read whose size came from the target

`read_memory_safe(addr, size)` walked regions and issued a read per region with
no ceiling. `size` normally comes from a header field or a length in the
target's own memory, so a corrupt one meant a multi-gigabyte allocation and a
sweep of the address space, with nothing to say it was a typo.

It now refuses a request over `max_bytes` (default `DEFAULT_MAX_READ`, 512 MiB)
by raising `ValueError` — not by truncating, which was the tempting option.
`MemoryRead.gaps` holds `(address, size, win32_error)` triples and a
policy truncation has no `win32_error` to report, so it would have arrived
looking exactly like uncommitted memory. Truncating here would have produced
one more entry in this file.

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
