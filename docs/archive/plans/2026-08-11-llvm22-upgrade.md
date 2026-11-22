# LLVM 17 → 22 Upgrade Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade the precompiled LLVM used by the pydbg instrumentation backend from 17.0.6 to 22.1.8, keeping the precompiled (source-built-once) model, and make the full instrument test suite pass against LLVM 22.

**Architecture:** Build LLVM 22.1.8 from source (replicating the llvm-17 recipe: Ninja/MSVC, `clang`+`X86`, static libs, forced /MD) and install it to `C:/Users/Spyder/AppData/Local/llvm-22`. Point pydbg's meson build at llvm-22, migrate the C++ backend's LLVM API usage (mostly `legacy::PassManager`/`addPassesToEmitFile` and clang `tooling` entry points) for the 17→22 API changes, then verify with the live-instrument tests.

**Tech Stack:** CMake, Ninja, MSVC cl (VS2022 17.14 / 14.44), meson, Cython, C++17, LLVM/clang C++ API, Python unittest (meson test).

**Environment facts (verified):**
- Working dir for code changes: `C:/Users/Spyder/Desktop/ai_eden/Output/pydbg-llvm22` (worktree, branch `refactor/llvm-22`).
- LLVM-17 install: `C:/Users/Spyder/AppData/Local/llvm-17` (kept as rollback).
- llvm-17 recipe (from its CMakeCache): Ninja, cl 14.44, Release, `LLVM_ENABLE_PROJECTS=clang`, `LLVM_TARGETS_TO_BUILD=X86`, `BUILD_SHARED_LIBS=OFF`; produced libs are **/MD**.
- pydbg builds /MD (meson default); llvm libs must be /MD or linking fails with LNK2038.
- `gh` CLI is the working route to GitHub (github.com:443 blocked; api.github.com works).
- Meson ninja: `C:/Program Files/Meson/ninja.exe`; CMake: VS-bundled `3.31.6`.
- Build script runs in a VS2022 x64 devshell (`vcvars64.bat`).

---

### Task 1: Add reproducible LLVM 22 build script

**Files:**
- Create: `devtools/build-llvm-22.ps1`

- [ ] **Step 1: Write the script**

```powershell
# build-llvm-22.ps1 — Fetch + build + install LLVM 22.1.8 (the "precompiled" LLVM for pydbg).
# Produces C:/Users/Spyder/AppData/Local/llvm-22 with llvm-config.exe, static libs, headers.
# Replicates the llvm-17 recipe; forces /MD CRT to match pydbg's build.
# Requires: VS2022, cmake (VS-bundled ok), ninja (meson-bundled ok), git, gh.
$ErrorActionPreference = "Stop"

$Version  = "22.1.8"
$Tag      = "llvmorg-$Version"
$Local    = "C:\Users\Spyder\AppData\Local"
$SrcDir   = Join-Path $Local "llvm-22-src"
$BuildDir = Join-Path $Local "llvm-22-build"
$Install  = Join-Path $Local "llvm-22"
$Tarball  = Join-Path $SrcDir "$Tag.tar.gz"

# 1. Fetch source via gh (github.com is blocked; api.github.com works)
if (-not (Test-Path $Tarball)) {
    Write-Host "[fetch] $Tag source ..."
    New-Item -ItemType Directory -Force -Path $SrcDir | Out-Null
    Push-Location $SrcDir
    try { gh api "repos/llvm/llvm-project/tarball/refs/tags/$Tag" > $Tarball }
    finally { Pop-Location }
    if (-not (Test-Path $Tarball)) { Write-Host "[fail] source download"; exit 1 }
}

# 2. Extract (top-level dir from github tarball may be repo-<sha>; find llvm/CMakeLists.txt)
$SrcTop = $null
foreach ($d in (Get-ChildItem -Directory $SrcDir)) {
    if (Test-Path (Join-Path $d.FullName "llvm\CMakeLists.txt")) { $SrcTop = $d.FullName; break }
}
if (-not $SrcTop) {
    Write-Host "[extract] ..."
    tar -xf $Tarball -C $SrcDir
    foreach ($d in (Get-ChildItem -Directory $SrcDir)) {
        if (Test-Path (Join-Path $d.FullName "llvm\CMakeLists.txt")) { $SrcTop = $d.FullName; break }
    }
}
if (-not $SrcTop) { Write-Host "[fail] source tree not found after extract"; exit 1 }
Write-Host "[src] $SrcTop"

# 3. Configure inside a VS x64 devshell (so CMake finds cl.exe / link.exe)
if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

$cmake = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
$ninja = "C:\Program Files\Meson\ninja.exe"
$vcvars = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

$conf = @(
    "-S", "$SrcTop\llvm", "-B", $BuildDir,
    "-G", "Ninja",
    "-DCMAKE_MAKE_PROGRAM=$ninja",
    "-DCMAKE_BUILD_TYPE=Release",
    "-DCMAKE_INSTALL_PREFIX=$Install",
    "-DLLVM_ENABLE_PROJECTS=clang",
    "-DLLVM_TARGETS_TO_BUILD=X86",
    "-DBUILD_SHARED_LIBS=OFF",
    "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL",
    "-DLLVM_BUILD_TESTS=OFF", "-DLLVM_BUILD_DOCS=OFF", "-DLLVM_BUILD_EXAMPLES=OFF", "-DLLVM_BUILD_BENCHMARKS=OFF",
    "-DLLVM_INCLUDE_TESTS=OFF", "-DLLVM_INCLUDE_DOCS=OFF", "-DLLVM_INCLUDE_EXAMPLES=OFF", "-DLLVM_INCLUDE_BENCHMARKS=OFF",
    "-DLLVM_ENABLE_ASSERTIONS=OFF",
    "-DLLVM_ENABLE_BINDINGS=OFF", "-DLLVM_ENABLE_OCAMLDOC=OFF",
    "-DLLVM_ENABLE_TERMINFO=OFF", "-DLLVM_ENABLE_LIBEDIT=OFF", "-DLLVM_ENABLE_LIBPFM=OFF",
    "-DLLVM_ENABLE_ZLIB=OFF", "-DLLVM_ENABLE_ZSTD=OFF", "-DLLVM_ENABLE_FFI=OFF",
    "-DLLVM_ENABLE_LLD=OFF", "-DLLVM_ENABLE_LTO=OFF", "-DLLVM_ENABLE_PLUGINS=OFF"
)
cmd /c "call `"$vcvars`" >nul 2>&1 && `"$cmake`" $($conf -join ' ')"
if ($LASTEXITCODE -ne 0) { Write-Host "[fail] configure"; exit 1 }

# 4. Build (long; ~1-4h). Show ninja -j N.
Write-Host "[build] cmake --build (this takes a while) ..."
cmd /c "call `"$vcvars`" >nul 2>&1 && `"$cmake`" --build `"$BuildDir`" -- -j 16"
if ($LASTEXITCODE -ne 0) { Write-Host "[fail] build"; exit 1 }

# 5. Install
Write-Host "[install] cmake --install"
cmd /c "call `"$vcvars`" >nul 2>&1 && `"$cmake`" --install `"$BuildDir`""
if ($LASTEXITCODE -ne 0) { Write-Host "[fail] install"; exit 1 }

# 6. Verify
$cfg = Join-Path $Install "bin\llvm-config.exe"
if (-not (Test-Path $cfg)) { Write-Host "[fail] llvm-config missing"; exit 1 }
$v = & $cfg --version
if ($v -ne $Version) { Write-Host "[fail] version $v != $Version"; exit 1 }
if (-not (Test-Path (Join-Path $Install "lib\clangTooling.lib"))) { Write-Host "[fail] clangTooling.lib missing"; exit 1 }
Write-Host "[ok] LLVM $v installed at $Install"
```

- [ ] **Step 2: Lint check** — script has no syntax errors (open in editor / run with `-WhatIf`-free dry review).

- [ ] **Step 3: Commit**

```bash
cd C:/Users/Spyder/Desktop/ai_eden/Output/pydbg-llvm22
git add devtools/build-llvm-22.ps1
git commit -m "feat(llvm): add reproducible LLVM 22.1.8 build script"
```

---

### Task 2: Run the LLVM 22.1.8 build (long, background)

**Files:**
- None (runs the script from Task 1; outputs to `C:/Users/Spyder/AppData/Local/llvm-22`)

- [ ] **Step 1: Run the script in the background**

```bash
cd C:/Users/Spyder/Desktop/ai_eden/Output/pydbg-llvm22
powershell -ExecutionPolicy Bypass -File devtools/build-llvm-22.ps1   # run_in_background
```

- [ ] **Step 2: Wait for completion** (background task notification). While waiting, proceed to Task 3 (does not need llvm-22 yet).

- [ ] **Step 3: Verify install**

```bash
C:/Users/Spyder/AppData/Local/llvm-22/bin/llvm-config.exe --version    # -> 22.1.8
ls C:/Users/Spyder/AppData/Local/llvm-22/lib/clangFrontend.lib         # exists
# CRT check (must be MD_DynamicRelease):
MSYS_NO_PATHCONV=1 "C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64/dumpbin.exe" -directives C:/Users/Spyder/AppData/Local/llvm-22/lib/LLVMSupport.lib | grep -i "RuntimeLibrary"
```

---

### Task 3: Point pydbg's build at llvm-22

**Files:**
- Modify: `src/pydbg/instrument/llvm_backend/meson.build:1-33`
- Modify: `meson.options:4-10`
- Modify: `meson.build:16-21`
- Modify: `README.md:97-98`

- [ ] **Step 1: Update `llvm_backend/meson.build` search order** — replace the header comment and the `find_program`/fallback block:

```meson
# LLVM Instrument 后端 — 静态链接预编译 LLVM 22 + clang 组件库
llvm_config = ''
llvm_cfg = get_option('llvm-config')
if llvm_cfg != ''
  llvm_config = find_program(llvm_cfg, native : true)
else
  llvm_config = find_program(
    'llvm-config', 'llvm-config-22', 'llvm-config-18', 'llvm-config-17',
    required : false)
endif

if not llvm_config.found()
  llvm_search_dirs = [
    'C:/Users/Spyder/AppData/Local/llvm-22',
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
    error('LLVM Instrument requires llvm-config. Install prebuilt LLVM 22 or set -Dllvm-config=/path/to/llvm-config')
  endif
endif
```

- [ ] **Step 2: Update `meson.options` description**

```meson
option('enable-llvm-instrument',
  type : 'boolean',
  value : false,
  description : 'Enable LLVM-based instrumentation backend (requires prebuilt LLVM 22, static clang)')

option('llvm-config',
  type : 'string',
  value : '',
  description : 'Path to llvm-config binary. Default: search prebuilt LLVM 22 locations.')
```

- [ ] **Step 3: Update root `meson.build` messages (17 → 22)**

```meson
if get_option('enable-llvm-instrument')
  message('LLVM Instrument: ENABLED')
else
  message('LLVM Instrument: DISABLED (set -Denable-llvm-instrument=true)')
endif
```

- [ ] **Step 4: Update `README.md`**

```markdown
stub/trampoline 用硬编码指令生成，payload 由 LLVM 22 动态编译 C 源码为机器码并注入目标进程。
需以 `-Denable-llvm-instrument=true` 构建，并预装 LLVM 22（检测 `C:/Users/Spyder/AppData/Local/llvm-22` 或 `-Dllvm-config=`）。
```

- [ ] **Step 5: Configure + build the backend against llvm-22**

```bash
cd C:/Users/Spyder/Desktop/ai_eden/Output/pydbg-llvm22
# in a VS devshell:
meson setup build-x64 --buildtype=release -Denable-llvm-instrument=true
meson compile -C build-x64
```
Expected: meson reports `LLVM Instrument: using prebuilt LLVM at C:/Users/Spyder/AppData/Local/llvm-22`. Compile may fail — that is expected and handled by Tasks 4-7.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "build(llvm): point instrumentation backend at prebuilt LLVM 22"
```

---

### Task 4: Migrate `target_codegen.cpp` to LLVM 22

> Verified against the 22.1.8 source headers: `addPassesToEmitFile(PassManagerBase&, ...)`
> still exists (`llvm/Target/TargetMachine.h:426`, with `using legacy::PassManagerBase`);
> `llvm::legacy::PassManager` still exists (`llvm/IR/LegacyPassManager.h:53`). The **only**
> break: the scoped `llvm::CodeGenFileType` enum replaced the flat `llvm::CGFT_*` values
> (`llvm/Support/CodeGen.h:111`).

**Files:**
- Modify: `src/pydbg/instrument/llvm_backend/target_codegen.cpp:29,314`

- [ ] **Step 1: Add the include** (after the existing `#include <llvm/Target/TargetOptions.h>` at line 29):

```cpp
#include <llvm/Support/CodeGen.h>   /* CodeGenFileType::ObjectFile (LLVM >= 18) */
```

- [ ] **Step 2: Replace the file-type constant** (line 314):

```cpp
    if (targetMachine_->addPassesToEmitFile(pm, os, nullptr,
                                             llvm::CodeGenFileType::ObjectFile)) {
```

(Also update the pipeline comment on line 10 `(CGFT_ObjectFile)` → `(CodeGenFileType::ObjectFile)`.)

- [ ] **Step 3: Rebuild the backend**

```bash
meson compile -C build-x64
```
Expected: `target_codegen.cpp` compiles clean (this is the only code change in the file).

---

### Task 5: Verify `clang_to_ir.cpp` / `hook_compiler.cpp` compile unchanged

> Verified against 22.1.8 headers — **no code changes expected**:
> - `clang::tooling::runToolOnCodeWithArgs(unique_ptr<FrontendAction>, const Twine &,
>   const std::vector<std::string>&, const Twine&, ...)` — 4-arg call unchanged
>   (`clang/Tooling/Tooling.h:187`).
> - `DiagnosticsEngine::setFatalsAsError(bool)` present (`clang/Basic/Diagnostic.h:716`).
> - `DiagnosticConsumer::HandleDiagnostic(DiagnosticsEngine::Level, const Diagnostic&)` —
>   unchanged (`clang/Basic/Diagnostic.h:1789`); `Diagnostic::FormatDiagnostic` present.
> - clang AST walk + IRBuilder + `InitializeAll*` + ObjectFile relocations — stable.

**Files:**
- None (verification only)

- [ ] **Step 1: Rebuild and confirm both files compile**

```bash
meson compile -C build-x64
```
Expected: no errors in `clang_toir_ir.cpp` / `hook_compiler.cpp`. If a new compile error
appears, fix it against the 22 headers (grep the specific header) and commit with Task 7.

---

### Task 6: Resolve the LLVM 22 clang static-lib link set

**Files:**
- Modify: `src/pydbg/instrument/llvm_backend/meson.build:55-77`

- [ ] **Step 1: Inspect what clang libs llvm-22 installs**

```bash
ls C:/Users/Spyder/AppData/Local/llvm-22/lib/clang*.lib
```

- [ ] **Step 2: Iterate the `_clang_libs` list and `_llvm_clang_extras`** against linker (LNK) errors until `_llvm_backend.pyd` links. Expected to need additions/removals vs the 17 set.

- [ ] **Step 3: Rebuild the full backend** until `_llvm_backend.cp314-win_amd64.pyd` is produced.

- [ ] **Step 4: Commit** the meson.build link-set change.

---

### Task 7: Full backend build + smoke import

> Verified in advance: `createTargetMachine(const Triple&, StringRef, StringRef,
> const TargetOptions&, std::optional<Reloc::Model>, std::optional<CodeModel::Model>,
> CodeGenOptLevel, bool)` — the existing 5-arg call still compiles (`Reloc::Static`
> converts to `std::optional<Reloc::Model>` implicitly). No change needed.

**Files:**
- None (unless new compile errors appear)

- [ ] **Step 1: Rebuild the whole backend; fix any unexpected compile error** consulting the 22 headers for each.

- [ ] **Step 2: Confirm `_llvm_backend.pyd` builds and imports**

```bash
# in a VS devshell
meson compile -C build-x64
python -c "import sys; sys.path.insert(0,'src'); from pydbg.instrument.codegen import _backend; print(_backend())"
```

- [ ] **Step 3: Commit** remaining C++ fixes.

---

### Task 8: Acceptance — live instrument tests + full suite

**Files:**
- None (verification)

- [ ] **Step 1: Build the 32-bit WOW64 target**

```bash
powershell -ExecutionPolicy Bypass -File scripts/build-target32.ps1
```

- [ ] **Step 2: Run the full meson test suite**

```bash
meson test -C build-x64 --print-errorlogs
```
Expected: **`TestInstrumentLive` (x64 + WOW64) pass** — live hook injection through the LLVM 22 codegen (+103/round, install/restore roundtrip). Also full baseline (non-LLVM) suite passes.

- [ ] **Step 3: Lint**

```bash
flake8 src/ tests/ --max-line-length=120
```

---

### Task 9: Commit, PR

- [ ] **Step 1: Commit any remaining changes**

```bash
git add -A
git commit -m "feat(llvm): migrate instrumentation backend to LLVM 22"
```

- [ ] **Step 2: Push and open a PR** (title `feat: upgrade prebuilt LLVM 17 to 22`, body: 改动摘要、文件列表、CI 链接、自主决策记录). Do **not** merge — user merges.

---

## Self-Review

1. **Spec coverage**: spec sections 1-5 map to Tasks 1-3 (build+script+meson), 4-7 (API migration), 4/8 (tests), 5 (git/PR). Rollback = llvm-17 kept (Task 2 note). ✓
2. **Placeholders**: none. Tasks 4-5 are filled with the exact fixes verified against the 22.1.8 source headers (see Task 4/5 header notes). The only execution-time iteration is Task 6 (clang lib link set), driven by linker errors. ✓
3. **Type consistency**: `CodeGenFileType::ObjectFile`, `runToolOnCodeWithArgs`, `MultiThreadedDLL` used consistently. ✓
