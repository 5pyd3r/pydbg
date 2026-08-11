# LLVM 17 → 22 Prebuilt Upgrade — Design

Date: 2026-08-11
Status: Approved
Branch: `refactor/llvm-22`

## Goal

Upgrade the precompiled LLVM that the pydbg instrumentation backend links
against from **LLVM 17.0.6** to **LLVM 22.1.8**, keeping the "precompiled"
model: pydbg's build consumes a pre-built LLVM install directory; LLVM is not
compiled as part of pydbg's build.

## Current state (verified)

- pydbg links clang + LLVM **statically** (deliberate "no libclang.dll"
  design). The backend lives in `src/pydbg/instrument/llvm_backend/`
  (`hook_compiler.cpp`, `clang_to_ir.cpp`, `target_codegen.cpp`) and is built
  only when `-Denable-llvm-instrument=true`.
- The current "precompiled LLVM 17" is `C:/Users/Spyder/AppData/Local/llvm-17`
  (17.0.6, 3.3 GB): a **locally source-built** install with `llvm-config.exe`,
  ~140 static `.lib` files (incl. `clangTooling.lib`, `clangFrontend.lib`),
  and headers.
- Build discovery: `src/pydbg/instrument/llvm_backend/meson.build` uses
  `find_program('llvm-config', 'llvm-config-18', 'llvm-config-17')`, then a
  fallback scan of `C:/Users/Spyder/AppData/Local/llvm-17` and
  `C:/Program Files/LLVM` for `bin/llvm-config.exe`.
- CRT: llvm-17 libs are **/MD** (`/FAILIFMISMATCH:RuntimeLibrary=MD_DynamicRelease`
  per `dumpbin /directives`); pydbg builds with meson default **/MD**. They match.
- The official LLVM Windows release binaries are **toolchain-only** (no headers,
  no static libs, no `llvm-config.exe`) — confirmed by LLVM mailing lists — so
  they cannot satisfy the static-linking design.
- The downloaded `llvm-core-libs-22.1.4-x86_64-windows-static-md.tar.xz` contains
  only 8 LLVM core static libs and **no clang component libs / clang headers** —
  insufficient; not used.
- Network: `github.com:443` is unreachable from this machine; `api.github.com`
  works; `gh` CLI successfully downloads GitHub release assets and `gh api
  .../tarball/<tag>` streams the source archive.

## Decisions

1. **Source of LLVM 22**: build from source (mirrors how llvm-17 was produced),
   installed to `C:/Users/Spyder/AppData/Local/llvm-22`.
2. **Version**: LLVM **22.1.8** (latest patch of LLVM 22).
3. **CRT**: force **/MD** (`-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL`) so the
   produced libs match pydbg's /MD default (avoids LNK2038).
4. **Backend stays opt-in**: `-Denable-llvm-instrument=true` remains required;
   default builds (`devtools/build-x64-current.ps1`, CI) unchanged.
5. **Recipe is committed**: a reproducible `devtools/build-llvm-22.ps1` script is
   added (llvm-17 had no such script; its exact configure command is lost).
6. **llvm-17 is kept** untouched as rollback; meson falls back to it if llvm-22
   is absent.

## Implementation plan (sketch)

### 1. Acquire + build LLVM 22.1.8

- Fetch `llvmorg-22.1.8` source via `gh api repos/llvm/llvm-project/tarball/refs/tags/llvmorg-22.1.8`
  (~230 MB) → extract to `C:/Users/Spyder/AppData/Local/llvm-22-src/`.
- Configure in `C:/Users/Spyder/AppData/Local/llvm-22-build/`, install to
  `C:/Users/Spyder/AppData/Local/llvm-22/` (Ninja, VS2022 cl 14.44, Release):
  - `-DLLVM_ENABLE_PROJECTS=clang`
  - `-DLLVM_TARGETS_TO_BUILD=X86`
  - `-DBUILD_SHARED_LIBS=OFF`
  - `-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL`
  - tests/docs/examples/benchmarks off; `LLVM_ENABLE_TERMINFO/LIBEDIT/LIBPFM/ZLIB/ZSTD/FFI=OFF`;
    `LLVM_ENABLE_ASSERTIONS=OFF`.
- Build in the background (multi-hour); then `cmake --install`.
- Verify: `llvm-config --version` = 22.1.8; `clangTooling.lib` / `clangFrontend.lib`
  present; `dumpbin /directives` shows `MD_DynamicRelease`.
- Encode all of the above in `devtools/build-llvm-22.ps1`.

### 2. Update pydbg build scripts

- `src/pydbg/instrument/llvm_backend/meson.build`: search llvm-22 first
  (`C:/Users/Spyder/AppData/Local/llvm-22`), add `llvm-config-22` to
  `find_program`, update comments/error text.
- `meson.options`, root `meson.build`, `README.md`: "LLVM 17" → "LLVM 22",
  update the documented prebuilt path.

### 3. Migrate C++ backend (LLVM 17 → 22 API)

Verify each of the following against the real 22 headers; fix as needed:

- **High risk**: `llvm::legacy::PassManager` + `TargetMachine::addPassesToEmitFile`
  (`target_codegen.cpp::emitObjectFile`) — may be removed in 22; replace with the
  new pass-manager object-emission path if so.
- **Medium risk**: `clang::tooling::runToolOnCodeWithArgs` (`clang_to_ir.cpp`) —
  may be consolidated/deprecated; `createTargetMachine` optional
  `Reloc::Model` / `CodeGenOptLevel` params.
- **Low risk (verify)**: clang AST walk (ASTConsumer/FrontendAction/diagnostics),
  IRBuilder, `InitializeAll*`, ObjectFile/SectionRef/RelocationRef, `Triple`.
- **Link set**: iterate LNK errors — clang static lib list and
  `_llvm_clang_extras` (`LLVMOption`, `LLVMWindowsDriver`, `LLVMFrontendOpenMP`,
  `version.lib`) will change in 22.
- MSVC header-compat flags (`/D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH`,
  `/wd4146`, `/wd4624`) — keep, adjust only if 22 headers demand it (LLVM is
  built with the same cl 14.44, so STL versions match).

### 4. Test / acceptance

- Build the backend in the worktree with `-Denable-llvm-instrument=true`
  against llvm-22; build the 32-bit WOW64 test target.
- `meson test` must pass, including **`TestInstrumentLive` (x64 + WOW64)**:
  live C-source hook injection through the LLVM 22 codegen (+103/round
  assertion, install/restore roundtrip).
- Full baseline suite + `flake8 src/ tests/ --max-line-length=120`.

### 5. Git workflow (CLAUDE.md rules)

- All changes on `refactor/llvm-22` in the `../pydbg-llvm22` worktree; never
  commit on master. Commit and open a PR for the user to merge.
- The LLVM source/build/install directories live under `AppData/Local`, outside
  the repo.

## Risks

- **Long build time** (~1–4 h on this machine). Mitigated: background run,
  X86-only targets, clang-only project.
- **LLVM 22 may require a newer MSVC than installed.** cl 14.44 (VS 2022 17.14)
  is current; unlikely. If CMake rejects, surface immediately.
- **Unforeseen API breaks.** Mitigated by iterative compile against the real
  headers; the risky surfaces are enumerated above.
- **Download flakiness** via `gh` for the 230 MB archive. Retry; verify sha of
  the extracted tree (`llvm-config.h` version) before building.
- **CRT mismatch** would fail linking; forced /MD + dumpbin verification removes it.

## Rollback

- Keep `llvm-17`. Delete `llvm-22` (or the meson search-order change) to revert
  the dev environment. The feature-branch git history reverts the code.

## Non-goals

- No switch to dynamic `libclang.dll`/`LLVM-C.dll` linking.
- No enabling of the backend in CI or default builds.
- No change to the supported target matrix (X86-only LLVM build, as today).
- The incomplete `llvm-core-libs-22.1.4` tarball is ignored.
