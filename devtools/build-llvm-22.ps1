# build-llvm-22.ps1 — Fetch + build + install LLVM 22.1.8 (the "precompiled" LLVM for pydbg).
#
# Produces C:/Users/Spyder/AppData/Local/llvm-22 with llvm-config.exe, static .lib
# files, and headers. Replicates the llvm-17 recipe (Ninja, MSVC, clang + X86,
# static libs) and forces the /MD CRT so the libs link against pydbg's default
# /MD build (mismatch would fail with LNK2038).
#
# Requirements: VS2022 (Desktop C++), gh CLI, cmake (VS-bundled ok), ninja
# (meson-bundled ok). Run from a normal shell; the script shells into the VS
# x64 devshell itself.
#
# Usage:  powershell -ExecutionPolicy Bypass -File devtools/build-llvm-22.ps1

$ErrorActionPreference = "Stop"

$Version  = "22.1.8"
$Tag      = "llvmorg-$Version"
$Local    = "C:\Users\Spyder\AppData\Local"
$SrcDir   = Join-Path $Local "llvm-22-src"
$BuildDir = Join-Path $Local "llvm-22-build"
$Install  = Join-Path $Local "llvm-22"
$Tarball  = Join-Path $SrcDir "$Tag.tar.gz"

# ── Locate VS (vcvars) + bundled cmake + meson ninja ─────────────────────
$vswhere = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { $vswhere = "C:\Program Files\Microsoft Visual Studio\Installer\vswhere.exe" }
$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1
if (-not $vsPath) { Write-Host "[fail] no VS install"; exit 1 }
$vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
$cmake  = Join-Path $vsPath "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
$ninja  = "C:\Program Files\Meson\ninja.exe"
if (-not (Test-Path $ninja)) { $ninja = (Get-Command ninja -ErrorAction SilentlyContinue).Source }
if (-not $ninja) { Write-Host "[fail] ninja not found (install meson or set PATH)"; exit 1 }

# ── 1. Fetch source via gh (github.com is blocked; api.github.com works) ──
if (-not (Test-Path $Tarball)) {
    Write-Host "[fetch] $Tag source via gh ..."
    New-Item -ItemType Directory -Force -Path $SrcDir | Out-Null
    Push-Location $SrcDir
    try { gh api "repos/llvm/llvm-project/tarball/refs/tags/$Tag" > $Tarball }
    finally { Pop-Location }
    if (-not (Test-Path $Tarball)) { Write-Host "[fail] source download"; exit 1 }
}

# ── 2. Extract (find the dir that contains llvm/CMakeLists.txt) ──────────
$SrcTop = $null
foreach ($d in (Get-ChildItem -Directory $SrcDir -ErrorAction SilentlyContinue)) {
    if (Test-Path (Join-Path $d.FullName "llvm\CMakeLists.txt")) { $SrcTop = $d.FullName; break }
}
if (-not $SrcTop) {
    Write-Host "[extract] $Tag ..."
    tar -xf $Tarball -C $SrcDir   # symlink warnings in clang/test are harmless (tests off)
    foreach ($d in (Get-ChildItem -Directory $SrcDir)) {
        if (Test-Path (Join-Path $d.FullName "llvm\CMakeLists.txt")) { $SrcTop = $d.FullName; break }
    }
}
if (-not $SrcTop) { Write-Host "[fail] source tree not found after extract"; exit 1 }
Write-Host "[src] $SrcTop"

# ── 3. Configure (inside VS x64 devshell so CMake finds cl.exe) ──────────
if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

$conf = @(
    "-S", "$SrcTop\llvm", "-B", $BuildDir,
    "-G", "Ninja",
    "-DCMAKE_MAKE_PROGRAM=`"$ninja`"",
    "-DCMAKE_BUILD_TYPE=Release",
    "-DCMAKE_INSTALL_PREFIX=$Install",
    "-DLLVM_ENABLE_PROJECTS=clang",
    "-DLLVM_TARGETS_TO_BUILD=X86",
    "-DBUILD_SHARED_LIBS=OFF",
    "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL",
    # /utf-8 is required: clang sources are UTF-8; cl.exe otherwise reads them
    # as the system ANSI codepage (936/GBK here), where some UTF-8 bytes form a
    # GBK second byte 0x5C = line-continuation, splicing comments across the next
    # declaration (clang/lib/Lex/UnicodeCharSets.h C2226). Official Windows LLVM
    # builds are built with clang-cl (UTF-8 by default), which hides this.
    # Values are quoted so the spaces inside survive the $conf -join ' ' -> cmd.
    "-DCMAKE_C_FLAGS=`"/DWIN32 /D_WINDOWS /utf-8`"",
    "-DCMAKE_CXX_FLAGS=`"/DWIN32 /D_WINDOWS /EHsc /utf-8`"",
    "-DLLVM_PARALLEL_LINK_JOBS=4",
    "-DLLVM_BUILD_TESTS=OFF", "-DLLVM_BUILD_DOCS=OFF", "-DLLVM_BUILD_EXAMPLES=OFF", "-DLLVM_BUILD_BENCHMARKS=OFF",
    "-DLLVM_INCLUDE_TESTS=OFF", "-DLLVM_INCLUDE_DOCS=OFF", "-DLLVM_INCLUDE_EXAMPLES=OFF", "-DLLVM_INCLUDE_BENCHMARKS=OFF",
    "-DLLVM_ENABLE_ASSERTIONS=OFF",
    "-DLLVM_ENABLE_BINDINGS=OFF", "-DLLVM_ENABLE_OCAMLDOC=OFF",
    "-DLLVM_ENABLE_TERMINFO=OFF", "-DLLVM_ENABLE_LIBEDIT=OFF", "-DLLVM_ENABLE_LIBPFM=OFF",
    "-DLLVM_ENABLE_ZLIB=OFF", "-DLLVM_ENABLE_ZSTD=OFF", "-DLLVM_ENABLE_FFI=OFF",
    "-DLLVM_ENABLE_LLD=OFF", "-DLLVM_ENABLE_LTO=OFF", "-DLLVM_ENABLE_PLUGINS=OFF"
)
Write-Host "[configure] ..."
cmd /c "call `"$vcvars`" >nul 2>&1 && `"$cmake`" $($conf -join ' ')"
if ($LASTEXITCODE -ne 0) { Write-Host "[fail] configure"; exit 1 }

# ── 4. Build (long; ~1-4 h) ──────────────────────────────────────────────
$jobs = $env:NUMBER_OF_PROCESSORS
if (-not $jobs) { $jobs = 8 }
Write-Host "[build] cmake --build (this takes a while) ..."
cmd /c "call `"$vcvars`" >nul 2>&1 && `"$cmake`" --build `"$BuildDir`" -- -j $jobs"
if ($LASTEXITCODE -ne 0) { Write-Host "[fail] build"; exit 1 }

# ── 5. Install ───────────────────────────────────────────────────────────
Write-Host "[install] cmake --install"
cmd /c "call `"$vcvars`" >nul 2>&1 && `"$cmake`" --install `"$BuildDir`""
if ($LASTEXITCODE -ne 0) { Write-Host "[fail] install"; exit 1 }

# ── 6. Verify ────────────────────────────────────────────────────────────
$cfg = Join-Path $Install "bin\llvm-config.exe"
if (-not (Test-Path $cfg)) { Write-Host "[fail] llvm-config missing"; exit 1 }
$v = & $cfg --version
if ($v -ne $Version) { Write-Host "[fail] version $v != $Version"; exit 1 }
if (-not (Test-Path (Join-Path $Install "lib\clangTooling.lib"))) { Write-Host "[fail] clangTooling.lib missing"; exit 1 }
Write-Host "[ok] LLVM $v installed at $Install"
