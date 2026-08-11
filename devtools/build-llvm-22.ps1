# build-llvm-22.ps1 — Obtain the prebuilt LLVM 22 used by pydbg's instrumentation backend.
#
# Default: download the prebuilt LLVM 22.1.8 from this repo's GitHub release
# `llvm-prebuilt-22.1.8` (asset llvm-22.1.8-x86_64-windows.zip) and install it
# at C:/Users/Spyder/AppData/Local/llvm-22. The release asset is built once from
# source; nobody needs to compile LLVM locally.
#
#   -BuildFromSource   Instead of downloading, compile LLVM 22.1.8 from source
#                      (the original recipe; slow, ~1-3h). Used to rebuild the
#                      prebuilt asset or as an offline fallback.
#
# Requirements (download path): gh CLI (uses api.github.com, reliable even when
# github.com:443 is flaky). Source path additionally needs VS2022 + cmake + ninja.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File devtools/build-llvm-22.ps1
#   powershell -ExecutionPolicy Bypass -File devtools/build-llvm-22.ps1 -BuildFromSource

param(
    [switch]$BuildFromSource
)

$ErrorActionPreference = "Stop"

$Version  = "22.1.8"
$Release  = "llvm-prebuilt-22.1.8"
$Asset    = "llvm-22.1.8-x86_64-windows.7z"
$SevenZip = "C:\Program Files\7-Zip\7z.exe"
$Repo     = "5pyd3r/pydbg"
$Local    = "C:\Users\Spyder\AppData\Local"
$Install  = Join-Path $Local "llvm-22"

if (-not $BuildFromSource) {
    # ── Fast path: download the prebuilt install ───────────────────────
    $cfg = Join-Path $Install "bin\llvm-config.exe"
    if (Test-Path $cfg) {
        $v = & $cfg --version
        if ($v -eq $Version) {
            Write-Host "[ok] LLVM $Version already installed at $Install"
            exit 0
        }
        Write-Host "[info] found $v at $Install (need $Version) — replacing"
    }

    Write-Host "[download] $Asset from $Repo release $Release ..."
    $tmp = Join-Path $Local "llvm-22-download"
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    $dst = Join-Path $tmp $Asset
    # curl -C - resumes a partial download — robust against the flaky APAC link
    # to github.com / objects.githubusercontent.com; --retry re-attempts drops.
    curl -L -C - --retry 5 --retry-all-errors -o $dst `
        "https://github.com/$Repo/releases/download/$Release/$Asset"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[fail] download (github unreachable? try -BuildFromSource)"; exit 1
    }

    Write-Host "[extract] ..."
    if (-not (Test-Path $SevenZip)) { Write-Host "[fail] 7-Zip not found at $SevenZip"; exit 1 }
    & $SevenZip x (Join-Path $tmp $Asset) "-o$tmp" -y | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Host "[fail] extract"; exit 1 }

    if (Test-Path $Install) { Remove-Item -Recurse -Force $Install }
    Move-Item (Join-Path $tmp "llvm-22") $Install
    Remove-Item -Recurse -Force $tmp

    $v = & (Join-Path $Install "bin\llvm-config.exe") --version
    if ($v -ne $Version) { Write-Host "[fail] version $v != $Version"; exit 1 }
    if (-not (Test-Path (Join-Path $Install "lib\clangTooling.lib"))) {
        Write-Host "[fail] clangTooling.lib missing"; exit 1
    }
    Write-Host "[ok] LLVM $Version (prebuilt) installed at $Install"
    exit 0
}

# ═══════════════════════════════════════════════════════════════════════
#  -BuildFromSource: compile LLVM 22.1.8 from source (mirrors the original
#  recipe that produced the release asset). 1-3h.
# ═══════════════════════════════════════════════════════════════════════
$Tag      = "llvmorg-$Version"
$SrcDir   = Join-Path $Local "llvm-22-src"
$BuildDir = Join-Path $Local "llvm-22-build"
$Tarball  = Join-Path $SrcDir "$Tag.tar.gz"

$vswhere = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { $vswhere = "C:\Program Files\Microsoft Visual Studio\Installer\vswhere.exe" }
$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1
if (-not $vsPath) { Write-Host "[fail] no VS install"; exit 1 }
$vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
$cmake  = Join-Path $vsPath "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
$ninja  = "C:\Program Files\Meson\ninja.exe"
if (-not (Test-Path $ninja)) { $ninja = (Get-Command ninja -ErrorAction SilentlyContinue).Source }
if (-not $ninja) { Write-Host "[fail] ninja not found"; exit 1 }

if (-not (Test-Path $Tarball)) {
    Write-Host "[fetch] $Tag source via gh ..."
    New-Item -ItemType Directory -Force -Path $SrcDir | Out-Null
    Push-Location $SrcDir
    try { gh api "repos/llvm/llvm-project/tarball/refs/tags/$Tag" > $Tarball }
    finally { Pop-Location }
    if (-not (Test-Path $Tarball)) { Write-Host "[fail] source download"; exit 1 }
}

$SrcTop = $null
foreach ($d in (Get-ChildItem -Directory $SrcDir -ErrorAction SilentlyContinue)) {
    if (Test-Path (Join-Path $d.FullName "llvm\CMakeLists.txt")) { $SrcTop = $d.FullName; break }
}
if (-not $SrcTop) {
    Write-Host "[extract] $Tag ..."
    tar -xf $Tarball -C $SrcDir
    foreach ($d in (Get-ChildItem -Directory $SrcDir)) {
        if (Test-Path (Join-Path $d.FullName "llvm\CMakeLists.txt")) { $SrcTop = $d.FullName; break }
    }
}
if (-not $SrcTop) { Write-Host "[fail] source tree not found after extract"; exit 1 }
Write-Host "[src] $SrcTop"

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
    # /utf-8 required: clang sources are UTF-8; cl.exe reads them as the system
    # ANSI codepage (936/GBK here), where some UTF-8 bytes form a GBK second byte
    # 0x5C (line-continuation), splicing comments across the next declaration
    # (clang/lib/Lex/UnicodeCharSets.h C2226). Values are quoted so the spaces
    # survive the $conf -join ' ' -> cmd.
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

$jobs = $env:NUMBER_OF_PROCESSORS
if (-not $jobs) { $jobs = 8 }
Write-Host "[build] cmake --build (this takes a while) ..."
cmd /c "call `"$vcvars`" >nul 2>&1 && `"$cmake`" --build `"$BuildDir`" -- -j $jobs"
if ($LASTEXITCODE -ne 0) { Write-Host "[fail] build"; exit 1 }

Write-Host "[install] cmake --install"
cmd /c "call `"$vcvars`" >nul 2>&1 && `"$cmake`" --install `"$BuildDir`""
if ($LASTEXITCODE -ne 0) { Write-Host "[fail] install"; exit 1 }

$v = & (Join-Path $Install "bin\llvm-config.exe") --version
if ($v -ne $Version) { Write-Host "[fail] version $v != $Version"; exit 1 }
Write-Host "[ok] LLVM $Version (source-built) installed at $Install"
