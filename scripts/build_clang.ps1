# build_clang.ps1 — Build pydbg (x64) using clang with VS DevShell environment
#
# Usage:
#   .\scripts\build_clang.ps1              # build x64
#   .\scripts\build_clang.ps1 -RunTests    # build x64 + run tests

param(
    [switch]$RunTests
)

$ErrorActionPreference = "Stop"

$ROOT_DIR = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

# Activate VS DevShell
$VSCOMMUNITY = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\Launch-VsDevShell.ps1"
$VSBUILDTOOLS = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\Launch-VsDevShell.ps1"

if (Test-Path $VSCOMMUNITY) {
    $vsDevShell = $VSCOMMUNITY
} elseif (Test-Path $VSBUILDTOOLS) {
    $vsDevShell = $VSBUILDTOOLS
} else {
    Write-Host "[error] VS DevShell not found" -ForegroundColor Red
    exit 1
}

# Venv Python path (x64)
$VENV_X64_PYTHON = Join-Path $ROOT_DIR "venv-x64\Scripts\python.exe"
$VS_ARCH = "amd64"

if (-not (Test-Path $VENV_X64_PYTHON)) {
    Write-Host "[error] venv-x64 not found. Run setup_venv.ps1 first." -ForegroundColor Red
    exit 1
}

$buildDir = Join-Path $ROOT_DIR "build-clang-x64"

# Clean old build
if (Test-Path $buildDir) {
    Remove-Item -Recurse -Force $buildDir
}

# Create clang native file (x64)
$nativeFile = Join-Path $ROOT_DIR "native-clang-x64.ini"
@"
[binaries]
c = 'clang-cl'
cpp = 'clang-cl'
ar = 'llvm-ar'
link = 'lld-link'

[host_machine]
system = 'windows'
cpu_family = 'x86_64'
cpu = 'x86_64'
endian = 'little'

[built-in options]
c_args = ['-m64']
c_link_args = ['-m64']
"@ | Set-Content -Path $nativeFile -Encoding UTF8

# Configure with meson using clang
Write-Host "[configure] meson setup build-clang-x64" -ForegroundColor Yellow

# Launch in VS DevShell context
$mesonArgs = @("setup", $buildDir, $ROOT_DIR,
               "--buildtype=release",
               "--native-file=$nativeFile",
               "--reconfigure")

$scriptBlock = {
    param($devShell, $arch, $python, $mesonArgs)
    & $devShell -Arch $arch -HostArch amd64 -SkipAutomaticLocation | Out-Null
    & $python -m meson @mesonArgs
}

Invoke-Command -ScriptBlock $scriptBlock -ArgumentList $vsDevShell, $VS_ARCH, $VENV_X64_PYTHON, $mesonArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host "[fail] meson setup" -ForegroundColor Red
    exit 1
}

# Compile
Write-Host "[build] meson compile -C build-clang-x64" -ForegroundColor Yellow
$compileBlock = {
    param($devShell, $arch, $python, $buildDir)
    & $devShell -Arch $arch -HostArch amd64 -SkipAutomaticLocation | Out-Null
    & $python -m meson compile -C $buildDir
}
Invoke-Command -ScriptBlock $compileBlock -ArgumentList $vsDevShell, $VS_ARCH, $VENV_X64_PYTHON, $buildDir
if ($LASTEXITCODE -ne 0) {
    Write-Host "[fail] compile" -ForegroundColor Red
    exit 1
}

# Install
Write-Host "[install] pip install -e ." -ForegroundColor Yellow
Push-Location $ROOT_DIR
& $VENV_X64_PYTHON -m pip install -e . --no-build-isolation 2>&1 | Out-Null
Pop-Location
if ($LASTEXITCODE -ne 0) {
    Write-Host "[fail] install" -ForegroundColor Red
    exit 1
}

# Test
if ($RunTests) {
    Write-Host "[test] meson test" -ForegroundColor Yellow
    $testBlock = {
        param($devShell, $arch, $python, $buildDir)
        & $devShell -Arch $arch -HostArch amd64 -SkipAutomaticLocation | Out-Null
        & $python -m meson test -C $buildDir --print-errorlogs
    }
    Invoke-Command -ScriptBlock $testBlock -ArgumentList $vsDevShell, $VS_ARCH, $VENV_X64_PYTHON, $buildDir
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[fail] test" -ForegroundColor Red
        exit 1
    }
}

Write-Host "[pass] build-clang-x64 OK" -ForegroundColor Green
