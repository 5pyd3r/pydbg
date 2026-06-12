# build_clang.ps1 — Build pydbg using clang with VS DevShell environment
#
# Usage:
#   .\scripts\build_clang.ps1              # build for host arch
#   .\scripts\build_clang.ps1 -Arch x86    # build for x86
#   .\scripts\build_clang.ps1 -Arch x64    # build for x64
#   .\scripts\build_clang.ps1 -Arch all    # build both

param(
    [ValidateSet("x86", "x64", "all", "auto")]
    [string]$Arch = "auto",
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

if ($Arch -eq "auto") {
    if ([IntPtr]::Size -eq 8) { $Arch = "x64" } else { $Arch = "x86" }
}

# Venv Python paths
$VENV_X64_PYTHON = Join-Path $ROOT_DIR "venv-x64\Scripts\python.exe"
$VENV_X86_PYTHON = Join-Path $ROOT_DIR "venv-x86\Scripts\python.exe"

function Build-WithClang($name, $vsArch, $venvPython) {
    Write-Host ""
    Write-Host "========== Build $name (clang) ==========" -ForegroundColor Cyan

    if (-not (Test-Path $venvPython)) {
        Write-Host "[error] venv-$name not found. Run setup_venv.ps1 first." -ForegroundColor Red
        return $false
    }

    $buildDir = Join-Path $ROOT_DIR "build-clang-$name"

    # Clean old build
    if (Test-Path $buildDir) {
        Remove-Item -Recurse -Force $buildDir
    }

    # Create clang native file
    $nativeFile = Join-Path $ROOT_DIR "native-clang-$name.ini"
    if ($name -eq "x86") {
        @"
[binaries]
c = 'clang-cl'
cpp = 'clang-cl'
ar = 'llvm-ar'
link = 'lld-link'

[host_machine]
system = 'windows'
cpu_family = 'x86'
cpu = 'i686'
endian = 'little'

[built-in options]
c_args = ['-m32']
c_link_args = ['-m32']
"@ | Set-Content -Path $nativeFile -Encoding UTF8
    } else {
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
    }

    # Configure with meson using clang
    Write-Host "[configure] meson setup build-clang-$name" -ForegroundColor Yellow

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

    $result = Invoke-Command -ScriptBlock $scriptBlock -ArgumentList $vsDevShell, $vsArch, $venvPython, $mesonArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[fail] meson setup" -ForegroundColor Red
        return $false
    }

    # Compile
    Write-Host "[build] meson compile -C build-clang-$name" -ForegroundColor Yellow
    $compileBlock = {
        param($devShell, $arch, $python, $buildDir)
        & $devShell -Arch $arch -HostArch amd64 -SkipAutomaticLocation | Out-Null
        & $python -m meson compile -C $buildDir
    }
    $result = Invoke-Command -ScriptBlock $compileBlock -ArgumentList $vsDevShell, $vsArch, $venvPython, $buildDir
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[fail] compile" -ForegroundColor Red
        return $false
    }

    # Install
    Write-Host "[install] pip install -e ." -ForegroundColor Yellow
    Push-Location $ROOT_DIR
    & $venvPython -m pip install -e . --no-build-isolation 2>&1 | Out-Null
    Pop-Location
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[fail] install" -ForegroundColor Red
        return $false
    }

    # Test
    if ($RunTests) {
        Write-Host "[test] meson test" -ForegroundColor Yellow
        $testBlock = {
            param($devShell, $arch, $python, $buildDir)
            & $devShell -Arch $arch -HostArch amd64 -SkipAutomaticLocation | Out-Null
            & $python -m meson test -C $buildDir --print-errorlogs
        }
        $result = Invoke-Command -ScriptBlock $testBlock -ArgumentList $vsDevShell, $vsArch, $venvPython, $buildDir
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[fail] test" -ForegroundColor Red
            return $false
        }
    }

    Write-Host "[pass] build-clang-$name OK" -ForegroundColor Green
    return $true
}

$results = @{}

if ($Arch -eq "all") {
    $results["x64"] = Build-WithClang "x64" "amd64" $VENV_X64_PYTHON
    $results["x86"] = Build-WithClang "x86" "x86" $VENV_X86_PYTHON
} elseif ($Arch -eq "x64") {
    $results["x64"] = Build-WithClang "x64" "amd64" $VENV_X64_PYTHON
} else {
    $results["x86"] = Build-WithClang "x86" "x86" $VENV_X86_PYTHON
}

Write-Host ""
Write-Host "========== Summary ==========" -ForegroundColor Cyan
foreach ($a in $results.Keys) {
    $status = if ($results[$a]) { "PASS" } else { "FAIL" }
    $color = if ($results[$a]) { "Green" } else { "Red" }
    Write-Host "  $a : $status" -ForegroundColor $color
}

$failed = $results.Values | Where-Object { -not $_ }
if ($failed) { exit 1 }
