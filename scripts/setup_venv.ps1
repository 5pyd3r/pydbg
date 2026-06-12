# setup_venv.ps1 — Create 32-bit and 64-bit venvs with all dependencies
#
# Usage:
#   .\scripts\setup_venv.ps1              # setup both architectures
#   .\scripts\setup_venv.ps1 -Arch x64    # setup x64 only
#   .\scripts\setup_venv.ps1 -Arch x86    # setup x86 only

param(
    [ValidateSet("x86", "x64", "all")]
    [string]$Arch = "all"
)

$ErrorActionPreference = "Stop"

$ROOT_DIR = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

# System Python paths (pre-installed)
$PYTHON_X64 = "C:\Users\Spyder\AppData\Local\Python\pythoncore-3.14-64\python.exe"
$PYTHON_X86 = "C:\Users\Spyder\AppData\Local\Python\pythoncore-3.14-32\python.exe"

function Setup-Venv($name, $pythonExe) {
    $venvDir = Join-Path $ROOT_DIR "venv-$name"

    Write-Host ""
    Write-Host "========== venv-$name ==========" -ForegroundColor Cyan

    if (-not (Test-Path $pythonExe)) {
        Write-Host "[error] Python not found: $pythonExe" -ForegroundColor Red
        return $false
    }

    # Show Python version and arch
    $pyVer = & $pythonExe --version 2>&1
    $pyArch = & $pythonExe -c "import struct; print(f'{struct.calcsize('P')*8}-bit')" 2>&1
    Write-Host "[info] $pyVer ($pyArch)" -ForegroundColor Gray

    # Create venv
    if (Test-Path $venvDir) {
        Write-Host "[clean] Removing existing venv-$name" -ForegroundColor Yellow
        Remove-Item -Recurse -Force $venvDir
    }

    Write-Host "[create] python -m venv venv-$name" -ForegroundColor Yellow
    & $pythonExe -m venv $venvDir
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[fail] venv creation" -ForegroundColor Red
        return $false
    }

    $venvPython = Join-Path $venvDir "Scripts\python.exe"
    $venvPip = Join-Path $venvDir "Scripts\pip.exe"

    # Upgrade pip
    Write-Host "[pip] upgrade pip" -ForegroundColor Yellow
    & $venvPython -m pip install --upgrade pip 2>&1 | Out-Null

    # Install common build dependencies
    Write-Host "[pip] install build deps" -ForegroundColor Yellow
    & $venvPip install meson meson-python ninja cython pytest pytest-cov flake8 keystone-engine
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[fail] build deps install" -ForegroundColor Red
        return $false
    }

    # Install capstone (standard package has both win32 and win_amd64 wheels)
    Write-Host "[pip] install capstone" -ForegroundColor Yellow
    & $venvPip install "capstone>=5.0"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[fail] capstone install" -ForegroundColor Red
        return $false
    }

    # Verify imports
    Write-Host "[verify] checking imports..." -ForegroundColor Yellow
    & $venvPython -c @"
import sys
print(f'  Python {sys.version}')
import struct
print(f'  Arch: {struct.calcsize('P')*8}-bit')
try:
    import capstone
    print(f'  capstone: {capstone.cs_version()}')
except ImportError as e:
    print(f'  capstone: FAILED - {e}')
try:
    import keystone
    print(f'  keystone: OK')
except ImportError as e:
    print(f'  keystone: FAILED - {e}')
try:
    import cython
    print(f'  cython: {cython.__version__}')
except ImportError as e:
    print(f'  cython: FAILED - {e}')
"@

    Write-Host "[pass] venv-$name ready" -ForegroundColor Green
    Write-Host "  Activate: .\venv-$name\Scripts\Activate.ps1" -ForegroundColor Gray
    return $true
}

$results = @{}

if ($Arch -eq "all") {
    $results["x64"] = Setup-Venv "x64" $PYTHON_X64
    $results["x86"] = Setup-Venv "x86" $PYTHON_X86
} elseif ($Arch -eq "x64") {
    $results["x64"] = Setup-Venv "x64" $PYTHON_X64
} else {
    $results["x86"] = Setup-Venv "x86" $PYTHON_X86
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
