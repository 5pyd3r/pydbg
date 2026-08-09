# setup_venv.ps1 — Create the 64-bit venv with all dependencies (WOW64 targets supported)
#
# Usage:
#   .\scripts\setup_venv.ps1              # setup x64 venv

$ErrorActionPreference = "Stop"

$ROOT_DIR = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

# System Python path (pre-installed, x64)
$PYTHON_X64 = "C:\Users\Spyder\AppData\Local\Python\pythoncore-3.14-64\python.exe"

$venvDir = Join-Path $ROOT_DIR "venv-x64"

Write-Host ""
Write-Host "========== venv-x64 ==========" -ForegroundColor Cyan

if (-not (Test-Path $PYTHON_X64)) {
    Write-Host "[error] Python not found: $PYTHON_X64" -ForegroundColor Red
    exit 1
}

# Show Python version and arch
$pyVer = & $PYTHON_X64 --version 2>&1
$pyArch = & $PYTHON_X64 -c "import struct; print(f'{struct.calcsize('P')*8}-bit')" 2>&1
Write-Host "[info] $pyVer ($pyArch)" -ForegroundColor Gray

# Create venv
if (Test-Path $venvDir) {
    Write-Host "[clean] Removing existing venv-x64" -ForegroundColor Yellow
    Remove-Item -Recurse -Force $venvDir
}

Write-Host "[create] python -m venv venv-x64" -ForegroundColor Yellow
& $PYTHON_X64 -m venv $venvDir
if ($LASTEXITCODE -ne 0) {
    Write-Host "[fail] venv creation" -ForegroundColor Red
    exit 1
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
    exit 1
}

# Install capstone (win_amd64 wheel)
Write-Host "[pip] install capstone" -ForegroundColor Yellow
& $venvPip install "capstone>=5.0"
if ($LASTEXITCODE -ne 0) {
    Write-Host "[fail] capstone install" -ForegroundColor Red
    exit 1
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

Write-Host "[pass] venv-x64 ready" -ForegroundColor Green
Write-Host "  Activate: .\venv-x64\Scripts\Activate.ps1" -ForegroundColor Gray
