# build-test.ps1 — Build and test with the x64 embedded Python (WOW64 targets supported).
# Usage:
#   .\devtools\build-test.ps1

$ErrorActionPreference = "Stop"

$DEVTOOLS_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$ROOT_DIR = Split-Path -Parent $DEVTOOLS_DIR

$python = Join-Path $DEVTOOLS_DIR "python-x64\python.exe"
if (-not (Test-Path $python)) {
    Write-Host "[error] python-x64 not found. Run setup-embedded.ps1 first." -ForegroundColor Red
    exit 1
}

$build = Join-Path $ROOT_DIR "build-x64"
if (Test-Path $build) { Remove-Item -Recurse -Force $build }

Write-Host "[configure] meson setup build-x64" -ForegroundColor Yellow
& $python -m meson setup $build $ROOT_DIR --buildtype=release
if ($LASTEXITCODE -ne 0) { Write-Host "[fail] configure" -ForegroundColor Red; exit 1 }

Write-Host "[build] meson compile" -ForegroundColor Yellow
& $python -m meson compile -C $build
if ($LASTEXITCODE -ne 0) { Write-Host "[fail] build" -ForegroundColor Red; exit 1 }

Write-Host "[build] 32-bit WOW64 test target" -ForegroundColor Yellow
& powershell -ExecutionPolicy Bypass -File (Join-Path $ROOT_DIR "scripts\build-target32.ps1")
if ($LASTEXITCODE -ne 0) { Write-Host "[fail] build-target32" -ForegroundColor Red; exit 1 }

Write-Host "[pip] install capstone" -ForegroundColor Yellow
& $python -m pip install "capstone>=5.0" 2>&1 | Out-Null

Write-Host "[install] pip install -e ." -ForegroundColor Yellow
Push-Location $ROOT_DIR
& $python -m pip install -e . --no-build-isolation 2>&1 | Out-Null
Pop-Location
if ($LASTEXITCODE -ne 0) { Write-Host "[fail] install" -ForegroundColor Red; exit 1 }

Write-Host "[test] meson test" -ForegroundColor Yellow
& $python -m meson test -C $build --print-errorlogs
if ($LASTEXITCODE -ne 0) { Write-Host "[fail] test" -ForegroundColor Red; exit 1 }

Write-Host "[pass] python-x64 OK" -ForegroundColor Green
