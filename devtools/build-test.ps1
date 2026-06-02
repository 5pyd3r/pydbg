# build-test.ps1 — Build and test with embedded Python
# Usage:
#   .\devtools\build-test.ps1              # build & test for host arch
#   .\devtools\build-test.ps1 -Arch x86    # build & test for x86
#   .\devtools\build-test.ps1 -Arch x64    # build & test for x64
#   .\devtools\build-test.ps1 -Arch all    # build & test both

param(
    [ValidateSet("x86", "x64", "all")]
    [string]$Arch = "auto"
)

$ErrorActionPreference = "Stop"

$DEVTOOLS_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$ROOT_DIR = Split-Path -Parent $DEVTOOLS_DIR

if ($Arch -eq "auto") {
    if ([IntPtr]::Size -eq 8) { $Arch = "x64" } else { $Arch = "x86" }
}

function Build-And-Test($name) {
    $python = Join-Path $DEVTOOLS_DIR "python-$name\python.exe"
    if (-not (Test-Path $python)) {
        Write-Host "[error] python-$name not found. Run setup-embedded.ps1 first." -ForegroundColor Red
        return $false
    }

    $build = Join-Path $ROOT_DIR "build-$name"

    Write-Host ""
    Write-Host "========== python-$name ==========" -ForegroundColor Cyan

    # Clean old build
    if (Test-Path $build) { Remove-Item -Recurse -Force $build }

    # Configure
    Write-Host "[configure] meson setup build-$name" -ForegroundColor Yellow
    & $python -m meson setup $build $ROOT_DIR --buildtype=release
    if ($LASTEXITCODE -ne 0) { Write-Host "[fail] configure" -ForegroundColor Red; return $false }

    # Build
    Write-Host "[build] meson compile" -ForegroundColor Yellow
    & $python -m meson compile -C $build
    if ($LASTEXITCODE -ne 0) { Write-Host "[fail] build" -ForegroundColor Red; return $false }

    # Install
    Write-Host "[install] pip install -e ." -ForegroundColor Yellow
    Push-Location $ROOT_DIR
    & $python -m pip install -e . --no-build-isolation 2>&1 | Out-Null
    Pop-Location
    if ($LASTEXITCODE -ne 0) { Write-Host "[fail] install" -ForegroundColor Red; return $false }

    # Test
    Write-Host "[test] meson test" -ForegroundColor Yellow
    & $python -m meson test -C $build --print-errorlogs
    if ($LASTEXITCODE -ne 0) { Write-Host "[fail] test" -ForegroundColor Red; return $false }

    Write-Host "[pass] python-$name OK" -ForegroundColor Green
    return $true
}

$results = @{}

if ($Arch -eq "all") {
    foreach ($a in @("x64", "x86")) {
        $results[$a] = Build-And-Test $a
    }
} else {
    $results[$Arch] = Build-And-Test $Arch
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
