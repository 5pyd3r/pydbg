# setup-embedded.ps1 — Download and configure embedded Python for x64 (WOW64 targets supported)
# Usage: .\devtools\setup-embedded.ps1

$ErrorActionPreference = "Stop"

$PYTHON_VERSION = "3.13.3"
$DEVTOOLS_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$ROOT_DIR = Split-Path -Parent $DEVTOOLS_DIR

$ARCHES = @("amd64")
$NAMES = @("x64")

for ($i = 0; $i -lt $ARCHES.Length; $i++) {
    $arch = $ARCHES[$i]
    $name = $NAMES[$i]
    $dir = Join-Path $DEVTOOLS_DIR "python-$name"

    if (Test-Path "$dir\python.exe") {
        Write-Host "[skip] python-$name already exists" -ForegroundColor Yellow
        continue
    }

    $zip = "python-$PYTHON_VERSION-embed-$arch.zip"
    $url = "https://www.python.org/ftp/python/$PYTHON_VERSION/$zip"
    $tmp = Join-Path $DEVTOOLS_DIR $zip

    Write-Host "[download] $zip ..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $url -OutFile $tmp

    Write-Host "[extract] $dir" -ForegroundColor Cyan
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Expand-Archive -Path $tmp -DestinationPath $dir -Force
    Remove-Item $tmp

    # Enable import site for pip
    $pth = Get-ChildItem "$dir\*._pth" | Select-Object -First 1
    if ($pth) {
        (Get-Content $pth.FullName) -replace '#import site', 'import site' |
            Set-Content $pth.FullName
    }

    # Install pip
    Write-Host "[pip] bootstrapping pip for python-$name ..." -ForegroundColor Cyan
    $getpip = Join-Path $DEVTOOLS_DIR "get-pip.py"
    Invoke-WebRequest -Uri "https://bootstrap.pypa.io/get-pip.py" -OutFile $getpip
    & "$dir\python.exe" $getpip --no-warn-script-location
    Remove-Item $getpip

    # Install project deps
    Write-Host "[deps] installing build dependencies ..." -ForegroundColor Cyan
    & "$dir\python.exe" -m pip install --no-warn-script-location `
        meson meson-python ninja cython flake8 "capstone>=5.0" keystone-engine

    Write-Host "[done] python-$name ready at $dir" -ForegroundColor Green
}

Write-Host ""
Write-Host "Setup complete. Use devtools\build-test.ps1 to build and test." -ForegroundColor Green
