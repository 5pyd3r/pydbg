# rebuild-install.ps1 — Rebuild pydbg from this checkout and install it editable.
#
# Replaces the older build-x64-current.ps1, which had two problems that cost real
# debugging time:
#   1. $Root was hardcoded to a *different* checkout (ai_eden\Output\pydbg), so
#      running it here built the wrong tree.
#   2. It copied only the compiled .pyd into site-packages and never the Python
#      layer. Edits to src/pydbg/*.py therefore silently had no effect — the
#      installed package kept running old code while the source looked correct.
#      This was hit for real: a set of fixes was written, tested against the
#      source tree, and reported as done, while every analysis script importing
#      pydbg from the venv was still running the unfixed version.
#
# An editable install removes that whole class of problem: the venv points at
# this source tree, so Python edits take effect on the next import.
#
# Usage:
#   pwsh devtools/rebuild-install.ps1 [-Root <path>] [-LlvmConfig <path>]
#
# Notes:
#   - Must run from a checkout that has venv-x64/ (see scripts/setup_venv.ps1).
#   - Git for Windows ships its own link.exe; the build runs inside vcvarsall so
#     MSVC's linker wins. Do NOT reset PATH inside the cmd invocation — %PATH% is
#     expanded when cmd parses the whole line, so a later `set PATH=...%PATH%`
#     silently discards everything vcvarsall just configured.
#   - meson-python's editable loader regenerates the build on import, but only
#     needs a compiler when a source file actually changed. The venv's Scripts
#     dir must be on PATH at import time so `meson` is findable.

param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot),
    [string]$LlvmConfig = ""
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path (Join-Path $Root "pyproject.toml"))) {
    Write-Host "[fail] $Root does not look like the pydbg checkout (no pyproject.toml)"
    exit 1
}
# venv-x64 is gitignored, so a `git worktree` checkout does not have one. Walk up
# from $Root to find the one belonging to the parent checkout — that is the normal
# case when installing a feature branch from an isolated worktree.
$VenvRoot = $Root
while ($VenvRoot -and -not (Test-Path (Join-Path $VenvRoot "venv-x64\Scripts\python.exe"))) {
    $parent = Split-Path -Parent $VenvRoot
    if ($parent -eq $VenvRoot) { $VenvRoot = $null; break }
    $VenvRoot = $parent
}
if (-not $VenvRoot) {
    Write-Host "[fail] no venv-x64 at or above $Root — run scripts/setup_venv.ps1 first"
    exit 1
}
$Py = Join-Path $VenvRoot "venv-x64\Scripts\python.exe"
Write-Host "[root] $Root"
if ($VenvRoot -ne $Root) { Write-Host "[venv] $VenvRoot (found above the source tree)" }

$vswhere = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    $vswhere = "C:\Program Files\Microsoft Visual Studio\Installer\vswhere.exe"
}
$vsPath = & $vswhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath | Select-Object -First 1
if (-not $vsPath) { Write-Host "[fail] no Visual Studio with C++ tools found"; exit 1 }
$vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvarsall.bat"
Write-Host "[vs]   $vcvars"

# Put the venv on PATH *before* invoking vcvarsall, so vcvarsall prepends MSVC
# on top of it. Setting PATH the other way round loses the MSVC entries.
$env:PATH = "$(Join-Path $VenvRoot 'venv-x64\Scripts');$env:PATH"

$pipArgs = "-m pip install -e . --no-build-isolation"
if ($LlvmConfig) {
    $pipArgs += " --config-settings=setup-args=-Denable-llvm-instrument=true"
    $pipArgs += " --config-settings=setup-args=-Dllvm-config=$LlvmConfig"
    Write-Host "[llvm] $LlvmConfig"
} else {
    Write-Host "[llvm] disabled (pass -LlvmConfig to enable)"
}

Write-Host "[build+install] $pipArgs"
cmd /c "call `"$vcvars`" amd64 >nul 2>&1 && cd /d `"$Root`" && `"$Py`" $pipArgs"
if ($LASTEXITCODE -ne 0) { Write-Host "[fail] build/install"; exit 1 }

# Verify against the *installed* package, not the source tree: importing with a
# bare interpreter is the only way to catch a stale or non-editable install.
Write-Host "[verify] importing pydbg without PYTHONPATH"
$verify = @'
import inspect, sys
import pydbg
from pydbg import Debugger
print("  resolved ->", pydbg.__file__)
print("  run()     ", inspect.signature(Debugger.run))
missing = [n for n in ("_as_thread_handle",) if not hasattr(Debugger(), n)]
print("  expected attributes present:", not missing)
sys.exit(1 if missing else 0)
'@
$tmp = Join-Path $env:TEMP "pydbg_verify.py"
Set-Content -Path $tmp -Value $verify -Encoding UTF8
& $Py $tmp
if ($LASTEXITCODE -ne 0) { Write-Host "[fail] verification"; exit 1 }
Remove-Item $tmp -ErrorAction SilentlyContinue

Write-Host "[done] pydbg rebuilt and installed editable from $Root"
Write-Host "       Python edits now take effect on the next import;"
Write-Host "       a compiler is only needed when a source file changes."
