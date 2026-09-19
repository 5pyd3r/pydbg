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

# A .pyd sitting next to the package sources wins over the editable build, so
# src/pydbg/_pydbg*.pyd shadows the one this script just built. It used to be
# put there deliberately — scripts/build_venv.py copied the built extension into
# src/pydbg/ so the package was importable without installing it, and this
# script refreshed that copy.
#
# That whole arrangement is gone. The copy was never needed: with it removed,
# _pydbg resolves to the editable build's own output under build/ (verified —
# import and every symbol work, and the suite passes), because the editable
# loader maps the compiled module exactly as it maps the Python one. The copy
# only ever *hid* the real extension, and it went stale after any Cython
# change — silently, because the Python layer stayed current while the compiled
# layer did not: `import pydbg` succeeded and the damage surfaced later as an
# AttributeError from a function the old extension never had.
#
# So: delete it rather than refresh it, and assert below that the extension
# Python loads is the editable build's. Nothing under version control may hold
# a build output — the editable loader turns that from a style rule into a
# correctness one.
Write-Host "[ext]  removing any shadowing copy from src/pydbg/"
$shadow = Get-ChildItem -Path (Join-Path $Root "src\pydbg") `
    -Filter "_pydbg*.pyd" -ErrorAction SilentlyContinue
foreach ($stale in $shadow) {
    Write-Host "       deleted $($stale.Name)"
    Remove-Item $stale.FullName -Force
}
if (-not $shadow) { Write-Host "       (none present)" }

# Verify against the *installed* package, not the source tree: importing with a
# bare interpreter is the only way to catch a stale or non-editable install.
Write-Host "[verify] importing pydbg without PYTHONPATH"
$env:PYDBG_ROOT = $Root
$verify = @'
import os, sys
import pydbg
from pydbg import _pydbg

root = os.path.abspath(os.environ["PYDBG_ROOT"])
print("  package   ->", pydbg.__file__)
print("  extension ->", _pydbg.__file__)

problems = []
if not os.path.abspath(pydbg.__file__).startswith(os.path.join(root, "src")):
    problems.append("pydbg did not resolve into this checkout's src/ "
                    "(not an editable install of it?)")
if not os.path.abspath(_pydbg.__file__).startswith(os.path.join(root, "build")):
    problems.append("the compiled extension did not come from build/ "
                    "(a copy in src/pydbg/ is shadowing the editable build?)")

if problems:
    for line in problems:
        print("  [fail]", line)
    print("")
    print("  Both cases pass a pure-Python assertion while the compiled")
    print("  layer is old or elsewhere; only the resolved paths show it.")
sys.exit(1 if problems else 0)
'@
$tmp = Join-Path $env:TEMP "pydbg_verify.py"
Set-Content -Path $tmp -Value $verify -Encoding UTF8
& $Py $tmp
if ($LASTEXITCODE -ne 0) { Write-Host "[fail] verification"; exit 1 }
Remove-Item $tmp -ErrorAction SilentlyContinue

Write-Host "[done] pydbg rebuilt and installed editable from $Root"
Write-Host "       Python edits now take effect on the next import;"
Write-Host "       a compiler is only needed when a source file changes."
