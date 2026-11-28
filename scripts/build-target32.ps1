# build-target32.ps1 — 用 MSVC x64→x86 交叉工具链编译 32 位 WOW64 测试目标。
# 产物 tests/target/simple_target32.exe 不提交进仓库（*.exe 已 gitignore）。
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) { Write-Host '[error] vswhere not found'; exit 1 }
$vs = & $vswhere -latest -property installationPath
if (-not $vs) { Write-Host '[error] Visual Studio not found'; exit 1 }
$outDir = Join-Path $root 'tests\target'
New-Item -ItemType Directory -Force $outDir | Out-Null
$tmp = Join-Path $root '.build-target32.cmd'
try {
    $bat = "@echo off`n" +
           "call `"$vs\VC\Auxiliary\Build\vcvarsall.bat`" amd64_x86 >nul 2>&1`n" +
           "cd /d `"$root`"`n" +
           "cl /nologo /O2 /W3 /utf-8 /c tests\target\simple_target32.c /Fo$outDir\simple_target32.obj`n" +
           "if errorlevel 1 exit /b %errorlevel%`n" +
           "link /nologo /subsystem:console /machine:x86 /OUT:$outDir\simple_target32.exe $outDir\simple_target32.obj`n" +
           "if errorlevel 1 exit /b %errorlevel%`n" +
           "cl /nologo /O2 /W3 /utf-8 /c tests\target\spawn_child.c /Fo$outDir\spawn_child.obj`n" +
           "if errorlevel 1 exit /b %errorlevel%`n" +
           "link /nologo /subsystem:console /machine:x86 /OUT:$outDir\spawn_child.exe $outDir\spawn_child.obj`n" +
           "if errorlevel 1 exit /b %errorlevel%`n" +
           "cl /nologo /O2 /W3 /utf-8 /c tests\target\threaded_target32.c /Fo$outDir\threaded_target32.obj`n" +
           "if errorlevel 1 exit /b %errorlevel%`n" +
           "link /nologo /subsystem:console /machine:x86 /OUT:$outDir\threaded_target32.exe $outDir\threaded_target32.obj`n" +
           "if errorlevel 1 exit /b %errorlevel%`n" +
           "cl /nologo /O2 /W3 /utf-8 /c tests\target\instrument_target32.c /Fo$outDir\instrument_target32.obj`n" +
           "if errorlevel 1 exit /b %errorlevel%`n" +
           "link /nologo /subsystem:console /machine:x86 /OUT:$outDir\instrument_target32.exe $outDir\instrument_target32.obj`n" +
           "if errorlevel 1 exit /b %errorlevel%`n" +
           "cl /nologo /O2 /W3 /utf-8 /c tests\target\child_target.c /Fo$outDir\child_target32.obj`n" +
           "if errorlevel 1 exit /b %errorlevel%`n" +
           "link /nologo /subsystem:console /machine:x86 /OUT:$outDir\child_target32.exe $outDir\child_target32.obj`n" +
           "if errorlevel 1 exit /b %errorlevel%`n" +
           "rem P41: 32-bit PDB sample. /Zi makes the compiler write types and`n" +
           "rem symbols, /DEBUG makes the linker write pdb_target32.pdb beside`n" +
           "rem the image (the test reads it offline; nothing runs this target).`n" +
           "rem /Fd keeps the compiler's own PDB under tests\target too instead`n" +
           "rem of the repository root.`n" +
           "cl /nologo /O2 /W3 /utf-8 /Zi /Fd$outDir\pdb_target32_compiler.pdb /c tests\target\pdb_target32.c /Fo$outDir\pdb_target32.obj`n" +
           "if errorlevel 1 exit /b %errorlevel%`n" +
           "link /nologo /subsystem:console /machine:x86 /DEBUG /PDB:$outDir\pdb_target32.pdb /OUT:$outDir\pdb_target32.exe $outDir\pdb_target32.obj`n" +
           "if errorlevel 1 exit /b %errorlevel%`n" +
           "rem 32-bit BBL acceptance target (docs/analysis-coverage.md §12.5 item 6):`n" +
           "rem the same in-module loop as loop_target, compiled for WOW64.`n" +
           "cl /nologo /O2 /W3 /utf-8 /c tests\target\loop_target32.c /Fo$outDir\loop_target32.obj`n" +
           "if errorlevel 1 exit /b %errorlevel%`n" +
           "link /nologo /subsystem:console /machine:x86 /OUT:$outDir\loop_target32.exe $outDir\loop_target32.obj`n" +
           "if errorlevel 1 exit /b %errorlevel%`n" +
           "echo BUILD_OK"
    Set-Content -Path $tmp -Value $bat -Encoding ascii
    & cmd /c "`"$tmp`""
    if ($LASTEXITCODE -ne 0) { Write-Host '[error] build-target32 failed'; exit 1 }
} finally {
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}
Write-Host "[ok] built $outDir\simple_target32.exe, $outDir\spawn_child.exe, $outDir\threaded_target32.exe, $outDir\instrument_target32.exe, $outDir\child_target32.exe, $outDir\pdb_target32.exe + .pdb, $outDir\loop_target32.exe"

# ── WOW64 injection targets (spec §13.2/§13.8 item 7) ────────────────────────
# Its own command block, deliberately self-contained: another branch appends its
# 32-bit targets here too, and a second independent block keeps that merge to a
# trivial append conflict instead of an edit to the batch text above.
$injectCmd = Join-Path $root '.build-inject32.cmd'
try {
    $bat = "@echo off`n" +
           "call `"$vs\VC\Auxiliary\Build\vcvarsall.bat`" amd64_x86 >nul 2>&1`n" +
           "cd /d `"$root`"`n" +
           "cl /nologo /O2 /W3 /utf-8 /c tests\target\inject_target32.c /Fo$outDir\inject_target32.obj`n" +
           "if errorlevel 1 exit /b %errorlevel%`n" +
           "link /nologo /DLL /machine:x86 /IMPLIB:$outDir\inject_target32.lib /OUT:$outDir\inject_target32.dll $outDir\inject_target32.obj`n" +
           "if errorlevel 1 exit /b %errorlevel%`n" +
           "cl /nologo /O2 /W3 /utf-8 /c tests\target\inject_host32.c /Fo$outDir\inject_host32.obj`n" +
           "if errorlevel 1 exit /b %errorlevel%`n" +
           "link /nologo /subsystem:console /machine:x86 /OUT:$outDir\inject_host32.exe $outDir\inject_host32.obj`n" +
           "if errorlevel 1 exit /b %errorlevel%`n" +
           "echo BUILD_OK"
    Set-Content -Path $injectCmd -Value $bat -Encoding ascii
    & cmd /c "`"$injectCmd`""
    if ($LASTEXITCODE -ne 0) { Write-Host '[error] inject32 target build failed'; exit 1 }
} finally {
    Remove-Item $injectCmd -Force -ErrorAction SilentlyContinue
}
Write-Host "[ok] built $outDir\inject_host32.exe and $outDir\inject_target32.dll"
