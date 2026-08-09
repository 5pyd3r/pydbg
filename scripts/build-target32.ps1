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
           "echo BUILD_OK"
    Set-Content -Path $tmp -Value $bat -Encoding ascii
    & cmd /c "`"$tmp`""
    if ($LASTEXITCODE -ne 0) { Write-Host '[error] build-target32 failed'; exit 1 }
} finally {
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}
Write-Host "[ok] built $outDir\simple_target32.exe, $outDir\spawn_child.exe, $outDir\threaded_target32.exe"
