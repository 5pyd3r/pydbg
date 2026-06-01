@echo off
rem Build injected.dll for DLL injection demo.
rem Requires: Visual Studio Build Tools with C++ workload.
rem
rem Note: Git for Windows ships a link.exe (Unix hardlink tool) that
rem       shadows MSVC's link.exe. We use lld-link instead to avoid conflict.

setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d "C:\Output\pydbg"
cl /nologo /c /D_CRT_SECURE_NO_WARNINGS demo\injected.c /Fo:demo\injected.obj
lld-link /nologo /DLL /OUT:demo\injected.dll demo\injected.obj kernel32.lib
endlocal
