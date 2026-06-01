@echo off
rem Build injected.dll for DLL injection demo.
rem Requires: LLVM/Clang with lld-link.
rem
rem Note: Git for Windows ships a link.exe (Unix hardlink tool) that
rem       shadows MSVC's link.exe. We pass -fuse-ld=lld to force clang
rem       to use lld-link instead.

setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d "C:\Output\pydbg"
clang --target=x86_64-pc-windows-msvc -shared -fuse-ld=lld -D_CRT_SECURE_NO_WARNINGS -o demo\injected.dll demo\injected.c -lkernel32
endlocal
