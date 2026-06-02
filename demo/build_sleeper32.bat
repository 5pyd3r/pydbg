@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d "C:\Output\pydbg"
clang --target=i686-pc-windows-msvc -D_CRT_SECURE_NO_WARNINGS -fuse-ld=lld -L"C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.51.36231\lib\x86" -L"C:\Program Files (x86)\Windows Kits\10\lib\10.0.26100.0\um\x86" -L"C:\Program Files (x86)\Windows Kits\10\lib\10.0.26100.0\ucrt\x86" -o demo\sleeper32.exe demo\sleeper32.c -lkernel32
