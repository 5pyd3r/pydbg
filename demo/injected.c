/**
 * injected.c — Minimal DLL for testing DLL injection.
 *
 * When loaded via LoadLibrary, DllMain writes a marker file to confirm
 * the injection succeeded. The marker file path includes the PID so
 * multiple tests don't collide.
 *
 * Build (MSVC):  cl /LD /Fe:injected.dll demo\injected.c
 * Build (MinGW): gcc -shared -o injected.dll demo/injected.c
 */

#include <windows.h>
#include <stdio.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    char path[MAX_PATH];
    FILE *f;

    if (reason == DLL_PROCESS_ATTACH) {
        /* Write marker file: %TEMP%\pydbg_inject_<PID>.txt */
        snprintf(path, sizeof(path), "%s\\pydbg_inject_%lu.txt",
                 getenv("TEMP") ? getenv("TEMP") : "C:\\Temp",
                 GetCurrentProcessId());
        f = fopen(path, "w");
        if (f) {
            fprintf(f, "injected.dll loaded into pid=%lu\n",
                    GetCurrentProcessId());
            fclose(f);
        }
    }
    return TRUE;
}
