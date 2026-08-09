/* spawn_child.c — x86 (WOW64) parent helper for cross-arch child tests:
   spawns the child path given as argv[1] and waits for it. */
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[]) {
    if (argc < 2) return 1;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmd[MAX_PATH];
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    snprintf(cmd, sizeof(cmd), "\"%s\"", argv[1]);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) return 2;
    WaitForSingleObject(pi.hProcess, 60000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
