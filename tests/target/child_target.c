#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[]) {
    if (argc > 1 && strcmp(argv[1], "child") == 0) {
        printf("child process pid=%lu\n", GetCurrentProcessId());
        fflush(stdout);
        Sleep(2000);
        return 42;
    }

    printf("parent process pid=%lu\n", GetCurrentProcessId());
    fflush(stdout);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmd[MAX_PATH];

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    snprintf(cmd, sizeof(cmd), "%s child", argv[0]);

    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "CreateProcess failed: %lu\n", GetLastError());
        return 1;
    }

    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
