/* nested_parent.c — parent/child pair for the attach() nested-debugging tests.
 *
 * The shape it reproduces: we attach() to a process that is itself a debugger,
 * and the memory that matters belongs to ITS debuggee — OllyDbg is the real
 * case, where get_child_processes() came back empty and read_memory(pid=) said
 * "Unknown process pid". Here the relationship is only "a process with a
 * child", which is all the API needs to be exercised.
 *
 *   no arguments          parent: sleep 1500 ms, start a child of itself,
 *                         then wait up to 60 s for it.
 *   argv[1] == "child"    child: idle for argv[2] ms (default 30000), exit 42.
 *
 * The delay before the spawn is the point of this file. Without it the child
 * would already be running when the test attaches, and "attach() received no
 * CREATE_PROCESS event for the child" would have a competing explanation (the
 * child predates the attach) instead of being a statement about attach().
 * The child's 30 s lifetime is the other half: an assertion that the child's
 * memory is readable has to run while the child is still alive.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SPAWN_DELAY_MS 1500

int main(int argc, char* argv[]) {
    if (argc > 1 && strcmp(argv[1], "child") == 0) {
        int lifetime = argc > 2 ? atoi(argv[2]) : 30000;
        printf("child pid=%lu\n", GetCurrentProcessId());
        fflush(stdout);
        Sleep((DWORD)lifetime);
        return 42;
    }

    printf("parent pid=%lu\n", GetCurrentProcessId());
    fflush(stdout);
    Sleep(SPAWN_DELAY_MS);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmd[MAX_PATH];

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    snprintf(cmd, sizeof(cmd), "\"%s\" child 30000", argv[0]);

    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "CreateProcess failed: %lu\n", GetLastError());
        return 1;
    }

    printf("spawned child pid=%lu\n", (unsigned long)pi.dwProcessId);
    fflush(stdout);

    WaitForSingleObject(pi.hProcess, 60000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
