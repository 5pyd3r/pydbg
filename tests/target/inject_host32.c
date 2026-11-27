/* Host for the WOW64 injection acceptance test (spec §13.2/§13.8 item 7).
 *
 * argv[1] is a status file this program owns. It publishes the worker thread
 * id there so the test can queue an APC to the one thread that really sits in
 * an alertable wait, instead of guessing which tid of a running process it is.
 * Every time that wait returns WAIT_IO_COMPLETION the worker appends a line to
 * "<status>.apc": that marker is only written after an APC has run and
 * returned, which is what makes "the APC executed on a 32-bit thread"
 * observable from outside the process.
 *
 * "--load-dll" makes it load inject_target32.dll through the 32-bit loader and
 * call the export, so the same binary covers "a 32-bit process is already
 * using the DLL" as well as "the DLL appears because it was injected". The
 * status line "loaded=" records which case a run is, so no test has to assume.
 *
 * The status file is written once, before the worker is resumed, and the
 * worker writes a different file, so a reader never races an open handle.
 */

/* fopen's "unsafe" deprecation is about its error reporting, not its
 * behaviour; this test target only needs the portable CRT file API, and /W3
 * should stay quiet about it. Defined before the CRT headers, which is where
 * the warning is armed. */
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <string.h>

static char g_marker[MAX_PATH];

static void append_marker(void)
{
    FILE *file = fopen(g_marker, "a");
    if (file == NULL) {
        return;
    }
    fputs("apc\n", file);
    fclose(file);
}

static DWORD WINAPI alertable_worker(void *unused)
{
    (void)unused;
    for (;;) {
        /* SleepEx(INFINITE, TRUE) is the alertable wait an APC needs: it
         * returns WAIT_IO_COMPLETION once a queued user APC has run. */
        if (SleepEx(INFINITE, TRUE) == WAIT_IO_COMPLETION) {
            append_marker();
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    DWORD worker_id = 0;
    HANDLE worker;
    FILE *status;
    HMODULE dll = NULL;
    int answer = 0;
    int load = 0;
    int i;

    if (argc < 2) {
        fprintf(stderr, "usage: inject_host32.exe <status-file> [--load-dll]\n");
        return 2;
    }
    /* Room for the ".apc" suffix the worker's marker file needs. */
    if (strlen(argv[1]) + 5 > sizeof(g_marker)) {
        fprintf(stderr, "inject_host32: status path is too long\n");
        return 2;
    }
    snprintf(g_marker, sizeof(g_marker), "%s.apc", argv[1]);

    for (i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--load-dll") == 0) {
            load = 1;
        }
    }

    if (load) {
        int (__cdecl *answer_fn)(void);
        dll = LoadLibraryW(L"inject_target32.dll");
        if (dll == NULL) {
            fprintf(stderr, "inject_host32: LoadLibraryW failed: %lu\n",
                    (unsigned long)GetLastError());
            return 3;
        }
        answer_fn = (int (__cdecl *)(void))
            GetProcAddress(dll, "inject_target32_answer");
        if (answer_fn == NULL) {
            return 3;
        }
        answer = answer_fn();
    }

    /* Suspended first, so the status file can name the tid before the thread
     * runs and a test that reads it cannot race the worker's first wait. */
    worker = CreateThread(NULL, 0, alertable_worker, NULL,
                          CREATE_SUSPENDED, &worker_id);
    if (worker == NULL) {
        return 4;
    }

    status = fopen(argv[1], "w");
    if (status == NULL) {
        return 5;
    }
    fprintf(status,
            "ready\npid=%lu\nworker_tid=%lu\nloaded=%d\ndll_base=0x%08X\n"
            "answer=%d\nend\n",
            (unsigned long)GetCurrentProcessId(),
            (unsigned long)worker_id,
            load,
            (unsigned)(DWORD_PTR)dll,
            answer);
    fclose(status);

    ResumeThread(worker);
    WaitForSingleObject(worker, INFINITE);
    return 0;
}
