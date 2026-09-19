/* argv_target — records its own argv where a test can read it back.
 *
 * create_process() gained a cmdline argument so that targets configured by
 * argument can be started under debug control instead of forcing callers onto
 * attach() (which loses every startup-time breakpoint). Asserting that needs a
 * target whose argv survives: a debuggee's stdout goes to the debugger's
 * console and is not capturable, so the arguments are written to the file
 * named by the LAST argument instead.
 *
 * Usage: argv_target.exe <outfile> [<arg> ...]
 *   Writes one "%d:%s" line per argument, plus a leading "argc=N" line, then
 *   sleeps briefly so the debugger still owns a live process to tear down.
 */

#include <stdio.h>
#include <windows.h>

int main(int argc, char **argv) {
    FILE *f;
    int i;

    if (argc < 2) {
        Sleep(1000);
        return 2;
    }

    f = fopen(argv[1], "wb");
    if (f == NULL) {
        Sleep(1000);
        return 3;
    }

    fprintf(f, "argc=%d\n", argc);
    for (i = 0; i < argc; i++) {
        fprintf(f, "%d:%s\n", i, argv[i] ? argv[i] : "(null)");
    }
    fclose(f);

    Sleep(1000);
    return 0;
}
