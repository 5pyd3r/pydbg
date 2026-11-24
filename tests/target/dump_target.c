/* A real DLL for the Phase 4 live-dump acceptance test (spec §11.6(4)).
 *
 * The dump tests need a module that a process actually mapped: this one is
 * loaded by dump_host.exe, dumped out of the live process and rebuilt as a
 * file. It exports one function and imports one Win32 function, which are the
 * two facts the rebuilt export and import directories have to preserve, and it
 * carries a global so the dump has data to copy as well.
 */

#include <windows.h>

/* Named by the e2e test in the rebuilt export directory. */
__declspec(dllexport) int dump_target_answer(void);

/* Data the dump has to copy out of the live image. */
int dump_target_state = 42;

__declspec(dllexport) int dump_target_answer(void)
{
    /* GetTickCount keeps a real kernel32 import in the image even at /O2. */
    return (int)(GetTickCount() & 0x7fffffff) + dump_target_state;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        /* A second kernel32 import, and it stops the loader from sending a
         * thread-attach event for every host thread. */
        DisableThreadLibraryCalls(instance);
    }
    return TRUE;
}
