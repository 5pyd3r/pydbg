/* A 32-bit DLL for the WOW64 injection acceptance test (spec §13.2/§13.8).
 *
 * inject_host32.exe loads it with --load-dll, and the injection test maps it
 * into that host through a remote LoadLibraryW. Both consumers resolve
 * `inject_target32_answer` from the *target's* 32-bit mapping, so the export
 * has to be a real exported function: a name the test could only find in the
 * file would not prove the target actually mapped it.
 */

#include <windows.h>

__declspec(dllexport) int inject_target32_answer(void);

__declspec(dllexport) int inject_target32_answer(void)
{
    return 1234;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        /* The injected LoadLibraryW runs in a fresh remote thread. There is no
         * reason to pay for a loader callback on every host thread. */
        DisableThreadLibraryCalls(instance);
    }
    return TRUE;
}
