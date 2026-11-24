/* Host for the Phase 4 live-dump acceptance test (spec §11.6(4)).
 *
 * It loads dump_target.dll by name and then sleeps, so the test's debugger can
 * wait for the DLL to be mapped, dump it out of the live process, rebuild it,
 * and finally kill this host. Loading by name is enough because meson puts
 * both files in the same output directory, which is the exe's own directory
 * and therefore first on the loader's search path.
 */

#include <windows.h>

int main(void)
{
    HMODULE target = LoadLibraryW(L"dump_target.dll");
    if (target == NULL) {
        return 1;
    }
    /* The DLL stays mapped until the test terminates this host. */
    Sleep(INFINITE);
    return 0;
}
