/* loop_target32.c — the WOW64 counterpart of loop_target.c.
 *
 * The 32-bit BBL acceptance (docs/analysis-coverage.md §12.5 item 6) repeats
 * the x64 case on a target that executes a large number of blocks inside its
 * own module, so the in-module hot loop is what makes the instrumentation
 * meaningful rather than a single forced call.
 *
 * One iteration of main's loop calls `bump` exactly once. `bump` is
 * `__declspec(noinline)`, so the call survives /O2 and the block that starts at
 * its entry executes exactly once per iteration: instrumenting that one block
 * produces one BLOCK record per iteration. Both `bump` and `loop_done` are
 * exported so the test resolves them from the PE without debug information:
 * `bump` is a deterministic stop address for the shared execution slice, and
 * `loop_done` is where the loop ends.
 *
 * Nothing is imported on the hot path: the loop must not leave the module, so a
 * debugger's window on this image is not cut short by a call into the loader.
 *
 * The x86 toolchain is not part of the meson build; scripts/build-target32.ps1
 * compiles this into tests/target/loop_target32.exe (.exe files are ignored).
 */

#include <windows.h>
#include <stdio.h>

/* Written every iteration, so the compiler cannot fold the loop away. */
__declspec(dllexport) volatile int g_bump_total = 0;

__declspec(noinline) __declspec(dllexport) int __cdecl bump(int value) {
    g_bump_total += value;
    return g_bump_total;
}

/* One call after the loop: the address the test can stop at. */
__declspec(noinline) __declspec(dllexport) void __cdecl loop_done(void) {
    g_bump_total = 0;
}

int main(void) {
    int i;

    printf("loop_target32: pid=%lu\n", (unsigned long)GetCurrentProcessId());
    fflush(stdout);

    for (i = 0; i < 1000000; i++) {
        bump(i);
    }
    loop_done();

    printf("loop_target32: done\n");
    fflush(stdout);
    return 0;
}
