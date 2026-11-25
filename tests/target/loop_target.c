/* loop_target.c — the 1e6-block sample for the instrumented-scale budget
 * (docs/analysis-coverage.md §13.5).
 *
 * One iteration of main's loop calls `bump` exactly once. `bump` is
 * `__declspec(noinline)`, so the call survives /O2 and the block that starts at
 * its entry executes exactly once per iteration: instrumenting that one block
 * produces one BLOCK record per iteration, and 1,000,000 iterations are
 * 1,000,000 instrumented blocks.
 *
 * Both `bump` and `loop_done` are exported so the test can find their addresses
 * from the PE without debug information: `bump` is the block to detour, and
 * `loop_done` is where the debugger stops after the loop, which is the only
 * point at which the target-side event ring can be drained reliably.
 *
 * Nothing is imported on the hot path. The loop must not leave the module,
 * both because an imported call would end a `InstructionTracer` window at its
 * first iteration (the 10^4 single-step budget uses this same loop) and
 * because the instrumented run is meant to measure the stub, not the loader.
 */

#include <windows.h>
#include <stdio.h>

/* Written every iteration, so the compiler cannot fold the loop away. */
__declspec(dllexport) volatile int g_bump_total = 0;

__declspec(noinline) __declspec(dllexport) int __cdecl bump(int value) {
    g_bump_total += value;
    return g_bump_total;
}

/* One call after the loop: the software breakpoint the test runs to. */
__declspec(noinline) __declspec(dllexport) void __cdecl loop_done(void) {
    g_bump_total = 0;
}

int main(void) {
    int i;

    printf("loop_target: pid=%lu\n", (unsigned long)GetCurrentProcessId());
    fflush(stdout);

    for (i = 0; i < 1000000; i++) {
        bump(i);
    }
    loop_done();

    printf("loop_target: done\n");
    fflush(stdout);
    return 0;
}
