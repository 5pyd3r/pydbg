/* av_target — deliberately faults so a debugger sees EXCEPTION_ACCESS_VIOLATION.
 *
 * The point is the ExceptionInformation payload: [0] is the access type
 * (0 = read) and [1] the faulting address. A debugger that drops it can only
 * report a bare exception code, which is exactly the failure that hid behind
 * tests building DebugEvent dicts by hand.
 *
 * The fault sits inside the target's own SEH so the continue status can be
 * observed end to end: when a debugger continues the first-chance exception
 * with DBG_EXCEPTION_NOT_HANDLED, __except runs and the process exits with
 * AV_SEH_EXIT_CODE. A debugger that marks it handled (DBG_CONTINUE) never gets
 * here — resuming simply re-executes the faulting instruction.
 */
#include <windows.h>

#define AV_SEH_EXIT_CODE 42

int main(void) {
    volatile int *null_address = (volatile int *)0;
    __try {
        return *null_address;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return AV_SEH_EXIT_CODE;
    }
}
