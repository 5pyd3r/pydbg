/* av_target — deliberately faults so a debugger sees EXCEPTION_ACCESS_VIOLATION.
 *
 * The point is the ExceptionInformation payload: [0] is the access type
 * (0 = read) and [1] the faulting address. A debugger that drops it can only
 * report a bare exception code, which is exactly the failure that hid behind
 * tests building DebugEvent dicts by hand.
 */
#include <windows.h>

int main(void) {
    volatile int *null_address = (volatile int *)0;
    return *null_address;
}
