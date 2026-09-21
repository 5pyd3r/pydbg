/* A target that owns a window and then stops pumping messages.
 *
 * The third cause: the window exists, nothing is dismissing anything, and the
 * thread will not answer. Distinguished from modal_target by the absence of a
 * dialog, which is the only thing separating "waiting for a person" from
 * "stuck". */
#include "window_common.h"

int main(void) {
    HWND hwnd = pydbg_make_window();
    if (hwnd == NULL) {
        return 2;
    }
    for (;;) {
        Sleep(50);          /* deliberately not pumping */
    }
    (void)hwnd;
}
