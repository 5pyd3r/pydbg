/* A target whose only window is a modal message box.
 *
 * The case that cost a whole analysis round: the target is blocked on a
 * dialog it cannot dismiss itself, produces no debug events, and every probe
 * result is zero. Note that its thread IS pumping messages — a message box
 * runs its own modal loop — so this is NOT the hung-window case, and a probe
 * that classified it that way would name the one cause that has no
 * explanation instead of the one that does. */
#include "window_common.h"

int main(void) {
    HWND hwnd = pydbg_make_window();
    if (hwnd == NULL) {
        return 2;
    }
    MessageBoxA(hwnd, "Export failed", CHILD_TEXT, MB_OK | MB_ICONERROR);
    return 0;
}
