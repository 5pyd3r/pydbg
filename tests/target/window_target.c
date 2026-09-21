/* A target that owns a window and pumps messages, forever. The control for
 * "the target is running normally". */
#include "window_common.h"

int main(void) {
    HWND hwnd = pydbg_make_window();
    if (hwnd == NULL) {
        return 2;
    }
    return pydbg_pump_forever();
}
