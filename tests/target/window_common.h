/*
 * A real window and a real message loop, shared by the window probes' targets.
 *
 * The window probe's positive control has to be an actual window: a probe
 * exercised only against fabricated window dictionaries cannot show that it
 * reads a real one, and reading the real one is exactly what the analysis
 * round that motivated this had to leave pydbg to do.
 *
 * The three targets differ only in what they do once the window exists —
 * pump, block on a modal dialog, or stop pumping — so the window itself lives
 * here. Each target is its own translation unit with its own main(); meson
 * builds them separately.
 */
#include <windows.h>

#define CHILD_TEXT "Auto Export Error"

static const char kClassName[] = "PydbgWindowTarget";
static const char kTitle[] = "PydbgWindowTarget";

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    return DefWindowProcA(hwnd, msg, wp, lp);
}

static HWND pydbg_make_window(void) {
    WNDCLASSA wc;
    HWND hwnd;
    HWND child;

    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = kClassName;
    RegisterClassA(&wc);

    hwnd = CreateWindowExA(0, kClassName, kTitle, WS_OVERLAPPEDWINDOW,
                           CW_USEDEFAULT, CW_USEDEFAULT, 320, 200,
                           NULL, NULL, wc.hInstance, NULL);
    if (hwnd == NULL) {
        return NULL;
    }

    /* The child is the point of the fixture: the message the probe exists to
     * read is text on a Static control, not the top-level title. */
    child = CreateWindowExA(0, "STATIC", CHILD_TEXT, WS_CHILD | WS_VISIBLE,
                            10, 10, 200, 20, hwnd, NULL, wc.hInstance, NULL);
    (void)child;

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    return hwnd;
}

/* Unused by the modal and wedge targets, which is intended: the header is
 * shared so that the window under test is identical in all three. */
static int pydbg_pump_forever(void) {
    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return 0;
}
