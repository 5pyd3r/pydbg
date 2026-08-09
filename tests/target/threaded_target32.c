/* threaded_target32.c — 32 位多线程测试目标：worker_add 仅由工作线程循环调用，
   main_add 仅由主线程循环调用，用于验证进程级/线程级硬件断点的线程归属。 */
#include <windows.h>
#include <stdio.h>

__declspec(dllexport) volatile int g_worker_calls = 0;
__declspec(dllexport) volatile int g_main_calls = 0;

__declspec(noinline) __declspec(dllexport) int __cdecl worker_add(int a, int b) {
    g_worker_calls += a + b;
    return g_worker_calls;
}
__declspec(noinline) __declspec(dllexport) int __cdecl main_add(int a, int b) {
    g_main_calls += a + b;
    return g_main_calls;
}

static DWORD WINAPI worker(void* p) {
    for (;;) {
        Sleep(200);
        worker_add(1, 2);
    }
    return 0;
}

int main(void) {
    printf("threaded_target32: base=0x%08X pid=%lu\n",
           (unsigned)(DWORD_PTR)GetModuleHandleW(NULL), GetCurrentProcessId());
    fflush(stdout);
    CreateThread(NULL, 0, worker, NULL, 0, NULL);
    for (;;) {
        Sleep(200);
        main_add(3, 4);
    }
    return 0;
}
