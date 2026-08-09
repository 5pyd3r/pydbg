/* simple_target32.c — 32 位 (WOW64) 测试目标：导出确定性函数供断点/硬件断点/远程校验。
   镜像 wow64-dbg-demo 的 target32.c：__declspec(noinline) 防止 /O2 把导出函数内联/常量
   折叠，否则打在函数入口的 int3/硬件断点永不命中。 */
#include <windows.h>
#include <stdio.h>

__declspec(dllexport) volatile int g_counter = 0;
__declspec(dllexport) volatile unsigned g_tick = 0;
__declspec(dllexport) volatile int g_sum = 0;

__declspec(noinline) __declspec(dllexport) int __cdecl target_add(int a, int b) {
    return a + b;
}
__declspec(noinline) __declspec(dllexport) int __cdecl target_mul_store(int a, int b) {
    g_counter += a * b;
    return g_counter;
}
__declspec(noinline) __declspec(dllexport) int __cdecl target_get_global(void) {
    return g_counter;
}
__declspec(noinline) __declspec(dllexport) void __cdecl target_sleep(int ms) {
    Sleep(ms);
}

int main(void) {
    printf("simple_target32: base=0x%08X pid=%lu\n",
           (unsigned)(DWORD_PTR)GetModuleHandleW(NULL), GetCurrentProcessId());
    fflush(stdout);
    for (;;) {
        Sleep(200);
        target_mul_store(2, 1);
        g_sum += target_add((int)(g_tick & 1), 4);
        g_tick++;
    }
    return 0;
}
