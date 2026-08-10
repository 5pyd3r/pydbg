/* instrument_target.c — 插桩测试目标：导出确定性函数供 hook，循环累积全局和。
   __declspec(noinline) 防 /O2 内联，保证入口地址可插桩。
   add_numbers 保持纯算术（前几条指令位置无关），但经 volatile 函数指针调用，
   阻止 MSVC 把常量实参的纯函数调用提升出循环 —— 否则 hook 永远拦不到循环内的调用。 */
#include <windows.h>
#include <stdio.h>

__declspec(dllexport) volatile int g_sum = 0;

__declspec(noinline) __declspec(dllexport) int __cdecl add_numbers(int a, int b) {
    return a + b;
}

/* volatile 函数指针：每次循环经它调用，结果不可缓存，调用留在循环内 */
int (__cdecl * volatile g_fn)(int, int) = add_numbers;

int main(void) {
    printf("instrument_target: pid=%lu\n", (unsigned long)GetCurrentProcessId());
    fflush(stdout);
    for (;;) {
        g_sum += g_fn(1, 2);   /* 正常每轮 +3；插桩后每轮 +103 */
        Sleep(20);
    }
    return 0;
}
