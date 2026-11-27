/* stack_target.c — 64 位栈回溯测试目标（spec §13.3 D10）。
 *
 * main -> f1 -> f2 -> f3，f3 里 Sleep 住：调试器在 f3 入口停下时，栈上同时
 * 存在 f3/f2/f1/main 四条返回地址，`get_context_bytes` 抓到的 CONTEXT 因此
 * 能驱动 StackWalk64 走出 >= 3 帧的真实调用链。
 *
 * 三个函数都导出，测试用导出表拼出 f3 的运行时地址并下断点；__declspec(noinline)
 * 且调用后继续用返回值（而不是 `return f2(x);`），防止 /O2 把调用优化成尾调用，
 * 把整条链折叠掉。
 */
#include <stdio.h>
#include <windows.h>

__declspec(noinline) __declspec(dllexport) int __cdecl f3(int x) {
    /* 长 Sleep：断点没命中时测试仍有时间 attach；命中时这条还没执行。 */
    Sleep(30000);
    return x * 3;
}

__declspec(noinline) __declspec(dllexport) int __cdecl f2(int x) {
    int r = f3(x + 2);
    return r + 2;
}

__declspec(noinline) __declspec(dllexport) int __cdecl f1(int x) {
    int r = f2(x + 1);
    return r + 1;
}

int main(void) {
    int r = f1(10);
    printf("stack_target: r=%d\n", r);
    fflush(stdout);
    return r == 0;
}
