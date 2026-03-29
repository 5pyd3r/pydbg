#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

int main(void) {
    int x = 42;
    int y = x + 1;
    int z = x + y;

    printf("Hello from pydbg test target\n");
    printf("x=%d y=%d z=%d\n", x, y, z);

    /* Sleep so debugger has time to attach */
#ifdef _WIN32
    Sleep(1000);
#else
    sleep(1);
#endif

    return 0;
}
