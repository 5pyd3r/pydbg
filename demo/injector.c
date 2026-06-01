/**
 * injector.c — 32-bit DLL injector helper.
 * Usage: injector.exe <PID> <DLL_PATH>
 *
 * Build: clang --target=i686-pc-windows-msvc -o injector.exe injector.c -lkernel32
 */
#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <PID> <DLL_PATH>\n", argv[0]);
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    char *dll_path = argv[2];

    /* Validate DLL path */
    DWORD attrs = GetFileAttributesA(dll_path);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        printf("ERROR: DLL not found: %s\n", dll_path);
        return 1;
    }

    /* Open target process */
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        printf("ERROR: OpenProcess(%lu) failed: %lu\n", pid, GetLastError());
        return 1;
    }

    /* Allocate memory in target for DLL path */
    size_t path_len = strlen(dll_path) + 1;
    LPVOID remote_buf = VirtualAllocEx(hProc, NULL, path_len,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_READWRITE);
    if (!remote_buf) {
        printf("ERROR: VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }

    /* Write DLL path to target */
    SIZE_T written;
    if (!WriteProcessMemory(hProc, remote_buf, dll_path, path_len, &written)) {
        printf("ERROR: WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remote_buf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    /* Get LoadLibraryA address */
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLibrary = GetProcAddress(hK32, "LoadLibraryA");
    if (!pLoadLibrary) {
        printf("ERROR: GetProcAddress failed\n");
        VirtualFreeEx(hProc, remote_buf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    /* Create remote thread to call LoadLibraryA */
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibrary,
        remote_buf, 0, NULL);
    if (!hThread) {
        printf("ERROR: CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remote_buf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    /* Wait for LoadLibraryA to complete */
    WaitForSingleObject(hThread, 30000);

    /* Get exit code (= DLL base address) */
    DWORD exit_code = 0;
    GetExitCodeThread(hThread, &exit_code);

    if (exit_code > 0x1000) {
        printf("SUCCESS: DLL loaded at 0x%08lX\n", exit_code);
    } else {
        printf("FAILED: LoadLibraryA returned 0x%08lX (error %lu)\n",
               exit_code, GetLastError());
    }

    /* Cleanup */
    CloseHandle(hThread);
    VirtualFreeEx(hProc, remote_buf, 0, MEM_RELEASE);
    CloseHandle(hProc);

    return (exit_code > 0x1000) ? 0 : 1;
}
