/* antidebug_target - a sample that performs the classic read-only anti-debug
 * checks this repository detects (spec section 13.2).
 *
 * It asks IsDebuggerPresent, asks CheckRemoteDebuggerPresent about its own
 * process, and reads the two PEB fields the textbook checks use: BeingDebugged
 * and NtGlobalFlag. Running it under a debugger and outside one therefore
 * exercises the same state pydbg.antidebug reports, instead of a target that
 * merely looks like it might.
 *
 * The four answers are packed into the exit code (bit 0: IsDebuggerPresent,
 * bit 1: CheckRemoteDebuggerPresent, bit 2: PEB.BeingDebugged,
 * bit 3: PEB.NtGlobalFlag & 0x70) so the sample is checkable by hand as well:
 * launched normally it exits 0, under a debugger it exits 7 (and 15 when the
 * loader has also set the heap flags). Nothing is written anywhere.
 */

#include <windows.h>

/* PEB.BeingDebugged is at +0x02 in both layouts; NtGlobalFlag moved with the
 * pointer-sized fields: 0x68 in the 32-bit PEB, 0xBC in the 64-bit one. */
#ifdef _WIN64
#define PEB_FROM_TEB() ((BYTE *)(ULONG_PTR)__readgsqword(0x60))
#define PEB_NT_GLOBAL_FLAG_OFFSET 0xBC
#else
#define PEB_FROM_TEB() ((BYTE *)(ULONG_PTR)__readfsdword(0x30))
#define PEB_NT_GLOBAL_FLAG_OFFSET 0x68
#endif

#define PEB_BEING_DEBUGGED_OFFSET 0x02
#define NT_GLOBAL_FLAG_DEBUG_MASK 0x70

int main(void)
{
    BYTE *peb = PEB_FROM_TEB();
    BOOL remote = FALSE;
    int  result = 0;

    if (IsDebuggerPresent()) {
        result |= 1;
    }
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote) {
        result |= 2;
    }
    if (*(volatile BYTE *)(peb + PEB_BEING_DEBUGGED_OFFSET) != 0) {
        result |= 4;
    }
    if ((*(volatile DWORD *)(peb + PEB_NT_GLOBAL_FLAG_OFFSET) &
         NT_GLOBAL_FLAG_DEBUG_MASK) != 0) {
        result |= 8;
    }
    return result;
}

