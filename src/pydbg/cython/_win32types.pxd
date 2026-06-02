# _win32types.pxd — Shared Win32 type declarations for pydbg

from libc.stdint cimport uint32_t, uint64_t

cdef extern from "windows.h":
    # Basic types
    ctypedef void* HANDLE
    ctypedef void* HMODULE
    ctypedef unsigned long DWORD
    ctypedef unsigned short WORD
    ctypedef void* LPVOID
    ctypedef const void* LPCVOID
    ctypedef unsigned long long SIZE_T
    ctypedef int BOOL
    ctypedef long LONG
    ctypedef unsigned long long ULONG_PTR
    ctypedef unsigned long* LPDWORD
    ctypedef unsigned long long DWORD64
    ctypedef char* LPSTR
    ctypedef const char* LPCSTR
    ctypedef unsigned short USHORT
    ctypedef unsigned char UCHAR

    # === Constants ===
    DWORD WAIT_OBJECT_0
    DWORD WAIT_TIMEOUT
    DWORD MEM_RELEASE
    DWORD DEBUG_PROCESS
    DWORD DEBUG_ONLY_THIS_PROCESS
    DWORD CREATE_SUSPENDED
    DWORD INFINITE
    DWORD DBG_CONTINUE
    DWORD DBG_EXCEPTION_NOT_HANDLED
    DWORD EXCEPTION_DEBUG_EVENT
    DWORD CREATE_THREAD_DEBUG_EVENT
    DWORD CREATE_PROCESS_DEBUG_EVENT
    DWORD EXIT_THREAD_DEBUG_EVENT
    DWORD EXIT_PROCESS_DEBUG_EVENT
    DWORD LOAD_DLL_DEBUG_EVENT
    DWORD UNLOAD_DLL_DEBUG_EVENT
    DWORD OUTPUT_DEBUG_STRING_EVENT
    DWORD RIP_EVENT
    DWORD EXCEPTION_ACCESS_VIOLATION
    DWORD EXCEPTION_BREAKPOINT
    DWORD EXCEPTION_SINGLE_STEP
    DWORD EXCEPTION_GUARD_PAGE
    DWORD EXCEPTION_ARRAY_BOUNDS_EXCEEDED
    DWORD EXCEPTION_FLT_DENORMAL_OPERAND
    DWORD EXCEPTION_FLT_DIVIDE_BY_ZERO
    DWORD EXCEPTION_FLT_INEXACT_RESULT
    DWORD EXCEPTION_FLT_INVALID_OPERATION
    DWORD EXCEPTION_FLT_OVERFLOW
    DWORD EXCEPTION_FLT_STACK_CHECK
    DWORD EXCEPTION_FLT_UNDERFLOW
    DWORD EXCEPTION_INT_DIVIDE_BY_ZERO
    DWORD EXCEPTION_INT_OVERFLOW
    DWORD EXCEPTION_PRIVILEGED_INSTRUCTION
    DWORD EXCEPTION_STACK_OVERFLOW

    DWORD THREAD_ALL_ACCESS
    DWORD CONTEXT_ALL
    DWORD CONTEXT_DEBUG_REGISTERS
    DWORD CONTEXT_INTEGER
    DWORD CONTEXT_CONTROL

    # Memory constants
    DWORD MEM_COMMIT
    DWORD MEM_RESERVE
    DWORD MEM_FREE
    DWORD MEM_PRIVATE
    DWORD MEM_MAPPED
    DWORD MEM_IMAGE
    DWORD PAGE_NOACCESS
    DWORD PAGE_READONLY
    DWORD PAGE_READWRITE
    DWORD PAGE_EXECUTE
    DWORD PAGE_EXECUTE_READ
    DWORD PAGE_EXECUTE_READWRITE

    # === Structures ===

    ctypedef struct EXCEPTION_RECORD:
        DWORD ExceptionCode
        DWORD ExceptionFlags
        EXCEPTION_RECORD* ExceptionRecord
        LPVOID ExceptionAddress
        DWORD NumberParameters
        ULONG_PTR ExceptionInformation[15]

    ctypedef struct CREATE_PROCESS_DEBUG_INFO:
        HANDLE hFile
        HANDLE hProcess
        HANDLE hThread
        LPVOID lpBaseOfImage
        DWORD dwDebugInfoFileOffset
        DWORD nDebugInfoSize
        LPVOID lpThreadLocalBase
        DWORD (*lpStartAddress)(LPVOID)
        LPVOID lpImageName
        WORD fUnicode

    ctypedef struct CREATE_THREAD_DEBUG_INFO:
        HANDLE hThread
        LPVOID lpThreadLocalBase
        DWORD (*lpStartAddress)(LPVOID)

    ctypedef struct EXIT_PROCESS_DEBUG_INFO:
        DWORD dwExitCode

    ctypedef struct EXIT_THREAD_DEBUG_INFO:
        DWORD dwExitCode

    ctypedef struct LOAD_DLL_DEBUG_INFO:
        HANDLE hFile
        LPVOID lpBaseOfDll
        DWORD dwDebugInfoFileOffset
        DWORD nDebugInfoSize
        LPVOID lpImageName

    ctypedef struct UNLOAD_DLL_DEBUG_INFO:
        LPVOID lpBaseOfDll

    ctypedef struct EXCEPTION_DEBUG_INFO:
        EXCEPTION_RECORD ExceptionRecord
        DWORD dwFirstChance

    ctypedef struct OUTPUT_DEBUG_STRING_INFO:
        char* lpDebugStringData
        WORD fUnicode
        WORD nDebugStringLength

    ctypedef struct RIP_INFO:
        DWORD dwError
        DWORD dwType

    ctypedef union _u:
        EXCEPTION_DEBUG_INFO Exception
        CREATE_THREAD_DEBUG_INFO CreateThread
        CREATE_PROCESS_DEBUG_INFO CreateProcessInfo
        EXIT_THREAD_DEBUG_INFO ExitThread
        EXIT_PROCESS_DEBUG_INFO ExitProcess
        LOAD_DLL_DEBUG_INFO LoadDll
        UNLOAD_DLL_DEBUG_INFO UnloadDll
        OUTPUT_DEBUG_STRING_INFO DebugString
        RIP_INFO RipInfo

    ctypedef struct DEBUG_EVENT:
        DWORD dwDebugEventCode
        DWORD dwProcessId
        DWORD dwThreadId
        _u u

    ctypedef struct MEMORY_BASIC_INFORMATION:
        LPVOID BaseAddress
        LPVOID AllocationBase
        DWORD AllocationProtect
        SIZE_T RegionSize
        DWORD State
        DWORD Protect
        DWORD Type

    ctypedef struct MODULEINFO:
        LPVOID lpBaseOfDll
        DWORD SizeOfImage
        LPVOID EntryPoint

    ctypedef struct STARTUPINFOA:
        DWORD cb
        LPSTR lpReserved
        LPSTR lpDesktop
        LPSTR lpTitle
        DWORD dwX
        DWORD dwY
        DWORD dwXSize
        DWORD dwYSize
        DWORD dwXCountChars
        DWORD dwYCountChars
        DWORD dwFillAttribute
        DWORD dwFlags
        WORD wShowWindow
        WORD cbReserved2
        unsigned char* lpReserved2
        HANDLE hStdInput
        HANDLE hStdOutput
        HANDLE hStdError

    ctypedef struct PROCESS_INFORMATION:
        HANDLE hProcess
        HANDLE hThread
        DWORD dwProcessId
        DWORD dwThreadId

    # === Win32 API functions ===
    BOOL CreateProcessA(
        LPCSTR lpApplicationName,
        char* lpCommandLine,
        void* lpProcessAttributes,
        void* lpThreadAttributes,
        BOOL bInheritHandles,
        DWORD dwCreationFlags,
        void* lpEnvironment,
        LPCSTR lpCurrentDirectory,
        STARTUPINFOA* lpStartupInfo,
        PROCESS_INFORMATION* lpProcessInformation)

    BOOL WaitForDebugEvent(DEBUG_EVENT* lpDebugEvent, DWORD dwMilliseconds)
    BOOL ContinueDebugEvent(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus)
    BOOL DebugActiveProcess(DWORD dwProcessId)
    BOOL DebugActiveProcessStop(DWORD dwProcessId)
    BOOL GetExitCodeProcess(HANDLE hProcess, DWORD* lpExitCode)
    BOOL GetExitCodeThread(HANDLE hThread, DWORD* lpExitCode)
    BOOL TerminateProcess(HANDLE hProcess, unsigned int uExitCode)
    HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
    BOOL CloseHandle(HANDLE hObject)
    DWORD GetLastError()

    BOOL ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress,
        void* lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
    BOOL WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress,
        void* lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
    SIZE_T VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress,
        MEMORY_BASIC_INFORMATION* lpBuffer, SIZE_T dwLength)
    BOOL VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress,
        SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect)

    HANDLE OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId)
    BOOL GetThreadContext(HANDLE hThread, void* lpContext)
    BOOL SetThreadContext(HANDLE hThread, void* lpContext)
    DWORD SuspendThread(HANDLE hThread)
    DWORD ResumeThread(HANDLE hThread)
    DWORD GetThreadId(HANDLE hThread)
    BOOL GetThreadTimes(HANDLE hThread, void* lpCreationTime, void* lpExitTime,
        void* lpKernelTime, void* lpUserTime)
    BOOL IsWow64Process(HANDLE hProcess, BOOL* Wow64Process)

cdef extern from "psapi.h":
    BOOL EnumProcessModules(HANDLE hProcess, HMODULE* lphModule, DWORD cb, DWORD* lpcbNeeded)
    DWORD GetModuleFileNameExA(HANDLE hProcess, HMODULE hModule, char* lpFilename, DWORD nSize)
    BOOL GetModuleInformation(HANDLE hProcess, HMODULE hModule, MODULEINFO* lpmodinfo, DWORD cb)

cdef extern from "tlhelp32.h":
    DWORD TH32CS_SNAPTHREAD

    ctypedef struct THREADENTRY32:
        DWORD dwSize
        DWORD cntUsage
        DWORD th32ThreadID
        DWORD th32OwnerProcessID
        LONG tpBasePri
        LONG tpDeltaPri
        DWORD dwFlags

    HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID)
    BOOL Thread32First(HANDLE hSnapshot, THREADENTRY32* lpte)
    BOOL Thread32Next(HANDLE hSnapshot, THREADENTRY32* lpte)


cdef extern from "windows.h":
    # Memory allocation in remote process
    LPVOID VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress,
                          SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
    BOOL VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress,
                       SIZE_T dwSize, DWORD dwFreeType)

    # Thread creation in remote process
    HANDLE CreateRemoteThread(HANDLE hProcess, void* lpThreadAttributes,
                              SIZE_T dwStackSize, LPVOID lpStartAddress,
                              LPVOID lpParameter, DWORD dwCreationFlags,
                              LPDWORD lpThreadId)

    # Module/function resolution
    void* GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
    HMODULE GetModuleHandleA(LPCSTR lpModuleName)

    # Synchronization
    DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)


cdef extern from "dbghelp.h":
    DWORD MAX_SYM_NAME

    # Symbol options
    DWORD SYMOPT_UNDNAME
    DWORD SYMOPT_DEFERRED_LOADS
    DWORD SYMOPT_LOAD_LINES
    DWORD SYMOPT_FAIL_CRITICAL_ERRORS

    ctypedef struct SYMBOL_INFOW:
        unsigned long SizeOfStruct
        unsigned long TypeIndex
        unsigned long long Reserved[2]
        unsigned long Index
        unsigned long Size
        unsigned long long ModBase
        unsigned long Flags
        unsigned long long Value
        unsigned long long Address
        unsigned long Register
        unsigned long Scope
        unsigned long Tag
        unsigned long NameLen
        unsigned long MaxNameLen
        unsigned short Name[1]

    BOOL SymInitializeW(HANDLE hProcess, const unsigned short* UserSearchPath, BOOL fInvadeProcess)
    BOOL SymCleanup(HANDLE hProcess)
    BOOL SymFromNameW(HANDLE hProcess, const unsigned short* Name, SYMBOL_INFOW* Symbol)
    BOOL SymFromAddrW(HANDLE hProcess, DWORD64 Address, DWORD64* Displacement, SYMBOL_INFOW* Symbol)
    DWORD64 SymLoadModuleExW(HANDLE hProcess, HANDLE hFile,
        const unsigned short* ImageName, const unsigned short* ModuleName,
        DWORD64 BaseOfDll, DWORD DllSize, void* Data, DWORD Flags)
    DWORD SymSetOptions(DWORD SymOptions)
    DWORD SymGetOptions()

    # Minidump stream types
    DWORD MiniDumpReadDumpStream

    ctypedef struct MINIDUMP_DIRECTORY:
        unsigned long StreamType
        unsigned long Location_DataSize
        unsigned long Location_Rva
        unsigned long long Location_DataSize_high
        unsigned long long Location_Rva_high

    BOOL MiniDumpReadDumpStream(void* BaseOfDump, unsigned long StreamNumber,
                                MINIDUMP_DIRECTORY** Dir, void** StreamPointer,
                                unsigned long* StreamSize)

    # Stack walk
    ctypedef struct ADDRESS64:
        unsigned long long Offset
        unsigned short Segment
        unsigned long Mode

    ctypedef struct KDHELP64:
        unsigned long long Thread
        unsigned long ThCallbackStack
        unsigned long ThCallbackBStore
        unsigned long NextCallback
        unsigned long FramePointer
        unsigned long long KiCallUserMode
        unsigned long long KeUserCallbackDispatcher
        unsigned long long SystemRangeStart
        unsigned long long KiUserExceptionDispatcher
        unsigned long long StackBase
        unsigned long long StackLimit
        unsigned long long BuildVersion
        unsigned long long Reserved0
        unsigned long long Reserved1[4]

    ctypedef struct STACKFRAME64:
        ADDRESS64 AddrPC
        ADDRESS64 AddrReturn
        ADDRESS64 AddrFrame
        ADDRESS64 AddrStack
        ADDRESS64 AddrBStore
        void* FuncTableEntry
        unsigned long long Params[4]
        int Far
        int Virtual
        unsigned long long Reserved[3]
        KDHELP64 KdHelp

    BOOL StackWalk64(unsigned long MachineType, HANDLE hProcess, HANDLE hThread,
                     STACKFRAME64* StackFrame, void* ContextRecord,
                     void* ReadMemoryRoutine, void* FunctionTableAccessRoutine,
                     void* GetModuleBaseRoutine, void* TranslateAddress)

    void* SymFunctionTableAccess64(HANDLE hProcess, unsigned long long AddrBase)


# ── CONTEXT helper functions ──────────────────────────────────────────
# The Windows CONTEXT struct has different fields on x86 vs x64.
# We access it exclusively through these inline C helpers so that
# the same Cython source compiles on both architectures.

cdef extern from *:
    """
    #include <windows.h>
    #include <string.h>

    /* Size of the native CONTEXT struct */
    static inline int pydbg_ctx_sizeof(void) { return (int)sizeof(CONTEXT); }

    /* Initialize a CONTEXT with the given flags */
    static inline void pydbg_ctx_init(void* pctx, unsigned long flags) {
        memset(pctx, 0, sizeof(CONTEXT));
        ((CONTEXT*)pctx)->ContextFlags = flags;
    }

    /* ContextFlags */
    static inline unsigned long pydbg_ctx_get_flags(void* pctx) {
        return ((CONTEXT*)pctx)->ContextFlags;
    }
    static inline void pydbg_ctx_set_flags(void* pctx, unsigned long f) {
        ((CONTEXT*)pctx)->ContextFlags = f;
    }

    /* Instruction pointer */
    static inline unsigned long long pydbg_ctx_get_ip(void* pctx) {
    #ifdef _WIN64
        return ((CONTEXT*)pctx)->Rip;
    #else
        return ((CONTEXT*)pctx)->Eip;
    #endif
    }
    static inline void pydbg_ctx_set_ip(void* pctx, unsigned long long v) {
    #ifdef _WIN64
        ((CONTEXT*)pctx)->Rip = v;
    #else
        ((CONTEXT*)pctx)->Eip = (DWORD)v;
    #endif
    }

    /* Stack pointer */
    static inline unsigned long long pydbg_ctx_get_sp(void* pctx) {
    #ifdef _WIN64
        return ((CONTEXT*)pctx)->Rsp;
    #else
        return ((CONTEXT*)pctx)->Esp;
    #endif
    }
    static inline void pydbg_ctx_set_sp(void* pctx, unsigned long long v) {
    #ifdef _WIN64
        ((CONTEXT*)pctx)->Rsp = v;
    #else
        ((CONTEXT*)pctx)->Esp = (DWORD)v;
    #endif
    }

    /* Base pointer */
    static inline unsigned long long pydbg_ctx_get_bp(void* pctx) {
    #ifdef _WIN64
        return ((CONTEXT*)pctx)->Rbp;
    #else
        return ((CONTEXT*)pctx)->Ebp;
    #endif
    }
    static inline void pydbg_ctx_set_bp(void* pctx, unsigned long long v) {
    #ifdef _WIN64
        ((CONTEXT*)pctx)->Rbp = v;
    #else
        ((CONTEXT*)pctx)->Ebp = (DWORD)v;
    #endif
    }

    /* EFLAGS */
    static inline unsigned long pydbg_ctx_get_eflags(void* pctx) {
        return ((CONTEXT*)pctx)->EFlags;
    }
    static inline void pydbg_ctx_set_eflags(void* pctx, unsigned long v) {
        ((CONTEXT*)pctx)->EFlags = v;
    }

    /* General-purpose registers by index.
       x64: 0=Rax 1=Rcx 2=Rdx 3=Rbx 4=Rsp 5=Rbp 6=Rsi 7=Rdi
            8=R8  9=R9  10=R10 11=R11 12=R12 13=R13 14=R14 15=R15
       x86: 0=Eax 1=Ecx 2=Edx 3=Ebx 4=Esp 5=Ebp 6=Esi 7=Edi */
    static inline unsigned long long pydbg_ctx_get_gp(void* pctx, int idx) {
        CONTEXT* ctx = (CONTEXT*)pctx;
    #ifdef _WIN64
        switch(idx) {
            case 0:  return ctx->Rax;  case 1:  return ctx->Rcx;
            case 2:  return ctx->Rdx;  case 3:  return ctx->Rbx;
            case 4:  return ctx->Rsp;  case 5:  return ctx->Rbp;
            case 6:  return ctx->Rsi;  case 7:  return ctx->Rdi;
            case 8:  return ctx->R8;   case 9:  return ctx->R9;
            case 10: return ctx->R10;  case 11: return ctx->R11;
            case 12: return ctx->R12;  case 13: return ctx->R13;
            case 14: return ctx->R14;  case 15: return ctx->R15;
        }
    #else
        switch(idx) {
            case 0: return ctx->Eax;  case 1: return ctx->Ecx;
            case 2: return ctx->Edx;  case 3: return ctx->Ebx;
            case 4: return ctx->Esp;  case 5: return ctx->Ebp;
            case 6: return ctx->Esi;  case 7: return ctx->Edi;
        }
    #endif
        return 0;
    }
    static inline void pydbg_ctx_set_gp(void* pctx, int idx, unsigned long long v) {
        CONTEXT* ctx = (CONTEXT*)pctx;
    #ifdef _WIN64
        switch(idx) {
            case 0:  ctx->Rax = v; break;  case 1:  ctx->Rcx = v; break;
            case 2:  ctx->Rdx = v; break;  case 3:  ctx->Rbx = v; break;
            case 4:  ctx->Rsp = v; break;  case 5:  ctx->Rbp = v; break;
            case 6:  ctx->Rsi = v; break;  case 7:  ctx->Rdi = v; break;
            case 8:  ctx->R8  = v; break;  case 9:  ctx->R9  = v; break;
            case 10: ctx->R10 = v; break;  case 11: ctx->R11 = v; break;
            case 12: ctx->R12 = v; break;  case 13: ctx->R13 = v; break;
            case 14: ctx->R14 = v; break;  case 15: ctx->R15 = v; break;
        }
    #else
        switch(idx) {
            case 0: ctx->Eax = (DWORD)v; break;  case 1: ctx->Ecx = (DWORD)v; break;
            case 2: ctx->Edx = (DWORD)v; break;  case 3: ctx->Ebx = (DWORD)v; break;
            case 4: ctx->Esp = (DWORD)v; break;  case 5: ctx->Ebp = (DWORD)v; break;
            case 6: ctx->Esi = (DWORD)v; break;  case 7: ctx->Edi = (DWORD)v; break;
        }
    #endif
    }

    /* Debug registers: Dr0-Dr3, Dr6, Dr7 (register index: 0,1,2,3,6,7) */
    static inline unsigned long long pydbg_ctx_get_dr(void* pctx, int reg) {
        CONTEXT* ctx = (CONTEXT*)pctx;
        switch(reg) {
            case 0: return (unsigned long long)ctx->Dr0;
            case 1: return (unsigned long long)ctx->Dr1;
            case 2: return (unsigned long long)ctx->Dr2;
            case 3: return (unsigned long long)ctx->Dr3;
            case 6: return (unsigned long long)ctx->Dr6;
            case 7: return (unsigned long long)ctx->Dr7;
        }
        return 0;
    }
    static inline void pydbg_ctx_set_dr(void* pctx, int reg, unsigned long long v) {
        CONTEXT* ctx = (CONTEXT*)pctx;
    #ifdef _WIN64
        switch(reg) {
            case 0: ctx->Dr0 = v; break;  case 1: ctx->Dr1 = v; break;
            case 2: ctx->Dr2 = v; break;  case 3: ctx->Dr3 = v; break;
            case 6: ctx->Dr6 = v; break;  case 7: ctx->Dr7 = v; break;
        }
    #else
        switch(reg) {
            case 0: ctx->Dr0 = (DWORD)v; break;  case 1: ctx->Dr1 = (DWORD)v; break;
            case 2: ctx->Dr2 = (DWORD)v; break;  case 3: ctx->Dr3 = (DWORD)v; break;
            case 6: ctx->Dr6 = (DWORD)v; break;  case 7: ctx->Dr7 = (DWORD)v; break;
        }
    #endif
    }

    /* Segment registers: 0=CS 1=DS 2=ES 3=FS 4=GS 5=SS */
    static inline unsigned short pydbg_ctx_get_seg(void* pctx, int reg) {
        CONTEXT* ctx = (CONTEXT*)pctx;
        switch(reg) {
            case 0: return ctx->SegCs;  case 1: return ctx->SegDs;
            case 2: return ctx->SegEs;  case 3: return ctx->SegFs;
            case 4: return ctx->SegGs;  case 5: return ctx->SegSs;
        }
        return 0;
    }

    /* Host architecture: 32 or 64 */
    static inline int pydbg_host_arch(void) {
    #ifdef _WIN64
        return 64;
    #else
        return 32;
    #endif
    }
    """
    int pydbg_ctx_sizeof()
    void pydbg_ctx_init(void* pctx, unsigned long flags)
    unsigned long pydbg_ctx_get_flags(void* pctx)
    void pydbg_ctx_set_flags(void* pctx, unsigned long f)
    unsigned long long pydbg_ctx_get_ip(void* pctx)
    void pydbg_ctx_set_ip(void* pctx, unsigned long long v)
    unsigned long long pydbg_ctx_get_sp(void* pctx)
    void pydbg_ctx_set_sp(void* pctx, unsigned long long v)
    unsigned long long pydbg_ctx_get_bp(void* pctx)
    void pydbg_ctx_set_bp(void* pctx, unsigned long long v)
    unsigned long pydbg_ctx_get_eflags(void* pctx)
    void pydbg_ctx_set_eflags(void* pctx, unsigned long v)
    unsigned long long pydbg_ctx_get_gp(void* pctx, int idx)
    void pydbg_ctx_set_gp(void* pctx, int idx, unsigned long long v)
    unsigned long long pydbg_ctx_get_dr(void* pctx, int reg)
    void pydbg_ctx_set_dr(void* pctx, int reg, unsigned long long v)
    unsigned short pydbg_ctx_get_seg(void* pctx, int reg)
    int pydbg_host_arch()
