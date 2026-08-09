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
    DWORD WOW64_CONTEXT_ALL
    BOOL Wow64GetThreadContext(HANDLE hThread, void* lpContext)
    BOOL Wow64SetThreadContext(HANDLE hThread, void* lpContext)
    DWORD SuspendThread(HANDLE hThread)
    DWORD ResumeThread(HANDLE hThread)
    DWORD GetThreadId(HANDLE hThread)
    BOOL GetThreadTimes(HANDLE hThread, void* lpCreationTime, void* lpExitTime,
        void* lpKernelTime, void* lpUserTime)
    BOOL IsWow64Process(HANDLE hProcess, BOOL* Wow64Process)

cdef extern from "psapi.h":
    BOOL EnumProcessModules(HANDLE hProcess, HMODULE* lphModule, DWORD cb, DWORD* lpcbNeeded)
    DWORD LIST_MODULES_ALL
    BOOL EnumProcessModulesEx(HANDLE hProcess, HMODULE* lphModule,
                              DWORD cb, DWORD* lpcbNeeded, DWORD dwFilterFlag)
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

    /* 缓冲尺寸：x64 原生 CONTEXT 或 WOW64 (x86) CONTEXT 中较大的一个。
       扩展只编 x64，sizeof(CONTEXT) > sizeof(WOW64_CONTEXT)。 */
    typedef union {
        CONTEXT native;
        WOW64_CONTEXT wow64;
    } pydbg_ctx_buf_t;

    static inline int pydbg_ctx_sizeof(void) { return (int)sizeof(pydbg_ctx_buf_t); }

    /* machine: 32 = WOW64/x86 布局，其它 = x64 布局 */
    static inline void pydbg_ctx_init(void* pctx, int machine, unsigned long flags) {
        memset(pctx, 0, sizeof(pydbg_ctx_buf_t));
        if (machine == 32) ((WOW64_CONTEXT*)pctx)->ContextFlags = flags;
        else ((CONTEXT*)pctx)->ContextFlags = flags;
    }
    static inline unsigned long pydbg_ctx_get_flags(void* pctx, int machine) {
        return machine == 32 ? ((WOW64_CONTEXT*)pctx)->ContextFlags
                             : ((CONTEXT*)pctx)->ContextFlags;
    }
    static inline void pydbg_ctx_set_flags(void* pctx, int machine, unsigned long f) {
        if (machine == 32) ((WOW64_CONTEXT*)pctx)->ContextFlags = f;
        else ((CONTEXT*)pctx)->ContextFlags = f;
    }

    static inline unsigned long long pydbg_ctx_get_ip(void* pctx, int machine) {
        return machine == 32 ? (unsigned long long)((WOW64_CONTEXT*)pctx)->Eip
                             : ((CONTEXT*)pctx)->Rip;
    }
    static inline void pydbg_ctx_set_ip(void* pctx, int machine, unsigned long long v) {
        if (machine == 32) ((WOW64_CONTEXT*)pctx)->Eip = (DWORD)v;
        else ((CONTEXT*)pctx)->Rip = v;
    }
    static inline unsigned long long pydbg_ctx_get_sp(void* pctx, int machine) {
        return machine == 32 ? (unsigned long long)((WOW64_CONTEXT*)pctx)->Esp
                             : ((CONTEXT*)pctx)->Rsp;
    }
    static inline void pydbg_ctx_set_sp(void* pctx, int machine, unsigned long long v) {
        if (machine == 32) ((WOW64_CONTEXT*)pctx)->Esp = (DWORD)v;
        else ((CONTEXT*)pctx)->Rsp = v;
    }
    static inline unsigned long long pydbg_ctx_get_bp(void* pctx, int machine) {
        return machine == 32 ? (unsigned long long)((WOW64_CONTEXT*)pctx)->Ebp
                             : ((CONTEXT*)pctx)->Rbp;
    }
    static inline void pydbg_ctx_set_bp(void* pctx, int machine, unsigned long long v) {
        if (machine == 32) ((WOW64_CONTEXT*)pctx)->Ebp = (DWORD)v;
        else ((CONTEXT*)pctx)->Rbp = v;
    }
    static inline unsigned long pydbg_ctx_get_eflags(void* pctx, int machine) {
        return machine == 32 ? ((WOW64_CONTEXT*)pctx)->EFlags : ((CONTEXT*)pctx)->EFlags;
    }
    static inline void pydbg_ctx_set_eflags(void* pctx, int machine, unsigned long v) {
        if (machine == 32) ((WOW64_CONTEXT*)pctx)->EFlags = v;
        else ((CONTEXT*)pctx)->EFlags = v;
    }

    /* GP 寄存器索引表（两架构统一）：
       x86: 0=Eax 1=Ecx 2=Edx 3=Ebx 4=Esp 5=Ebp 6=Esi 7=Edi
       x64: 0=Rax 1=Rcx 2=Rdx 3=Rbx 4=Rsp 5=Rbp 6=Rsi 7=Rdi 8=R8..15=R15 */
    static inline unsigned long long pydbg_ctx_get_gp(void* pctx, int machine, int idx) {
        if (machine == 32) {
            WOW64_CONTEXT* c = (WOW64_CONTEXT*)pctx;
            switch (idx) {
                case 0: return c->Eax;  case 1: return c->Ecx;
                case 2: return c->Edx;  case 3: return c->Ebx;
                case 4: return c->Esp;  case 5: return c->Ebp;
                case 6: return c->Esi;  case 7: return c->Edi;
            }
            return 0;
        }
        CONTEXT* c = (CONTEXT*)pctx;
        switch (idx) {
            case 0:  return c->Rax;  case 1:  return c->Rcx;
            case 2:  return c->Rdx;  case 3:  return c->Rbx;
            case 4:  return c->Rsp;  case 5:  return c->Rbp;
            case 6:  return c->Rsi;  case 7:  return c->Rdi;
            case 8:  return c->R8;   case 9:  return c->R9;
            case 10: return c->R10;  case 11: return c->R11;
            case 12: return c->R12;  case 13: return c->R13;
            case 14: return c->R14;  case 15: return c->R15;
        }
        return 0;
    }
    static inline void pydbg_ctx_set_gp(void* pctx, int machine, int idx, unsigned long long v) {
        if (machine == 32) {
            WOW64_CONTEXT* c = (WOW64_CONTEXT*)pctx;
            switch (idx) {
                case 0: c->Eax = (DWORD)v; break;  case 1: c->Ecx = (DWORD)v; break;
                case 2: c->Edx = (DWORD)v; break;  case 3: c->Ebx = (DWORD)v; break;
                case 4: c->Esp = (DWORD)v; break;  case 5: c->Ebp = (DWORD)v; break;
                case 6: c->Esi = (DWORD)v; break;  case 7: c->Edi = (DWORD)v; break;
            }
            return;
        }
        CONTEXT* c = (CONTEXT*)pctx;
        switch (idx) {
            case 0:  c->Rax = v; break;  case 1:  c->Rcx = v; break;
            case 2:  c->Rdx = v; break;  case 3:  c->Rbx = v; break;
            case 4:  c->Rsp = v; break;  case 5:  c->Rbp = v; break;
            case 6:  c->Rsi = v; break;  case 7:  c->Rdi = v; break;
            case 8:  c->R8  = v; break;  case 9:  c->R9  = v; break;
            case 10: c->R10 = v; break;  case 11: c->R11 = v; break;
            case 12: c->R12 = v; break;  case 13: c->R13 = v; break;
            case 14: c->R14 = v; break;  case 15: c->R15 = v; break;
        }
    }

    /* 调试寄存器 Dr0-3, Dr6, Dr7（索引 0,1,2,3,6,7） */
    static inline unsigned long long pydbg_ctx_get_dr(void* pctx, int machine, int reg) {
        WOW64_CONTEXT* w = (WOW64_CONTEXT*)pctx;
        CONTEXT* n = (CONTEXT*)pctx;
        if (machine == 32) {
            switch (reg) {
                case 0: return w->Dr0;  case 1: return w->Dr1;
                case 2: return w->Dr2;  case 3: return w->Dr3;
                case 6: return w->Dr6;  case 7: return w->Dr7;
            }
            return 0;
        }
        switch (reg) {
            case 0: return n->Dr0;  case 1: return n->Dr1;
            case 2: return n->Dr2;  case 3: return n->Dr3;
            case 6: return n->Dr6;  case 7: return n->Dr7;
        }
        return 0;
    }
    static inline void pydbg_ctx_set_dr(void* pctx, int machine, int reg, unsigned long long v) {
        if (machine == 32) {
            WOW64_CONTEXT* c = (WOW64_CONTEXT*)pctx;
            switch (reg) {
                case 0: c->Dr0 = (DWORD)v; break;  case 1: c->Dr1 = (DWORD)v; break;
                case 2: c->Dr2 = (DWORD)v; break;  case 3: c->Dr3 = (DWORD)v; break;
                case 6: c->Dr6 = (DWORD)v; break;  case 7: c->Dr7 = (DWORD)v; break;
            }
            return;
        }
        CONTEXT* c = (CONTEXT*)pctx;
        switch (reg) {
            case 0: c->Dr0 = v; break;  case 1: c->Dr1 = v; break;
            case 2: c->Dr2 = v; break;  case 3: c->Dr3 = v; break;
            case 6: c->Dr6 = v; break;  case 7: c->Dr7 = v; break;
        }
    }

    /* 段寄存器：0=CS 1=DS 2=ES 3=FS 4=GS 5=SS */
    static inline unsigned short pydbg_ctx_get_seg(void* pctx, int machine, int reg) {
        WOW64_CONTEXT* w = (WOW64_CONTEXT*)pctx;
        CONTEXT* n = (CONTEXT*)pctx;
        switch (reg) {
            case 0: return machine == 32 ? (unsigned short)w->SegCs : n->SegCs;
            case 1: return machine == 32 ? (unsigned short)w->SegDs : n->SegDs;
            case 2: return machine == 32 ? (unsigned short)w->SegEs : n->SegEs;
            case 3: return machine == 32 ? (unsigned short)w->SegFs : n->SegFs;
            case 4: return machine == 32 ? (unsigned short)w->SegGs : n->SegGs;
            case 5: return machine == 32 ? (unsigned short)w->SegSs : n->SegSs;
        }
        return 0;
    }

    /* 宿主架构：扩展只编 x64，恒为 64 */
    static inline int pydbg_host_arch(void) { return 64; }
    """
    int pydbg_ctx_sizeof()
    void pydbg_ctx_init(void* pctx, int machine, unsigned long flags)
    unsigned long pydbg_ctx_get_flags(void* pctx, int machine)
    void pydbg_ctx_set_flags(void* pctx, int machine, unsigned long f)
    unsigned long long pydbg_ctx_get_ip(void* pctx, int machine)
    void pydbg_ctx_set_ip(void* pctx, int machine, unsigned long long v)
    unsigned long long pydbg_ctx_get_sp(void* pctx, int machine)
    void pydbg_ctx_set_sp(void* pctx, int machine, unsigned long long v)
    unsigned long long pydbg_ctx_get_bp(void* pctx, int machine)
    void pydbg_ctx_set_bp(void* pctx, int machine, unsigned long long v)
    unsigned long pydbg_ctx_get_eflags(void* pctx, int machine)
    void pydbg_ctx_set_eflags(void* pctx, int machine, unsigned long v)
    unsigned long long pydbg_ctx_get_gp(void* pctx, int machine, int idx)
    void pydbg_ctx_set_gp(void* pctx, int machine, int idx, unsigned long long v)
    unsigned long long pydbg_ctx_get_dr(void* pctx, int machine, int reg)
    void pydbg_ctx_set_dr(void* pctx, int machine, int reg, unsigned long long v)
    unsigned short pydbg_ctx_get_seg(void* pctx, int machine, int reg)
    int pydbg_host_arch()
