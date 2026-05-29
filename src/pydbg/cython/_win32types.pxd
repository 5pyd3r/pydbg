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

    ctypedef struct CONTEXT:
        DWORD64 P1Home
        DWORD64 P2Home
        DWORD64 P3Home
        DWORD64 P4Home
        DWORD64 P5Home
        DWORD64 P6Home
        DWORD ContextFlags
        DWORD MxCsr
        WORD SegCs
        WORD SegDs
        WORD SegEs
        WORD SegFs
        WORD SegGs
        WORD SegSs
        DWORD EFlags
        DWORD64 Dr0
        DWORD64 Dr1
        DWORD64 Dr2
        DWORD64 Dr3
        DWORD64 Dr6
        DWORD64 Dr7
        DWORD64 Rax
        DWORD64 Rcx
        DWORD64 Rdx
        DWORD64 Rbx
        DWORD64 Rsp
        DWORD64 Rbp
        DWORD64 Rsi
        DWORD64 Rdi
        DWORD64 R8
        DWORD64 R9
        DWORD64 R10
        DWORD64 R11
        DWORD64 R12
        DWORD64 R13
        DWORD64 R14
        DWORD64 R15
        DWORD64 Rip

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
    BOOL GetThreadContext(HANDLE hThread, CONTEXT* lpContext)
    BOOL SetThreadContext(HANDLE hThread, CONTEXT* lpContext)
    DWORD SuspendThread(HANDLE hThread)
    DWORD ResumeThread(HANDLE hThread)
    DWORD GetThreadId(HANDLE hThread)
    BOOL GetThreadTimes(HANDLE hThread, void* lpCreationTime, void* lpExitTime,
        void* lpKernelTime, void* lpUserTime)

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
