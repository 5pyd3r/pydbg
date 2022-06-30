from libcpp cimport bool

cdef extern from "Windows.h":
    ctypedef Py_UNICODE WCHAR
    ctypedef const WCHAR* LPCWSTR
    ctypedef WCHAR* LPWSTR
    ctypedef char* LPSTR
    ctypedef const void* LPCVOID
    ctypedef void* PVOID
    ctypedef size_t SIZE_T
    cdef struct SECURITY_ATTRIBUTES:
        pass

    ctypedef SECURITY_ATTRIBUTES* LPSECURITY_ATTRIBUTES
    ctypedef int BOOL
    ctypedef unsigned long DWORD
    ctypedef unsigned short WORD
    ctypedef void* LPVOID
    ctypedef struct STARTUPINFOW:
        DWORD cb

    ctypedef STARTUPINFOW* LPSTARTUPINFOW

    ctypedef void* HANDLE
    ctypedef struct PROCESS_INFORMATION:
        HANDLE hProcess
        DWORD dwProcessId
        DWORD dwThreadId

    ctypedef PROCESS_INFORMATION* LPPROCESS_INFORMATION

    BOOL CreateProcessW(
        LPCWSTR lpApplicationName, 
        LPWSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles,
        DWORD dwCreationFlags,
        LPVOID lpEnvironment,
        LPCWSTR lpCurrentDirectory,
        LPSTARTUPINFOW lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation)

    DWORD GetLastError()
    DWORD ERROR_ALREADY_EXISTS, ERROR_INVALID_HANDLE

    BOOL CloseHandle(HANDLE h)

    BOOL ReadProcessMemory(
        HANDLE  hProcess,
        LPCVOID lpBaseAddress,
        LPVOID  lpBuffer,
        SIZE_T  nSize,
        SIZE_T  *lpNumberOfBytesRead
    )

    BOOL WriteProcessMemory(
        HANDLE  hProcess,
        LPVOID  lpBaseAddress,
        LPCVOID lpBuffer,
        SIZE_T  nSize,
        SIZE_T  *lpNumberOfBytesWritten
    )

cdef extern from "debugapi.h":
    BOOL DebugActiveProcessStop(DWORD dwProcessId)
    BOOL DebugActiveProcess(DWORD dwProcessId)

    DWORD EXCEPTION_ACCESS_VIOLATION
    DWORD EXCEPTION_ARRAY_BOUNDS_EXCEEDED
    DWORD EXCEPTION_BREAKPOINT
    DWORD EXCEPTION_DATATYPE_MISALIGNMENT
    DWORD EXCEPTION_FLT_DENORMAL_OPERAND
    DWORD EXCEPTION_FLT_DIVIDE_BY_ZERO
    DWORD EXCEPTION_FLT_INEXACT_RESULT
    DWORD EXCEPTION_FLT_INVALID_OPERATION
    DWORD EXCEPTION_FLT_OVERFLOW 
    DWORD EXCEPTION_FLT_STACK_CHECK
    DWORD EXCEPTION_FLT_UNDERFLOW
    DWORD EXCEPTION_ILLEGAL_INSTRUCTION
    DWORD EXCEPTION_IN_PAGE_ERROR
    DWORD EXCEPTION_INT_DIVIDE_BY_ZERO
    DWORD EXCEPTION_INT_OVERFLOW
    DWORD EXCEPTION_INVALID_DISPOSITION
    DWORD EXCEPTION_NONCONTINUABLE_EXCEPTION
    DWORD EXCEPTION_PRIV_INSTRUCTION
    DWORD EXCEPTION_SINGLE_STEP
    DWORD EXCEPTION_STACK_OVERFLOW

    ctypedef struct EXCEPTION_RECORD:
        DWORD ExceptionCode
        DWORD ExceptionFlags
        PVOID ExceptionAddress
        DWORD NumberParameters

    ctypedef struct EXCEPTION_DEBUG_INFO:
        EXCEPTION_RECORD ExceptionRecord
        DWORD dwFirstChance

    ctypedef struct CREATE_THREAD_DEBUG_INFO:
        HANDLE hThread
        LPVOID lpThreadLocalBase

    ctypedef struct CREATE_PROCESS_DEBUG_INFO:
        HANDLE hFile
        HANDLE hProcess
        HANDLE hThread
        LPVOID lpBaseOfImage
        DWORD dwDebugInfoFileOffset
        DWORD nDebugInfoSize
        LPVOID lpThreadLocalBase
        LPVOID lpImageName
        WORD fUnicode

    ctypedef struct EXIT_THREAD_DEBUG_INFO:
        DWORD dwExitCode

    ctypedef struct EXIT_PROCESS_DEBUG_INFO:
        DWORD dwExitCode
    
    ctypedef struct LOAD_DLL_DEBUG_INFO:
        HANDLE hFile
        LPVOID lpBaseOfDll
        DWORD dwDebugInfoFileOffset
        DWORD nDebugInfoSize
        LPVOID lpImageName
        WORD fUnicode

    ctypedef struct UNLOAD_DLL_DEBUG_INFO:
        LPVOID lpBaseOfDll

    ctypedef struct OUTPUT_DEBUG_STRING_INFO:
        LPSTR lpDebugStringData
        WORD fUnicode
        WORD nDebugStringLength

    ctypedef struct RIP_INFO:
        DWORD dwError
        DWORD dwType

    ctypedef struct _DEBUG_INFO:
        EXCEPTION_DEBUG_INFO Exception
        CREATE_THREAD_DEBUG_INFO CreateThread
        CREATE_PROCESS_DEBUG_INFO CreateProcessInfo
        EXIT_THREAD_DEBUG_INFO ExitThread
        EXIT_PROCESS_DEBUG_INFO ExitProcess
        LOAD_DLL_DEBUG_INFO LoadDll
        UNLOAD_DLL_DEBUG_INFO UnloadDll
        OUTPUT_DEBUG_STRING_INFO DebugString
        RIP_INFO RipInfo

    DWORD EXCEPTION_DEBUG_EVENT
    DWORD CREATE_THREAD_DEBUG_EVENT
    DWORD CREATE_PROCESS_DEBUG_EVENT
    DWORD EXIT_THREAD_DEBUG_EVENT
    DWORD EXIT_PROCESS_DEBUG_EVENT
    DWORD LOAD_DLL_DEBUG_EVENT
    DWORD UNLOAD_DLL_DEBUG_EVENT
    DWORD OUTPUT_DEBUG_STRING_EVENT
    DWORD RIP_EVENT

    ctypedef struct DEBUG_EVENT:
        DWORD dwDebugEventCode
        DWORD dwProcessId
        DWORD dwThreadId
        _DEBUG_INFO u
    ctypedef DEBUG_EVENT* LPDEBUG_EVENT
    DWORD INFINITE
    BOOL WaitForDebugEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds)
    DWORD DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, DBG_REPLY_LATER
    BOOL ContinueDebugEvent(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus)

cdef extern from "winhelper.h":
    ctypedef DWORD c_pid_t
    ctypedef DWORD c_tid_t
    bool c_attach(c_pid_t pid)
    bool c_detach(c_pid_t pid)
    bool c_start(char* path, char* const argv[])
    bool c_wait_event(LPDEBUG_EVENT event)
    bool c_continue(c_pid_t pid, c_tid_t tid)