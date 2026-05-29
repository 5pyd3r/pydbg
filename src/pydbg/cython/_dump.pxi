# _dump.pxi — dbghelp.dll dump and stack walk wrappers

from libc.string cimport memset
from _win32types cimport (
    HANDLE, DWORD, BOOL, LPVOID,
    MINIDUMP_DIRECTORY, STACKFRAME64, KDHELP64,
    SYMBOL_INFOW, MAX_SYM_NAME,
    MiniDumpReadDumpStream, StackWalk64, SymFunctionTableAccess64,
    GetLastError,
)


cpdef bytes mini_dump_read_dump_stream(
        unsigned long long base_of_dump, unsigned long stream_number):
    """Read a stream from a minidump file in memory.

    Returns the stream data as bytes. Raises OSError on failure.
    """
    cdef MINIDUMP_DIRECTORY* dirent = NULL
    cdef void* stream_ptr = NULL
    cdef unsigned long stream_size = 0

    cdef BOOL result = MiniDumpReadDumpStream(
        <void*>base_of_dump,
        <unsigned long>stream_number,
        &dirent,
        &stream_ptr,
        &stream_size)

    if result == 0 or stream_ptr == NULL:
        raise OSError(GetLastError(), "MiniDumpReadDumpStream failed")

    cdef bytes data = (<char*>stream_ptr)[:stream_size]
    return data


cpdef dict stack_walk_frame(unsigned long machine_type,
        unsigned long long h_process, unsigned long long h_thread,
        object context_bytes,
        unsigned long long initial_frame_ip,
        unsigned long long initial_frame_sp,
        unsigned long long initial_frame_fp):
    """Walk a single stack frame.

    Returns dict with frame_ip, frame_sp, frame_fp or None when done.
    context_bytes: raw CONTEXT bytes from GetThreadContext.
    """
    cdef STACKFRAME64 sf
    memset(&sf, 0, sizeof(sf))
    sf.AddrPC.Offset = initial_frame_ip
    sf.AddrPC.Mode = 0  # AddrModeFlat
    sf.AddrStack.Offset = initial_frame_sp
    sf.AddrStack.Mode = 0
    sf.AddrFrame.Offset = initial_frame_fp
    sf.AddrFrame.Mode = 0

    cdef void* ctx = <void*>(<char*>context_bytes)

    cdef BOOL result = StackWalk64(
        <unsigned long>machine_type,
        <HANDLE><LPVOID>h_process,
        <HANDLE><LPVOID>h_thread,
        &sf,
        ctx,
        NULL,   # ReadMemoryRoutine (default: process memory)
        <void*>SymFunctionTableAccess64,
        NULL,   # GetModuleBaseRoutine (default: process modules)
        NULL)   # TranslateAddress

    if result == 0:
        return None

    return {
        'frame_ip': <unsigned long long>sf.AddrPC.Offset,
        'frame_sp': <unsigned long long>sf.AddrStack.Offset,
        'frame_fp': <unsigned long long>sf.AddrFrame.Offset,
    }
