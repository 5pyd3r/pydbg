# _dump.pxi — dbghelp.dll dump and stack walk wrappers

from libc.stdlib cimport malloc, free
from libc.string cimport memset, memcpy
from _win32types cimport (
    HANDLE, DWORD, BOOL, LPVOID,
    MINIDUMP_DIRECTORY, STACKFRAME64, KDHELP64,
    SYMBOL_INFOW, MAX_SYM_NAME,
    MiniDumpReadDumpStream, StackWalk64, SymFunctionTableAccess64,
    GetLastError,
    pydbg_ctx_arch_sizeof,
)

# ADDRESS_MODE.AddrModeFlat. It is 3 (1616/1632/Real/Flat), not 0 — seeding 0
# asks dbghelp for a 16:16 far frame and StackWalk64 answers FALSE.
cdef int _ADDR_MODE_FLAT = 3

# IMAGE_FILE_MACHINE, which is what StackWalk64 wants as MachineType. It is not
# the 32/64 flag the CONTEXT helpers take, so the two are mapped explicitly
# below instead of being compared against 32.
cdef unsigned long _MACHINE_X86 = 0x14C
cdef unsigned long _MACHINE_X64 = 0x8664


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
        unsigned long long initial_frame_fp,
        object frame_state=None):
    """Walk a single stack frame.

    Returns dict with frame_ip/frame_sp/frame_fp, plus the two pieces of
    state StackWalk64 needs to continue the walk: 'context' (the CONTEXT
    bytes, updated in place) and 'frame_state' (an opaque copy of the
    STACKFRAME64). Both must be handed back on the next call; passing only
    the frame addresses restarts from the same frame. Returns None when the
    stack ends.

    context_bytes: raw CONTEXT bytes from GetThreadContext. The buffer is
    copied, so the caller's bytes are not modified.
    frame_state: None for the first frame; the previous call's frame_state.

    Raises ValueError when context_bytes is shorter than the CONTEXT for
    machine_type.
    """
    cdef STACKFRAME64 sf
    memset(&sf, 0, sizeof(sf))
    cdef bytes state = frame_state if frame_state is not None else b""
    if len(state) == sizeof(STACKFRAME64):
        memcpy(&sf, <char*>state, sizeof(sf))
    else:
        sf.AddrPC.Offset = initial_frame_ip
        sf.AddrPC.Mode = _ADDR_MODE_FLAT
        sf.AddrStack.Offset = initial_frame_sp
        sf.AddrStack.Mode = _ADDR_MODE_FLAT
        sf.AddrFrame.Offset = initial_frame_fp
        sf.AddrFrame.Mode = _ADDR_MODE_FLAT

    # StackWalk64 interprets this pointer as the live CONTEXT (or
    # WOW64_CONTEXT for a 32-bit target) and writes back into it, so a buffer
    # shorter than the architecture's struct is an overflow waiting to happen.
    cdef bytes ctx = bytes(context_bytes)
    cdef Py_ssize_t ctx_len = len(ctx)
    # machine_type is IMAGE_FILE_MACHINE (0x14C / 0x8664), not the 32/64 flag
    # pydbg_ctx_arch_sizeof takes: handing it 0x14C as-is would ask for the x64
    # size and reject every real 716-byte WOW64_CONTEXT.
    cdef int ctx_arch
    if machine_type == _MACHINE_X86:
        ctx_arch = 32
    elif machine_type == _MACHINE_X64:
        ctx_arch = 64
    else:
        raise ValueError("unknown machine type 0x%X" % machine_type)
    cdef int need = pydbg_ctx_arch_sizeof(ctx_arch)
    if ctx_len < need:
        raise ValueError(
            "CONTEXT for machine 0x%X is %d bytes, got %d"
            % (machine_type, need, ctx_len))
    cdef void* ctx_copy = malloc(ctx_len)
    if ctx_copy == NULL:
        raise MemoryError("Failed to allocate CONTEXT copy")
    memcpy(ctx_copy, <char*>ctx, ctx_len)

    cdef BOOL result = StackWalk64(
        <unsigned long>machine_type,
        <HANDLE><LPVOID>h_process,
        <HANDLE><LPVOID>h_thread,
        &sf,
        ctx_copy,
        NULL,   # ReadMemoryRoutine (default: process memory)
        <void*>SymFunctionTableAccess64,
        NULL,   # GetModuleBaseRoutine (default: process modules)
        NULL)   # TranslateAddress

    cdef bytes next_context = (<char*>ctx_copy)[:ctx_len]
    cdef char* sf_raw = <char*>&sf
    cdef bytes next_state = sf_raw[:sizeof(STACKFRAME64)]
    free(ctx_copy)

    if result == 0:
        return None

    return {
        'frame_ip': <unsigned long long>sf.AddrPC.Offset,
        'frame_sp': <unsigned long long>sf.AddrStack.Offset,
        'frame_fp': <unsigned long long>sf.AddrFrame.Offset,
        'context': next_context,
        'frame_state': next_state,
    }
