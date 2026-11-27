# _memory.pyx — Win32 memory and module operations

from libc.stdint cimport uint32_t, uint64_t, uintptr_t
from libc.stdlib cimport malloc, free
from _win32types cimport (
    HANDLE, DWORD, BOOL, LPVOID, LPCVOID, SIZE_T, LPCSTR,
    HMODULE,
    MEMORY_BASIC_INFORMATION, MODULEINFO,
    ReadProcessMemory, WriteProcessMemory,
    VirtualQueryEx, VirtualProtectEx, VirtualAllocEx, VirtualFreeEx,
    EnumProcessModulesEx, LIST_MODULES_32BIT, LIST_MODULES_64BIT,
    LIST_MODULES_ALL, GetModuleFileNameExA,
    GetModuleInformation, GetLastError, CloseHandle,
    MEM_COMMIT, MEM_RESERVE, MEM_FREE, MEM_RELEASE, MEM_PRIVATE,
    MEM_MAPPED, MEM_IMAGE,
    PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
)

cpdef bytes read_process_memory(uintptr_t h_process, uintptr_t addr, size_t size):
    """Read 'size' bytes from process memory at 'addr'.

    Returns bytes read. Raises OSError on failure.
    """
    cdef void* buf = malloc(size)
    if buf == NULL:
        raise MemoryError("Failed to allocate read buffer")

    cdef SIZE_T bytes_read = 0
    cdef BOOL result = ReadProcessMemory(
        <HANDLE>h_process,
        <LPCVOID>addr,
        buf,
        <SIZE_T>size,
        &bytes_read)

    if result == 0:
        free(buf)
        raise OSError(GetLastError(), "ReadProcessMemory failed")

    cdef bytes data = (<char*>buf)[:bytes_read]
    free(buf)
    return data


cpdef tuple read_process_memory_partial(uintptr_t h_process, uintptr_t addr,
                                        size_t size):
    """Read up to 'size' bytes, keeping whatever transferred.

    Returns (data, bytes_read, error_code); error_code is 0 on full success.

    ReadProcessMemory reports how much it copied before failing
    (ERROR_PARTIAL_COPY, 299) when the range spans an unreadable page. That
    partial result is exactly what callers rebuilding a broken image need, so
    a failed read returns it instead of raising and losing it. Only an
    allocation failure raises.
    """
    cdef size_t alloc = size if size > 0 else 1
    cdef void* buf = malloc(alloc)
    if buf == NULL:
        raise MemoryError("Failed to allocate read buffer")

    cdef SIZE_T bytes_read = 0
    cdef BOOL result = ReadProcessMemory(
        <HANDLE>h_process,
        <LPCVOID>addr,
        buf,
        <SIZE_T>size,
        &bytes_read)

    cdef DWORD err = 0
    if result == 0:
        err = GetLastError()

    cdef bytes data = (<char*>buf)[:bytes_read]
    free(buf)
    return (data, <size_t>bytes_read, err)


cpdef int write_process_memory(uintptr_t h_process, uintptr_t addr, bytes data):
    """Write bytes to process memory at 'addr'.

    Returns number of bytes written. Raises OSError on failure.
    """
    cdef const char *buf = data
    cdef int size = len(data)
    cdef SIZE_T bytes_written = 0
    cdef BOOL result = WriteProcessMemory(
        <HANDLE>h_process,
        <LPVOID>addr,
        buf,
        <SIZE_T>size,
        &bytes_written)

    if result == 0:
        raise OSError(GetLastError(), "WriteProcessMemory failed")

    return <int>bytes_written


cdef dict _mbi_to_dict(MEMORY_BASIC_INFORMATION mbi):
    """Convert a MEMORY_BASIC_INFORMATION into the public region dict."""
    return {
        'base_address': <uint64_t>mbi.BaseAddress,
        'allocation_base': <uint64_t>mbi.AllocationBase,
        'allocation_protect': mbi.AllocationProtect,
        'region_size': <uint64_t>mbi.RegionSize,
        'state': mbi.State,
        'protect': mbi.Protect,
        'type': mbi.Type,
    }


cpdef dict virtual_query_ex(uintptr_t h_process, uintptr_t addr):
    """Query memory region info at 'addr'.

    Returns dict with: base_address, allocation_base, allocation_protect,
    region_size, state, protect, type.
    Raises OSError on failure.
    """
    cdef MEMORY_BASIC_INFORMATION mbi
    cdef SIZE_T result = VirtualQueryEx(
        <HANDLE>h_process,
        <LPVOID>addr,
        &mbi,
        sizeof(MEMORY_BASIC_INFORMATION))

    if result == 0:
        raise OSError(GetLastError(), "VirtualQueryEx failed")

    return _mbi_to_dict(mbi)


cpdef list virtual_query_all(uintptr_t h_process, uintptr_t start=0,
                             uintptr_t max_addr=0):
    """Walk the target's virtual address space with VirtualQueryEx.

    Returns a list of region dicts (same shape as virtual_query_ex) in
    ascending address order, covering both committed and free regions.
    'max_addr' of 0 means "to the end of the address space".

    A rejected query is how the walk *ends*, not an error, so unlike
    virtual_query_ex this never raises OSError.
    """
    cdef MEMORY_BASIC_INFORMATION mbi
    cdef list out = []
    cdef uintptr_t addr = start
    cdef uintptr_t base
    cdef uintptr_t rsize
    cdef SIZE_T result

    while True:
        result = VirtualQueryEx(
            <HANDLE>h_process,
            <LPCVOID>addr,
            &mbi,
            sizeof(MEMORY_BASIC_INFORMATION))
        if result == 0:
            break

        base = <uintptr_t>mbi.BaseAddress
        rsize = <uintptr_t>mbi.RegionSize
        if rsize == 0:
            break

        out.append(_mbi_to_dict(mbi))

        addr = base + rsize
        if addr <= base:            # wrapped past the top of the address space
            break
        if max_addr != 0 and addr >= max_addr:
            break

    return out


cpdef int virtual_protect_ex(uintptr_t h_process, uintptr_t addr,
                              int size, int protect):
    """Change memory protection on a region.

    Returns old protection value. Raises OSError on failure.
    """
    cdef DWORD old_protect
    cdef BOOL result = VirtualProtectEx(
        <HANDLE>h_process,
        <LPVOID>addr,
        <SIZE_T>size,
        <DWORD>protect,
        &old_protect)

    if result == 0:
        raise OSError(GetLastError(), "VirtualProtectEx failed")

    return old_protect


cdef list _enum_process_modules(uintptr_t h_process, DWORD filter_flag):
    """Enumerate one module table of a process.

    'filter_flag' is the psapi.h table selector: LIST_MODULES_ALL for
    everything Windows reports, or LIST_MODULES_32BIT / LIST_MODULES_64BIT
    for exactly one table. The buffer grows until EnumProcessModulesEx
    reports that everything fit. A fixed 1024-entry array used to return
    whatever portion fit, and a truncated module list is indistinguishable
    from a complete one.
    """
    cdef DWORD cb_needed = 0
    cdef DWORD capacity = 256
    cdef void* buffer = NULL
    cdef BOOL result
    cdef list out
    cdef int count
    cdef int i
    cdef int attempt

    for attempt in range(16):
        buffer = malloc(capacity * sizeof(HMODULE))
        if buffer == NULL:
            raise MemoryError("cannot allocate module list buffer")
        result = EnumProcessModulesEx(
            <HANDLE>h_process,
            <HMODULE*>buffer,
            capacity * sizeof(HMODULE),
            &cb_needed,
            filter_flag)
        if result == 0:
            free(buffer)
            raise OSError(GetLastError(), "EnumProcessModulesEx failed")
        if cb_needed <= capacity * sizeof(HMODULE):
            break
        free(buffer)
        buffer = NULL
        # Grow past the reported need: modules can load between the calls.
        capacity = cb_needed // sizeof(HMODULE) + 16
    else:
        free(buffer)
        raise OSError(0, "EnumProcessModulesEx kept reporting growth")

    count = cb_needed // sizeof(HMODULE)
    out = []
    for i in range(count):
        out.append({
            'handle': <uint64_t>((<HMODULE*>buffer)[i]),
            'base_address': <uint64_t>((<HMODULE*>buffer)[i]),
        })
    free(buffer)
    return out


cpdef list enum_process_modules(uintptr_t h_process):
    """Enumerate loaded modules in a process.

    Returns list of dicts with: handle, base_address.
    Raises OSError on failure.

    This is the historical LIST_MODULES_ALL view. On a WOW64 target it holds
    both tables; enum_process_modules_ex() selects one of them.
    """
    return _enum_process_modules(h_process, LIST_MODULES_ALL)


cpdef list enum_process_modules_ex(uintptr_t h_process, DWORD filter_flag):
    """Enumerate one architecture's module table in a process.

    'filter_flag' is LIST_MODULES_32BIT or LIST_MODULES_64BIT (the Python
    copies live in pydbg.constants). Windows rejects a table the process
    cannot have, so the caller must check the target's architecture before
    asking — ModuleResolver does.

    A WOW64 process has no 32-bit table before the loader has mapped its
    32-bit image; until then EnumProcessModulesEx raises ERROR_PARTIAL_COPY
    and this function raises OSError carrying that code.

    Returns list of dicts with: handle, base_address.
    Raises OSError on failure.
    """
    return _enum_process_modules(h_process, filter_flag)


cpdef str get_module_file_name_ex(uintptr_t h_process, uintptr_t h_module):
    """Get file name of a module in a process.

    Returns file path string. Raises OSError on failure.
    """
    cdef char[260] filename
    cdef DWORD len = GetModuleFileNameExA(
        <HANDLE>h_process,
        <HANDLE>h_module,
        filename,
        260)

    if len == 0:
        raise OSError(GetLastError(), "GetModuleFileNameExA failed")

    return filename[:len].decode('mbcs', errors='replace')


cpdef dict virtual_alloc_ex(uintptr_t h_process, uintptr_t addr,
                            size_t size, int alloc_type, int protect):
    """Allocate memory in the remote process.

    Returns dict with base_address. Raises OSError on failure.
    """
    cdef LPVOID result = VirtualAllocEx(
        <HANDLE>h_process,
        <LPVOID>addr,
        <SIZE_T>size,
        <DWORD>alloc_type,
        <DWORD>protect)

    if result == NULL:
        raise OSError(GetLastError(), "VirtualAllocEx failed")

    return {'base_address': <uint64_t>result}


cpdef int virtual_free_ex(uintptr_t h_process, uintptr_t addr,
                           size_t size, int free_type):
    """Free memory in the remote process.

    Returns 0 on success. Raises OSError on failure.
    """
    cdef BOOL result = VirtualFreeEx(
        <HANDLE>h_process,
        <LPVOID>addr,
        <SIZE_T>size,
        <DWORD>free_type)

    if result == 0:
        raise OSError(GetLastError(), "VirtualFreeEx failed")

    return 0


cpdef dict virtual_alloc(uintptr_t h_process, size_t size,
                          int alloc_type, int protect):
    """Allocate memory in the remote process (null address).

    Convenience wrapper: always passes NULL for lpAddress.
    Returns dict with base_address. Raises OSError on failure.
    """
    return virtual_alloc_ex(h_process, 0, size, alloc_type, protect)


cpdef int virtual_free(uintptr_t h_process, uintptr_t addr,
                        size_t size, int free_type):
    """Free memory in the remote process.

    Convenience alias for virtual_free_ex.
    Returns 0 on success. Raises OSError on failure.
    """
    return virtual_free_ex(h_process, addr, size, free_type)
