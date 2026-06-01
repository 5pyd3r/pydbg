# _memory.pyx — Win32 memory and module operations

from libc.stdint cimport uint32_t, uint64_t, uintptr_t
from libc.stdlib cimport malloc, free
from _win32types cimport (
    HANDLE, DWORD, BOOL, LPVOID, LPCVOID, SIZE_T, LPCSTR, LPDWORD,
    HMODULE,
    MEMORY_BASIC_INFORMATION, MODULEINFO, MODULEENTRY32,
    ReadProcessMemory, WriteProcessMemory,
    VirtualQueryEx, VirtualProtectEx, VirtualAllocEx, VirtualFreeEx,
    EnumProcessModules, EnumProcessModulesEx, GetModuleFileNameExA,
    GetModuleInformation, GetLastError, CloseHandle,
    CreateToolhelp32Snapshot, Module32First, Module32Next,
    TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
    MEM_COMMIT, MEM_RESERVE, MEM_FREE, MEM_RELEASE, MEM_PRIVATE,
    MEM_MAPPED, MEM_IMAGE,
    PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
)

# LIST_MODULES_ALL = 0x03: enumerate 32-bit and 64-bit modules
DEF LIST_MODULES_ALL = 3

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

    return {
        'base_address': <uint64_t>mbi.BaseAddress,
        'allocation_base': <uint64_t>mbi.AllocationBase,
        'allocation_protect': mbi.AllocationProtect,
        'region_size': <uint64_t>mbi.RegionSize,
        'state': mbi.State,
        'protect': mbi.Protect,
        'type': mbi.Type,
    }


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


cpdef list enum_process_modules(uintptr_t h_process):
    """Enumerate loaded modules in a process.

    Uses EnumProcessModulesEx with LIST_MODULES_ALL to support
    both 32-bit and 64-bit target processes from any host bitness.
    Falls back to EnumProcessModules if Ex variant is unavailable.

    Returns list of dicts with: handle, base_address.
    Raises OSError on failure.
    """
    cdef HMODULE[1024] modules
    cdef DWORD cb_needed = 0
    cdef BOOL result = EnumProcessModulesEx(
        <HANDLE>h_process,
        modules,
        sizeof(modules),
        &cb_needed,
        3)  # LIST_MODULES_ALL

    if result == 0:
        # Fallback to non-Ex version
        result = EnumProcessModules(
            <HANDLE>h_process,
            modules,
            sizeof(modules),
            &cb_needed)

    if result == 0:
        # Fallback: try Toolhelp32 (works across WoW64 boundary)
        # Note: caller must provide pid for Toolhelp fallback
        # For now, just raise the original error
        raise OSError(GetLastError(), "EnumProcessModules failed")

    cdef int count = cb_needed // sizeof(HANDLE)
    cdef list out = []
    cdef int i
    for i in range(count):
        out.append({
            'handle': <uint64_t>modules[i],
            'base_address': <uint64_t>modules[i],
        })

    return out


cpdef list enum_process_modules_toolhelp(uintptr_t h_process, int pid):
    """Enumerate loaded modules using Toolhelp32 snapshot.

    Works across WoW64 boundaries (64-bit host → 32-bit target).
    Falls back to this method when EnumProcessModules fails.

    Returns list of dicts with: handle, base_address, name.
    Raises OSError on failure.
    """
    cdef HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32, <DWORD>pid)
    if snap == <HANDLE><void*>(-1):  # INVALID_HANDLE_VALUE
        raise OSError(GetLastError(), "CreateToolhelp32Snapshot failed")

    cdef MODULEENTRY32 me
    me.dwSize = sizeof(MODULEENTRY32)
    cdef list out = []

    if Module32First(snap, &me):
        out.append({
            'handle': <uint64_t>me.hModule,
            'base_address': <uint64_t><uintptr_t>me.modBaseAddr,
            'name': me.szModule[:].decode('ascii', errors='replace'),
        })
        while Module32Next(snap, &me):
            out.append({
                'handle': <uint64_t>me.hModule,
                'base_address': <uint64_t><uintptr_t>me.modBaseAddr,
                'name': me.szModule[:].decode('ascii', errors='replace'),
            })

    CloseHandle(snap)
    return out


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

    return filename[:len].decode('utf-8', errors='replace')


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
