# _symbol.pxi — dbghelp.dll symbol resolution wrappers

from libc.stdlib cimport malloc, free
from libc.string cimport memset
from _win32types cimport (
    HANDLE, DWORD, BOOL, LPVOID, LPCSTR,
    SYMBOL_INFOW, MAX_SYM_NAME,
    SymInitializeW, SymCleanup, SymFromNameW, SymFromAddrW,
    SymLoadModuleExW, SymSetOptions, SymGetOptions,
    SYMOPT_UNDNAME, SYMOPT_DEFERRED_LOADS,
    GetLastError, CloseHandle,
)

cpdef void sym_initialize(unsigned long long h_process, str search_path, int invade):
    """Initialize the symbol handler for a process."""
    cdef bytes sp_bytes = search_path.encode('utf-16-le') if search_path else None
    cdef BOOL result = SymInitializeW(
        <HANDLE><LPVOID>h_process,
        <const unsigned short*>(<char*>sp_bytes) if sp_bytes else NULL,
        <BOOL>invade)
    if result == 0:
        raise OSError(GetLastError(), "SymInitializeW failed")


cpdef void sym_cleanup(unsigned long long h_process):
    """Deallocate all symbol resources for a process."""
    cdef BOOL result = SymCleanup(<HANDLE><LPVOID>h_process)
    if result == 0:
        raise OSError(GetLastError(), "SymCleanup failed")


cpdef dict sym_from_name(unsigned long long h_process, str name):
    """Look up symbol by name. Returns dict with address, size, name."""
    cdef bytes name_bytes = name.encode('utf-16-le')
    cdef unsigned long sym_info_size = sizeof(SYMBOL_INFOW) + MAX_SYM_NAME
    cdef SYMBOL_INFOW* sym = <SYMBOL_INFOW*>malloc(sym_info_size)
    if sym == NULL:
        raise MemoryError("Failed to allocate SYMBOL_INFOW")

    memset(sym, 0, sym_info_size)
    sym.SizeOfStruct = sizeof(SYMBOL_INFOW)
    sym.MaxNameLen = MAX_SYM_NAME

    cdef BOOL result = SymFromNameW(
        <HANDLE><LPVOID>h_process,
        <const unsigned short*>(<char*>name_bytes),
        sym)

    if result == 0:
        free(sym)
        raise OSError(GetLastError(), f"SymFromNameW failed for '{name}'")

    cdef bytes raw = (<char*>sym.Name)[:sym.NameLen * 2]
    cdef str sym_name = raw.decode('utf-16-le')
    cdef dict out = {
        'address': <unsigned long long>sym.Address,
        'size': sym.Size,
        'name': sym_name,
    }
    free(sym)
    return out


cpdef dict sym_from_addr(unsigned long long h_process, unsigned long long address):
    """Look up symbol by address. Returns dict with address, displacement, name."""
    cdef unsigned long sym_info_size = sizeof(SYMBOL_INFOW) + MAX_SYM_NAME
    cdef SYMBOL_INFOW* sym = <SYMBOL_INFOW*>malloc(sym_info_size)
    if sym == NULL:
        raise MemoryError("Failed to allocate SYMBOL_INFOW")

    memset(sym, 0, sym_info_size)
    sym.SizeOfStruct = sizeof(SYMBOL_INFOW)
    sym.MaxNameLen = MAX_SYM_NAME

    cdef unsigned long long displacement = 0
    cdef BOOL result = SymFromAddrW(
        <HANDLE><LPVOID>h_process,
        address,
        &displacement,
        sym)

    if result == 0:
        free(sym)
        raise OSError(GetLastError(), f"SymFromAddrW failed for 0x{address:X}")

    cdef bytes raw = (<char*>sym.Name)[:sym.NameLen * 2]
    cdef str sym_name = raw.decode('utf-16-le')
    cdef dict out = {
        'address': <unsigned long long>sym.Address,
        'displacement': <unsigned long long>displacement,
        'name': sym_name,
    }
    free(sym)
    return out


cpdef unsigned long long sym_load_module_ex(unsigned long long h_process,
        unsigned long long h_file, str image_name, str module_name,
        unsigned long long base_of_dll, int dll_size):
    """Load symbol table for a module."""
    cdef bytes img = image_name.encode('utf-16-le') if image_name else None
    cdef bytes mod = module_name.encode('utf-16-le') if module_name else None
    cdef unsigned long long result = SymLoadModuleExW(
        <HANDLE><LPVOID>h_process,
        <HANDLE><LPVOID>h_file,
        <const unsigned short*>(<char*>img) if img else NULL,
        <const unsigned short*>(<char*>mod) if mod else NULL,
        base_of_dll,
        <unsigned long>dll_size,
        NULL,
        0)
    if result == 0:
        raise OSError(GetLastError(), "SymLoadModuleExW failed")
    return result


cpdef int sym_set_options(int options):
    """Set symbol handler options. Returns previous options."""
    return <int>SymSetOptions(<DWORD>options)


cpdef int sym_get_options():
    """Get current symbol handler options."""
    return <int>SymGetOptions()
