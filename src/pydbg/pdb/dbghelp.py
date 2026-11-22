"""Symbol enumeration through an offline dbghelp session (spec §10.2, §10.3).

dbghelp can read a PDB without a debuggee, but only if it is handed the image:
the image names the PDB and its preferred base, and the PDB's directory is the
symbol search path. This module owns that session, the ctypes bindings, and the
translation from SYMBOL_INFOW records to `PdbSymbol`.

Three measured properties shape the code (research/pdb-format.md §B5-B9):

- dbghelp is process-wide and single threaded, so every call — including the
  enumeration callback's — runs under one module-level `RLock`.
- `SymLoadModuleExW` returning 0 is not a failure: it also means "already
  loaded". The session remembers what it loaded and resolves the base instead.
- An exception must never cross back into C: the callback captures it, stops
  the enumeration by returning FALSE, and the Python side raises after.

`symbols()` returning an empty tuple is not evidence of success — dbghelp
returns TRUE for an empty or fully mismatched enumeration. The caller
(`analysis`) records "pdb: no symbols" when that happens; this layer does not
turn emptiness into an error.
"""

import atexit
import ctypes
import os
import threading
from dataclasses import dataclass

from ..pe import PE
from .errors import PdbError

# Measured with dbghelp.dll 10.0.26100 (research/pdb-format.md §B5): a fresh
# process starts with options 0x0, so the two safe defaults are set explicitly.
# SYMOPT_UNDNAME (0x2) is deliberately not among them; see `demangle_name`.
SYM_SET_OPTIONS = 0x204          # DEFERRED_LOADS | FAIL_CRITICAL_ERRORS
LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800

# `UnDecorateSymbolName` flags: NAME_ONLY strips the decoration but keeps the
# qualified C++ name (`?v@Derived@@UEAAHXZ` -> `Derived::v`). COMPLETE would
# return a whole declaration, which is not a name a NameTable can use.
UNDNAME_NAME_ONLY = 0x1000
UNDECORATE_MAX = 0x1000

# cvconst.h / dbghelp.h `SymTagEnum`, measured over 3762 symbols in §B7.
SYMTAG_FUNCTION = 5
SYMTAG_DATA = 7
SYMTAG_PUBLIC = 10
KIND_BY_TAG = {
    SYMTAG_FUNCTION: "function",
    SYMTAG_DATA: "data",
    SYMTAG_PUBLIC: "public",
}
KIND_UNKNOWN = "unknown"

# offsetof(SYMBOL_INFOW, Name). The flexible array member is not part of the
# structure size, and ctypes arrays cannot express "however long the callback
# says", so the name is read with `wstring_at` from this offset.
NAME_OFFSET = 84


@dataclass(frozen=True)
class PdbSymbol:
    """One named address from the PDB.

    `rva` is `Address - LoadedBase`, so it is relative to the image file and
    independent of where (or whether) the module was loaded. `size` is the
    symbol's byte size as recorded — a function's body, a datum's type size.
    `kind` is "function", "data", "public" or "unknown"; `is_public` is true
    only for the Tag=10 aliases dbghelp also reports (polymorphic functions
    appear once as data and once as a public thunk, for example).
    """

    rva: int
    name: str
    size: int
    kind: str
    is_public: bool


class SYMBOL_INFOW(ctypes.Structure):
    """The measured SYMBOL_INFOW layout (88 bytes including Name[1]).

    Mirrors dbghelp.h field for field, including the 4-byte hole after Flags
    that ULONG64 alignment creates. Bytes beyond Name[1] are the name buffer
    dbghelp allocates for the callback; `_record_callback` reads them from
    NAME_OFFSET instead of through this array.
    """

    _fields_ = [
        ("SizeOfStruct", ctypes.c_uint32),
        ("TypeIndex", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint64 * 2),
        ("Index", ctypes.c_uint32),
        ("Size", ctypes.c_uint32),
        ("ModBase", ctypes.c_uint64),
        ("Flags", ctypes.c_uint32),
        ("Value", ctypes.c_uint64),
        ("Address", ctypes.c_uint64),
        ("Register", ctypes.c_uint32),
        ("Scope", ctypes.c_uint32),
        ("Tag", ctypes.c_uint32),
        ("NameLen", ctypes.c_uint32),
        ("MaxNameLen", ctypes.c_uint32),
        ("Name", ctypes.c_wchar * 1),
    ]


def symbol_kind(tag):
    """The `PdbSymbol.kind` for a SYMBOL_INFOW Tag.

    Only the three tags dbghelp enumerates as symbols are named; every other
    value is "unknown" rather than a guess derived from where it appeared.
    """
    return KIND_BY_TAG.get(tag, KIND_UNKNOWN)


def trim_name(text, name_len):
    """'text' cut to the length SYMBOL_INFOW.NameLen describes.

    Measured fact: NameLen includes the terminating NUL (it is wcslen + 1), so
    the usable name is the first `name_len - 1` characters. A non-positive
    length is treated as "no limit" so a malformed record keeps its name.
    """
    if name_len <= 0:
        return text
    return text[:name_len - 1]


def demangle_name(name):
    """'name' with MSVC decoration removed, or 'name' itself when that fails.

    Tag 5/7 names are stored undecorated already; the `?`-prefixed ones are
    public aliases and C++ symbols. NAME_ONLY demangling yields the bare name a
    NameTable can use (`?v@Derived@@UEAAHXZ` -> `Derived::v`), and a failed
    decode keeps the original spelling rather than inventing one.
    """
    if not name.startswith("?"):
        return name
    bare = _undecorate(name)
    return bare or name


def build_symbols(records, loaded_base, image_size):
    """Convert raw enumeration records into the public, deduplicated tuple.

    'records' yields (tag, address, size, text, name_len) in the order dbghelp
    reported them. A record survives only when `Address - loaded_base` lands
    inside the image; a repeated (rva, name) keeps the first record, because
    dbghelp lists the compiland record before the public alias of the same
    address. The result is sorted by (rva, name) so two enumerations of one PDB
    compare equal regardless of callback order.
    """
    symbols = []
    seen = set()
    for tag, address, size, text, name_len in records:
        rva = address - loaded_base
        if not 0 <= rva < image_size:
            continue
        name = demangle_name(trim_name(text, name_len))
        key = (rva, name)
        if key in seen:
            continue
        seen.add(key)
        symbols.append(PdbSymbol(rva, name, size, symbol_kind(tag),
                                 tag == SYMTAG_PUBLIC))
    symbols.sort(key=lambda symbol: (symbol.rva, symbol.name))
    return tuple(symbols)


def _record_callback(records, failures):
    """Build the `SymEnumSymbolsW` callback that appends raw records.

    ctypes swallows an exception raised inside a callback and treats it as
    FALSE, which silently truncates the enumeration. So the callback catches
    everything, records the exception in 'failures', and returns FALSE itself;
    `_Session.enumerate` re-raises it as a PdbError once dbghelp has returned.

    The extraction is deliberately minimal — Tag, Address, Size, name text and
    NameLen. Trimming, demangling and range filtering happen in `build_symbols`
    after the callback, outside the C call.
    """

    def callback(info, _size, _context):
        try:
            symbol = info.contents
            text = ctypes.wstring_at(ctypes.addressof(symbol) + NAME_OFFSET)
            records.append((symbol.Tag, symbol.Address, symbol.Size, text,
                            symbol.NameLen))
        except Exception as exc:      # must not cross the C boundary
            failures.append(exc)
            return False
        return True

    return callback


class _Dbghelp:
    """ctypes prototypes for the dbghelp entry points this package calls.

    Loading is lazy: importing `pydbg.pdb` must not depend on dbghelp.dll, and
    no session exists until a symbol is first asked for. `dbghelp.dll` is
    loaded from System32 by name with LOAD_LIBRARY_SEARCH_SYSTEM32, so neither
    the current directory nor PATH can shadow it.
    """

    def __init__(self):
        self._dll = None
        self._kernel32 = None

    def _load(self):
        if self._dll is not None:
            return self._dll
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.LoadLibraryExW.argtypes = [ctypes.c_wchar_p,
                                            ctypes.c_void_p, ctypes.c_uint32]
        kernel32.LoadLibraryExW.restype = ctypes.c_void_p
        kernel32.GetCurrentProcess.argtypes = []
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        handle = kernel32.LoadLibraryExW("dbghelp.dll", None,
                                         LOAD_LIBRARY_SEARCH_SYSTEM32)
        if not handle:
            raise PdbError("dbghelp.dll could not be loaded from System32 "
                           f"(error {ctypes.get_last_error()})")

        # Python 3.13 refuses a bare integer handle here; an explicit handle is
        # also what makes the loaded module the one these prototypes bind to.
        dll = ctypes.WinDLL("dbghelp.dll", handle=handle, use_last_error=True)
        dll.SymSetOptions.argtypes = [ctypes.c_uint32]
        dll.SymSetOptions.restype = ctypes.c_uint32
        dll.SymInitializeW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                       ctypes.c_int]
        dll.SymInitializeW.restype = ctypes.c_int
        dll.SymCleanup.argtypes = [ctypes.c_void_p]
        dll.SymCleanup.restype = ctypes.c_int
        dll.SymLoadModuleExW.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p,
            ctypes.c_wchar_p, ctypes.c_uint64, ctypes.c_uint32,
            ctypes.c_void_p, ctypes.c_uint32]
        dll.SymLoadModuleExW.restype = ctypes.c_uint64
        dll.SymGetModuleBase64.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
        dll.SymGetModuleBase64.restype = ctypes.c_uint64
        dll.SymEnumSymbolsW.argtypes = [
            ctypes.c_void_p, ctypes.c_uint64, ctypes.c_wchar_p,
            ctypes.c_void_p, ctypes.c_void_p]
        dll.SymEnumSymbolsW.restype = ctypes.c_int
        dll.UnDecorateSymbolName.argtypes = [
            ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32,
            ctypes.c_uint32]
        dll.UnDecorateSymbolName.restype = ctypes.c_uint32
        self._kernel32 = kernel32
        self._dll = dll
        return dll

    def current_process(self):
        self._load()
        return self._kernel32.GetCurrentProcess()

    def set_options(self, options):
        """Set the process-wide options; returns the previous value."""
        return self._load().SymSetOptions(options)

    def initialize(self, handle, search_path):
        return bool(self._load().SymInitializeW(handle, search_path, False))

    def cleanup(self, handle):
        return bool(self._load().SymCleanup(handle))

    def load_module_ex(self, handle, image_path, base):
        """Load one image's symbols; 0 means "loaded already" as well as fail."""
        dll = self._load()
        return dll.SymLoadModuleExW(handle, None, image_path, image_path,
                                    base, 0, None, 0)

    def module_base(self, handle, address):
        return self._load().SymGetModuleBase64(handle, address)

    def enum_symbols(self, handle, base, callback):
        """Enumerate one module's symbols through 'callback'."""
        # WINFUNCTYPE only exists on Windows, so it cannot be built while this
        # module is imported; the callback type lives as long as the call.
        callback_type = ctypes.WINFUNCTYPE(
            ctypes.c_int, ctypes.POINTER(SYMBOL_INFOW), ctypes.c_uint32,
            ctypes.c_void_p)
        procedure = callback_type(callback)
        return bool(self._load().SymEnumSymbolsW(
            handle, base, None, ctypes.cast(procedure, ctypes.c_void_p), None))

    def undecorate(self, name):
        """The NAME_ONLY form of 'name', or None when dbghelp cannot decode it."""
        buffer = ctypes.create_unicode_buffer(UNDECORATE_MAX)
        written = self._load().UnDecorateSymbolName(
            name, buffer, UNDECORATE_MAX, UNDNAME_NAME_ONLY)
        return buffer.value if written else None

    def local_free(self, pointer):
        self._load()
        return self._kernel32.LocalFree(pointer)


_lock = threading.RLock()
_api_instance = None
_session = None
_atexit_registered = False


def _api():
    """The process-wide binding table, created on first use."""
    global _api_instance
    with _lock:
        if _api_instance is None:
            _api_instance = _Dbghelp()
        return _api_instance


def _undecorate(name):
    """NAME_ONLY-decorate through dbghelp; None when it cannot decode."""
    return _api().undecorate(name)


def local_free(pointer):
    """Free a buffer dbghelp allocated with LocalAlloc (P19's TI_GET_SYMNAME).

    `LocalFree` returns NULL on success, so its return value says nothing about
    failure; this helper deliberately does not report it. Passing NULL is a
    no-op, which lets callers free unconditionally.
    """
    if pointer:
        _api().local_free(pointer)


class _Session:
    """One SymInitializeW session for this process, reused by every Pdb.

    dbghelp's options and loaded modules belong to the (process, handle) pair,
    and a fresh SymInitializeW takes milliseconds; the session is therefore
    created once and only restarted when the symbol search path has to change.
    Callers must hold `_lock`; every method here calls into dbghelp.
    """

    def __init__(self, api, search_path):
        self.api = api
        self.search_path = search_path
        self.loaded = {}
        self.handle = api.current_process()
        api.set_options(SYM_SET_OPTIONS)
        if not api.initialize(self.handle, search_path):
            raise PdbError("dbghelp session could not be initialized "
                           f"(error {ctypes.get_last_error()})")

    def close(self):
        """End the session; a failure is not worth raising during teardown."""
        self.api.cleanup(self.handle)
        self.loaded.clear()

    def load(self, image_path, requested_base, preferred_base):
        """Load 'image_path' once and return the base its symbols use.

        `SymLoadModuleExW` returns 0 both on failure and when the module is
        already loaded, so 0 is resolved with SymGetModuleBase64 instead of
        being reported as an error (research/pdb-format.md §B6).
        """
        key = (os.path.normcase(os.path.abspath(image_path)), requested_base)
        loaded = self.loaded.get(key)
        if loaded:
            return loaded
        loaded = self.api.load_module_ex(self.handle, image_path,
                                         requested_base)
        if not loaded:
            loaded = self.api.module_base(
                self.handle, requested_base or preferred_base)
        if not loaded:
            raise PdbError(f"dbghelp could not load image {image_path} "
                           f"(error {ctypes.get_last_error()})")
        self.loaded[key] = loaded
        return loaded

    def enumerate(self, base):
        """Every raw symbol record for the module loaded at 'base'."""
        records = []
        failures = []
        ok = self.api.enum_symbols(self.handle, base,
                                   _record_callback(records, failures))
        if failures:
            error = failures[0]
            raise PdbError(
                f"dbghelp symbol enumeration failed: {error}") from error
        if not ok:
            raise PdbError("dbghelp symbol enumeration failed "
                           f"(error {ctypes.get_last_error()})")
        return records


def _close_session():
    """atexit hook: one SymCleanup per session, at process end."""
    global _session, _atexit_registered
    with _lock:
        if _session is not None:
            _session.close()
            _session = None
        _atexit_registered = False


def _session_for(search_path):
    """The process-wide session, restarted only when its search path changes.

    dbghelp fixes its symbol search path at SymInitializeW. Two PDBs can live
    in two directories, so a changed directory starts a clean session rather
    than relying on SymSetSearchPathW semantics this package never measured.
    Callers must hold `_lock`.
    """
    global _session, _atexit_registered
    if _session is not None and _session.search_path == search_path:
        return _session
    if _session is not None:
        _session.close()
    _session = _Session(_api(), search_path)
    if not _atexit_registered:
        atexit.register(_close_session)
        _atexit_registered = True
    return _session


def symbols(pdb_path, image_path, image_base=None):
    """Every named address in the PDB for 'image_path', sorted and deduplicated.

    'image_path' is required: dbghelp finds the PDB through the image and the
    image supplies both the preferred base and the size that decides which
    addresses are inside it. The PDB's own directory becomes the dbghelp symbol
    search path, because a PDB copied away from the path recorded in the image
    is still the PDB meant for it.

    An empty tuple means dbghelp enumerated nothing, or nothing inside the
    image. dbghelp also returns TRUE when it silently ignored a mismatched PDB,
    so emptiness must not be read as success: the caller records
    "pdb: no symbols" and lets the validation layer be the reason.

    Raises:
        PdbError: no image path was supplied, the image cannot be read, or
            dbghelp failed to initialize, load or enumerate.
    """
    if image_path is None:
        raise PdbError(
            "image path is required to enumerate PDB symbols; construct "
            "Pdb(path, image_path=...) or use find() on an image that has a "
            "path")
    image_path = os.fspath(image_path)
    pdb_path = os.fspath(pdb_path)
    if not os.path.isfile(image_path):
        raise PdbError(f"image for PDB symbols does not exist: {image_path}")
    try:
        pe = PE.from_file(image_path)
    except Exception as exc:          # a user-supplied file is a boundary
        raise PdbError(f"image for PDB symbols could not be read: "
                       f"{image_path}: {exc}") from exc
    image_size = pe.optional_header.size_of_image
    search_path = os.path.dirname(os.path.abspath(pdb_path))

    with _lock:
        session = _session_for(search_path)
        loaded_base = session.load(image_path, image_base or 0, pe.image_base)
        records = session.enumerate(loaded_base)
        return build_symbols(records, loaded_base, image_size)
