"""dbghelp sessions for symbols and types, offline (spec §10.2, §10.3).

dbghelp can read a PDB without a debuggee, but only if it is handed the image:
the image names the PDB and its preferred base, and the PDB's directory is the
symbol search path. This module owns that session, the ctypes bindings, the
translation from SYMBOL_INFOW records to `PdbSymbol`, and the TI_* type reader
the layouts are built from. Both readers share one session and one lock because
that is what dbghelp requires; `types.py` decides what a type *means*, this
module only asks the questions.

Four measured properties shape the code (research/pdb-format.md §B5-B9):

- dbghelp is process-wide and single threaded, so every call — including the
  enumeration callback's — runs under one module-level `RLock`.
- `SymLoadModuleExW` returning 0 is not a failure: it also means "already
  loaded". The session remembers what it loaded and resolves the base instead.
- An exception must never cross back into C: the callback captures it, stops
  the enumeration by returning FALSE, and the Python side raises after.
- A type stream must be opened before it can be queried: SymGetTypeInfo answers
  E_INVALIDARG for ids that are valid afterwards, and SymGetTypeFromNameW
  returns a bogus index, until SymEnumTypesW has run. `TypeReader` therefore
  primes through the session before every query.

`symbols()` returning an empty tuple is not evidence of success — dbghelp
returns TRUE for an empty or fully mismatched enumeration. The caller
(`analysis`) records "pdb: no symbols" when that happens; this layer does not
turn emptiness into an error. The same holds for an empty type stream.
"""

import atexit
import ctypes
import os
import struct
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

# `IMAGEHLP_SYMBOL_TYPE_INFO` values this package calls, measured in
# research/pdb-format.md §B8. pInfo is the pointer type each query writes:
# DWORD for tags/ids/offsets/counts, ULONG64 for lengths, WCHAR** for names,
# and the raw TI_FINDCHILDREN_PARAMS buffer for a child array.
TI_GET_SYMTAG = 0
TI_GET_SYMNAME = 1
TI_GET_LENGTH = 2
TI_GET_TYPE = 3
TI_GET_BASETYPE = 5
TI_FINDCHILDREN = 7
TI_GET_OFFSET = 10
TI_GET_COUNT = 12
TI_GET_CHILDRENCOUNT = 13
TI_GET_BITPOSITION = 14

# SymGetTypeFromNameW fills a SYMBOL_INFOW whose name is copied into the
# caller's buffer; 1 KiB is far beyond any measured type name.
MAX_TYPE_NAME = 0x400


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


def _type_record_callback(records, failures):
    """The `SymEnumTypesW` callback: one (TypeIndex, Tag) per enumerated type.

    Same exception discipline as `_record_callback`: an exception must not cross
    into C, so it is captured and the enumeration stops. Only the two fields the
    type layer needs are copied out; names are read later through TI_GET_SYMNAME
    (which allocates) rather than borrowed from the callback's buffer.
    """

    def callback(info, _size, _context):
        try:
            symbol = info.contents
            records.append((symbol.TypeIndex, symbol.Tag))
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
        dll.SymEnumTypesW.argtypes = [
            ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p,
            ctypes.c_void_p]
        dll.SymEnumTypesW.restype = ctypes.c_int
        dll.SymGetTypeFromNameW.argtypes = [
            ctypes.c_void_p, ctypes.c_uint64, ctypes.c_wchar_p,
            ctypes.POINTER(SYMBOL_INFOW)]
        dll.SymGetTypeFromNameW.restype = ctypes.c_int
        dll.SymGetTypeInfo.argtypes = [
            ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_int,
            ctypes.c_void_p]
        dll.SymGetTypeInfo.restype = ctypes.c_int
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

    def enum_types(self, handle, base, callback):
        """Enumerate one module's types through 'callback'.

        This is also what opens the module's type stream for SymGetTypeInfo and
        SymGetTypeFromNameW (see `TypeReader`), so callers that only want the
        stream opened still go through here.
        """
        callback_type = ctypes.WINFUNCTYPE(
            ctypes.c_int, ctypes.POINTER(SYMBOL_INFOW), ctypes.c_uint32,
            ctypes.c_void_p)
        procedure = callback_type(callback)
        return bool(self._load().SymEnumTypesW(
            handle, base, ctypes.cast(procedure, ctypes.c_void_p), None))

    def get_type_info(self, handle, base, type_id, kind, info):
        """One `SymGetTypeInfo` call; 'info' is the pInfo buffer for 'kind'."""
        return bool(self._load().SymGetTypeInfo(handle, base, type_id, kind,
                                                info))

    def type_from_name(self, handle, base, name):
        """The type id `SymGetTypeFromNameW` assigns to 'name', or None.

        Requires the type stream to be open first: on a fresh module this call
        was measured to answer with a bogus index instead of failing (see
        `TypeReader.find_type`).
        """
        buffer = ctypes.create_string_buffer(
            ctypes.sizeof(SYMBOL_INFOW) + MAX_TYPE_NAME)
        symbol = SYMBOL_INFOW.from_buffer(buffer)
        symbol.SizeOfStruct = ctypes.sizeof(SYMBOL_INFOW)
        symbol.MaxNameLen = MAX_TYPE_NAME
        if not self._load().SymGetTypeFromNameW(handle, base, name,
                                                ctypes.byref(symbol)):
            return None
        return symbol.TypeIndex

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
        self.types_loaded = {}
        self._open()

    def _open(self):
        """Start a fresh SymInitializeW session for `self.search_path`."""
        self.handle = self.api.current_process()
        self.api.set_options(SYM_SET_OPTIONS)
        if not self.api.initialize(self.handle, self.search_path):
            raise PdbError("dbghelp session could not be initialized "
                           f"(error {ctypes.get_last_error()})")

    def restart(self):
        """Drop every loaded module and start a fresh session.

        dbghelp holds at most one module per address. Unloading a module by
        hand would leave the other Pdb's cache claiming a module that is gone,
        so a collision resets the session and lets each reader reload what it
        asks for. Two images that share a preferred base therefore alternate
        rather than coexist; their already-returned results stay valid.
        """
        self.api.cleanup(self.handle)
        self.loaded.clear()
        self.types_loaded.clear()
        self._open()

    def close(self):
        """End the session; a failure is not worth raising during teardown."""
        self.api.cleanup(self.handle)
        self.loaded.clear()
        self.types_loaded.clear()

    def load(self, image_path, requested_base, preferred_base):
        """Load 'image_path' once and return the base its symbols use.

        `SymLoadModuleExW` returns 0 both on failure and when the module is
        already loaded, so 0 is resolved with SymGetModuleBase64 instead of
        being reported as an error (research/pdb-format.md §B6).

        A *different* image already loaded at the address this one needs cannot
        be loaded alongside it — dbghelp would silently answer with the first
        module's symbols — so the session is restarted first.
        """
        key = (os.path.normcase(os.path.abspath(image_path)), requested_base)
        loaded = self.loaded.get(key)
        if loaded:
            return loaded
        target = requested_base or preferred_base
        occupied = any(other_base == target and other_key != key
                       for other_key, other_base in self.loaded.items())
        if occupied:
            self.restart()
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

    def type_records(self, base):
        """Every (TypeIndex, Tag) the module loaded at 'base' describes.

        This call has a side effect the type layer depends on: measured,
        SymGetTypeInfo answers E_INVALIDARG for a valid type id until
        SymEnumTypesW has run, and SymGetTypeFromNameW instead returns a bogus
        index (1 for a type whose real index is 227). Enumerating therefore
        primes the stream, and the result is cached per loaded module so later
        reads do not pay for it again.
        """
        records = self.types_loaded.get(base)
        if records is not None:
            return records
        collected = []
        failures = []
        ok = self.api.enum_types(self.handle, base,
                                 _type_record_callback(collected, failures))
        if failures:
            error = failures[0]
            raise PdbError(
                f"dbghelp type enumeration failed: {error}") from error
        if not ok:
            raise PdbError("dbghelp type enumeration failed "
                           f"(error {ctypes.get_last_error()})")
        records = tuple(collected)
        self.types_loaded[base] = records
        return records


class TypeReader:
    """The TI_* queries for one module, used only inside `read_types`.

    A TypeIndex is meaningful only for the session that produced it, so this
    object is handed to an action for the duration of one call and never kept.
    Callers must already hold `_lock`; `read_types` guarantees that.

    Every query opens the module's type stream first (`types()`): measured,
    SymGetTypeInfo answers E_INVALIDARG for ids that are valid afterwards until
    SymEnumTypesW has run, so a fresh session cannot answer even a raw id it was
    handed. The first call pays for the enumeration; later ones hit the cache.
    """

    def __init__(self, session, base):
        self._session = session
        self._base = base

    def _value(self, type_id, kind, fmt, size):
        """One scalar `SymGetTypeInfo` query, or None when it fails."""
        self.types()
        buffer = ctypes.create_string_buffer(size)
        if not self._session.api.get_type_info(
                self._session.handle, self._base, type_id, kind, buffer):
            return None
        return struct.unpack_from(fmt, buffer.raw)[0]

    def sym_tag(self, type_id):
        """`TI_GET_SYMTAG`: the SymTag kind of 'type_id', or None."""
        return self._value(type_id, TI_GET_SYMTAG, "<I", 4)

    def length(self, type_id):
        """`TI_GET_LENGTH`: bytes for a type, bits for a bitfield *member*."""
        return self._value(type_id, TI_GET_LENGTH, "<Q", 8)

    def base_type(self, type_id):
        """`TI_GET_BASETYPE`: the cvconst BasicType number, or None."""
        return self._value(type_id, TI_GET_BASETYPE, "<I", 4)

    def type_of(self, type_id):
        """`TI_GET_TYPE`: the pointed-to, element, underlying or member type."""
        return self._value(type_id, TI_GET_TYPE, "<I", 4)

    def count(self, type_id):
        """`TI_GET_COUNT`: an array's element count, or None."""
        return self._value(type_id, TI_GET_COUNT, "<I", 4)

    def offset(self, member_id):
        """`TI_GET_OFFSET`: a member's byte offset, or None."""
        return self._value(member_id, TI_GET_OFFSET, "<I", 4)

    def bit_position(self, member_id):
        """`TI_GET_BITPOSITION`: bit offset inside the storage unit, or None.

        A plain member answers FALSE, which is how a bitfield is recognised.
        """
        return self._value(member_id, TI_GET_BITPOSITION, "<I", 4)

    def sym_name(self, type_id):
        """`TI_GET_SYMNAME`: the type or member name, or None.

        dbghelp allocates the string with LocalAlloc; it is copied into Python
        and freed before returning, on both the success and failure paths.
        """
        self.types()
        pointer = ctypes.c_void_p()
        if not self._session.api.get_type_info(
                self._session.handle, self._base, type_id, TI_GET_SYMNAME,
                ctypes.byref(pointer)):
            return None
        if not pointer:
            return None
        try:
            return ctypes.wstring_at(pointer)
        finally:
            local_free(pointer)

    def children(self, type_id):
        """The child ids: () for no children, None when a query failed."""
        count = self._value(type_id, TI_GET_CHILDRENCOUNT, "<I", 4)
        if count is None:
            return None
        if not count:
            return ()
        # TI_FINDCHILDREN_PARAMS declares ChildId[1] but dbghelp writes Count
        # entries; indexing the ctypes array past [0] would read out of bounds,
        # so the ids are unpacked from the raw buffer (research §B8 rule 4).
        raw = ctypes.create_string_buffer(8 + 4 * count)
        struct.pack_into("<II", raw, 0, count, 0)
        if not self._session.api.get_type_info(
                self._session.handle, self._base, type_id, TI_FINDCHILDREN,
                raw):
            return None
        return tuple(struct.unpack_from("<I", raw, 8 + 4 * index)[0]
                     for index in range(count))

    def types(self):
        """Every (TypeIndex, SymTag) in the module's type stream."""
        return self._session.type_records(self._base)

    def find_type(self, name):
        """`SymGetTypeFromNameW`: the TypeIndex for 'name', or None.

        The stream is opened first; on a fresh module the call returns index 1
        for a name whose real index is 227 (measured), so it is only usable
        after `types()`.
        """
        self.types()
        return self._session.api.type_from_name(self._session.handle,
                                                self._base, name)


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


def _loadable_image(image_path, what):
    """The parsed image for a read, or the PdbError explaining why there is none.

    Both readers (symbols and types) need the image: dbghelp locates the PDB
    through it, and the image supplies the preferred base the module is loaded
    at. 'what' names the read in the message ("symbols" or "types").
    """
    if image_path is None:
        raise PdbError(
            f"image path is required to read PDB {what}; construct "
            "Pdb(path, image_path=...) or use find() on an image that has a "
            "path")
    image_path = os.fspath(image_path)
    if not os.path.isfile(image_path):
        raise PdbError(f"image for PDB {what} does not exist: {image_path}")
    try:
        return PE.from_file(image_path), image_path
    except Exception as exc:          # a user-supplied file is a boundary
        raise PdbError(f"image for PDB {what} could not be read: "
                       f"{image_path}: {exc}") from exc


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
    pdb_path = os.fspath(pdb_path)
    pe, image_path = _loadable_image(image_path, "symbols")
    image_size = pe.optional_header.size_of_image
    search_path = os.path.dirname(os.path.abspath(pdb_path))

    with _lock:
        session = _session_for(search_path)
        loaded_base = session.load(image_path, image_base or 0, pe.image_base)
        records = session.enumerate(loaded_base)
        return build_symbols(records, loaded_base, image_size)


def read_types(pdb_path, image_path, image_base, action):
    """Run 'action(reader)' against the PDB's type stream, under the lock.

    The same session and the same search-path rule as `symbols`: dbghelp is
    process-wide and single threaded, so the action — all of whose dbghelp calls
    go through the `TypeReader` it is given — runs inside the lock. The reader
    is valid only for the duration of the call: TypeIndex values are session
    scoped and must not escape.

    Returns whatever 'action' returns.

    Raises:
        PdbError: no image path was supplied, the image cannot be read, or
            dbghelp failed to load the module or enumerate its types.
    """
    pdb_path = os.fspath(pdb_path)
    pe, image_path = _loadable_image(image_path, "types")
    search_path = os.path.dirname(os.path.abspath(pdb_path))

    with _lock:
        session = _session_for(search_path)
        loaded_base = session.load(image_path, image_base or 0, pe.image_base)
        return action(TypeReader(session, loaded_base))
