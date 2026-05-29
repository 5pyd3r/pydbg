from ..exceptions import PydbgError

SYMOPT_UNDNAME = 0x2
SYMOPT_DEFERRED_LOADS = 0x4


class SymbolResolver:
    """Symbol resolution via dbghelp.dll."""

    def __init__(self, session):
        self._s = session
        self._initialized = False

    def initialize(self, search_path=None, invade=True):
        try:
            from .. import _pydbg
        except ImportError:
            raise PydbgError("_pydbg extension not available")
        sp = search_path or ""
        _pydbg.sym_initialize(self._s.process_handle, sp, 1 if invade else 0)
        self._initialized = True

    def cleanup(self):
        if not self._initialized:
            return
        try:
            from .. import _pydbg
        except ImportError:
            raise PydbgError("_pydbg extension not available")
        _pydbg.sym_cleanup(self._s.process_handle)
        self._initialized = False

    def from_name(self, name):
        if not self._initialized:
            raise PydbgError("SymbolResolver not initialized. Call initialize() first.")
        try:
            from .. import _pydbg
        except ImportError:
            raise PydbgError("_pydbg extension not available")
        try:
            return _pydbg.sym_from_name(self._s.process_handle, name)
        except OSError as e:
            raise PydbgError(f"SymFromName failed: {e}")

    def from_addr(self, address):
        if not self._initialized:
            raise PydbgError("SymbolResolver not initialized. Call initialize() first.")
        try:
            from .. import _pydbg
        except ImportError:
            raise PydbgError("_pydbg extension not available")
        try:
            return _pydbg.sym_from_addr(self._s.process_handle, address)
        except OSError as e:
            raise PydbgError(f"SymFromAddr failed: {e}")

    def load_module(self, image_name, base_of_dll, dll_size=0):
        if not self._initialized:
            raise PydbgError("SymbolResolver not initialized. Call initialize() first.")
        try:
            from .. import _pydbg
        except ImportError:
            raise PydbgError("_pydbg extension not available")
        try:
            return _pydbg.sym_load_module_ex(
                self._s.process_handle, 0, image_name, image_name,
                base_of_dll, dll_size)
        except OSError as e:
            raise PydbgError(f"SymLoadModuleEx failed: {e}")

    def set_options(self, options):
        try:
            from .. import _pydbg
        except ImportError:
            raise PydbgError("_pydbg extension not available")
        return _pydbg.sym_set_options(options)
