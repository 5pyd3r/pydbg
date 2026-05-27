"""ModuleResolver — enumerate modules and resolve filenames."""

try:
    from ..cython import _memory
except ImportError:
    _memory = None

from ..exceptions import MemError


class ModuleResolver:
    """Resolves module information for the debugged process."""

    def __init__(self, session):
        self._s = session

    def enumerate(self):
        try:
            return _memory.enum_process_modules(self._s.process_handle)
        except OSError as e:
            raise MemError(f"EnumProcessModules: {e}")

    def get_filename(self, h_module):
        try:
            return _memory.get_module_file_name_ex(self._s.process_handle, h_module)
        except OSError as e:
            raise MemError(f"GetModuleFileNameEx: {e}")
