"""ModuleResolver — enumerate modules and resolve filenames."""

from .. import _pydbg
from ..exceptions import MemError


class ModuleResolver:
    """Resolves module information for the debugged process."""

    def __init__(self, session):
        self._s = session

    def enumerate(self):
        try:
            return _pydbg.enum_process_modules(self._s.process_handle)
        except OSError as e:
            raise MemError(f"EnumProcessModules: {e}")

    def get_filename(self, h_module):
        try:
            return _pydbg.get_module_file_name_ex(self._s.process_handle, h_module)
        except OSError as e:
            raise MemError(f"GetModuleFileNameEx: {e}")
