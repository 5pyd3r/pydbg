"""ModuleResolver — enumerate modules and resolve filenames."""

from .. import _pydbg
from ..exceptions import MemError


class ModuleResolver:
    """Resolves module information for the debugged process."""

    def __init__(self, session):
        self._s = session

    def enumerate(self):
        """Return list of loaded modules with handle, base_address, and name.

        Each dict: {'handle': int, 'base_address': int, 'name': str}
        'name' is the full filesystem path to the module file.
        """
        try:
            modules = _pydbg.enum_process_modules(self._s.process_handle)
        except OSError as e:
            raise MemError(f"EnumProcessModules: {e}")

        # Resolve module names
        h_proc = self._s.process_handle
        for m in modules:
            try:
                m['name'] = _pydbg.get_module_file_name_ex(h_proc, m['handle'])
            except OSError:
                m['name'] = ''
        return modules

    def enumerate_handle(self, h_process):
        """Same as enumerate() but with explicit process handle."""
        try:
            modules = _pydbg.enum_process_modules(h_process)
        except OSError as e:
            raise MemError(f"EnumProcessModules: {e}")

        for m in modules:
            try:
                m['name'] = _pydbg.get_module_file_name_ex(h_process, m['handle'])
            except OSError:
                m['name'] = ''
        return modules

    def get_filename(self, h_module):
        """Resolve a module handle to its filesystem path."""
        try:
            return _pydbg.get_module_file_name_ex(self._s.process_handle, h_module)
        except OSError as e:
            raise MemError(f"GetModuleFileNameEx: {e}")

    def find_module(self, name):
        """Find a module by name (case-insensitive basename match).

        Args:
            name: Module basename, e.g. 'kernel32.dll'

        Returns:
            dict with handle/base_address/name, or None if not found.
        """
        name_lower = name.lower()
        for m in self.enumerate():
            basename = m.get('name', '').split('\\')[-1].lower()
            if basename == name_lower:
                return m
        return None
