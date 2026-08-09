"""ModuleResolver — enumerate modules and resolve filenames."""

import struct

from .. import _pydbg
from ..exceptions import MemError

# PE IMAGE_FILE_HEADER.Machine -> architecture label.
_MACHINE_TO_ARCH = {0x14C: "x86", 0x8664: "x64"}


class ModuleResolver:
    """Resolves module information for the debugged process."""

    def __init__(self, session):
        self._s = session

    @staticmethod
    def _module_arch(h_proc, base):
        """Determine a module's architecture by reading its PE header machine."""
        try:
            dos = _pydbg.read_process_memory(h_proc, base, 0x40)
            if len(dos) < 0x40 or dos[:2] != b"MZ":
                return "unknown"
            e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
            nt = _pydbg.read_process_memory(h_proc, base + e_lfanew, 6)
            if len(nt) < 6 or nt[:4] != b"PE\x00\x00":
                return "unknown"
            # NT header layout: Signature "PE\0\0" (4 bytes) then
            # IMAGE_FILE_HEADER.Machine (WORD) at offset 4.
            machine = struct.unpack_from("<H", nt, 4)[0]
            return _MACHINE_TO_ARCH.get(machine, "unknown")
        except (OSError, TypeError):
            return "unknown"

    def enumerate(self):
        """Return list of loaded modules with handle, base_address, name, arch.

        Each dict: {'handle': int, 'base_address': int, 'name': str,
                    'arch': 'x86' | 'x64' | 'unknown'}
        'name' is the full filesystem path to the module file. 'arch' is
        derived from the module's PE header machine field, so WOW64 targets
        yield both 32-bit modules ('x86') and 64-bit modules ('x64').
        """
        try:
            modules = _pydbg.enum_process_modules(self._s.process_handle)
        except OSError as e:
            raise MemError(f"EnumProcessModules: {e}")

        # Resolve module names
        h_proc = self._s.process_handle
        for m in modules:
            m['arch'] = self._module_arch(h_proc, m['base_address'])
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
            m['arch'] = self._module_arch(h_process, m['base_address'])
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
