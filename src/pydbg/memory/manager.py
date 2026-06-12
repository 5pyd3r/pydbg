"""MemoryManager — read/write/query/protect process memory."""

from .. import _pydbg
from ..exceptions import MemError


class MemoryManager:
    """Manages process memory operations."""

    def __init__(self, session):
        self._s = session

    def read(self, addr, size):
        try:
            return _pydbg.read_process_memory(self._s.process_handle, addr, size)
        except OSError as e:
            raise MemError(f"ReadProcessMemory at 0x{addr:X}: {e}")

    def write(self, addr, data):
        try:
            return _pydbg.write_process_memory(self._s.process_handle, addr, data)
        except OSError as e:
            raise MemError(f"WriteProcessMemory at 0x{addr:X}: {e}")

    def query(self, addr):
        try:
            return _pydbg.virtual_query_ex(self._s.process_handle, addr)
        except OSError as e:
            raise MemError(f"VirtualQueryEx at 0x{addr:X}: {e}")

    def protect(self, addr, size, protect):
        try:
            return _pydbg.virtual_protect_ex(
                self._s.process_handle, addr, size, protect
            )
        except OSError as e:
            raise MemError(f"VirtualProtectEx at 0x{addr:X}: {e}")

    # ── handle variants for child process support ──

    def read_handle(self, h_process, addr, size):
        try:
            return _pydbg.read_process_memory(h_process, addr, size)
        except OSError as e:
            raise MemError(f"ReadProcessMemory at 0x{addr:X}: {e}")

    def write_handle(self, h_process, addr, data):
        try:
            return _pydbg.write_process_memory(h_process, addr, data)
        except OSError as e:
            raise MemError(f"WriteProcessMemory at 0x{addr:X}: {e}")

    def query_handle(self, h_process, addr):
        try:
            return _pydbg.virtual_query_ex(h_process, addr)
        except OSError as e:
            raise MemError(f"VirtualQueryEx at 0x{addr:X}: {e}")

    def protect_handle(self, h_process, addr, size, protect):
        try:
            return _pydbg.virtual_protect_ex(h_process, addr, size, protect)
        except OSError as e:
            raise MemError(f"VirtualProtectEx at 0x{addr:X}: {e}")
