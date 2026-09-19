"""MemoryManager — read/write/query/protect process memory."""

from dataclasses import dataclass, field

from .. import _pydbg
from ..exceptions import MemError

# VirtualQueryEx state / page constants, used by the tolerant read path.
_MEM_COMMIT = 0x1000
_PAGE_SIZE = 0x1000


@dataclass
class MemoryRead:
    """Result of a tolerant memory read.

    'data' is always 'size' bytes long: readable spans hold what the target
    returned, unreadable spans are zero-filled and listed in 'gaps'. A caller
    rebuilding an image wants 'data' plus 'complete'; one that only needs the
    bytes that exist can ignore the rest. Raising instead would discard the
    successfully-read prefix, which is the whole reason this exists.
    """

    address: int
    size: int
    data: bytes
    # (address, size, win32_error) per unreadable span, ascending.
    gaps: list = field(default_factory=list)

    @property
    def complete(self):
        """True when every requested byte was read."""
        return not self.gaps

    @property
    def readable_bytes(self):
        """How many of the requested bytes were actually read."""
        return self.size - sum(size for _, size, _ in self.gaps)


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

    # ── region enumeration and tolerant reads ──

    def regions_handle(self, h_process, start=0, max_addr=0):
        """Enumerate the target's memory regions via VirtualQueryEx.

        Returns a list of region dicts (base_address, allocation_base,
        allocation_protect, region_size, state, protect, type), ascending.
        Unlike query_handle this walks the whole chain, and reaching the end
        of the address space is not an error.
        """
        return _pydbg.virtual_query_all(h_process, start, max_addr)

    def read_safe_handle(self, h_process, addr, size):
        """Read [addr, addr+size) without losing the readable parts.

        read() raises on the first unreadable page and discards what it already
        read, so callers dumping memory or rebuilding a PE had to hand-roll a
        page-by-page fallback. This walks regions instead, keeps every byte the
        target would give up, and reports the rest as gaps.

        Returns a MemoryRead; never raises for unreadable memory.
        """
        if size <= 0:
            return MemoryRead(addr, size, b"", [])

        end = addr + size
        buf = bytearray(size)
        gaps = []
        cursor = addr

        while cursor < end:
            try:
                region = _pydbg.virtual_query_ex(h_process, cursor)
            except OSError as e:
                gaps.append((cursor, end - cursor, getattr(e, "errno", 0) or 0))
                break

            base = region["base_address"]
            rsize = region["region_size"]
            if rsize <= 0:
                gaps.append((cursor, end - cursor, 0))
                break
            region_end = base + rsize

            stop = min(region_end, end)
            if region["state"] != _MEM_COMMIT:
                # Free or merely reserved: nothing to read, and asking would
                # just produce ERROR_PARTIAL_COPY.
                gaps.append((cursor, stop - cursor, 0))
            else:
                self._read_span(h_process, cursor, stop, buf, addr, gaps)

            if region_end <= cursor:  # defensive: never loop without progress
                break
            cursor = min(region_end, end)

        return MemoryRead(addr, size, bytes(buf), gaps)

    def _read_span(self, h_process, start, stop, buf, origin, gaps):
        """Fill buf[start-origin : stop-origin], degrading to pages on failure."""
        size = stop - start
        data, nread, err = _pydbg.read_process_memory_partial(
            h_process, start, size)
        if nread:
            buf[start - origin:start - origin + nread] = data
        if err == 0 and nread == size:
            return

        # The whole span did not transfer. Retry page by page from where the
        # partial read stopped, so one bad page costs one page rather than the
        # rest of the region.
        cursor = start + nread
        while cursor < stop:
            chunk = min(_PAGE_SIZE, stop - cursor)
            data, nread, err = _pydbg.read_process_memory_partial(
                h_process, cursor, chunk)
            if nread:
                buf[cursor - origin:cursor - origin + nread] = data
            if nread < chunk:
                gaps.append((cursor + nread, chunk - nread, err))
            cursor += chunk
