"""ProcessSource — a live module presented as a pe.Source.

The piece that lets a running process be parsed by the same code as a file:
pair this with LoadedView and every RVA resolves as a direct offset into the
module, which is exactly what a Source positioned at the module base means.

An unreadable page is not a parse failure. Live modules routinely have holes —
an uncommitted page, a guard page, a packed image's stub — and analysis is
expected to degrade to the parts it can read.
"""

from ..exceptions import PydbgError
from ..pe.source import Source


class ProcessSource(Source):
    """Read a target process's memory as though it were a file.

    Offsets are relative to the module base, so this is only meaningful
    together with LoadedView; a FileView would translate RVAs through section
    headers and read the wrong bytes.
    """

    def __init__(self, session, base_address, size=None, reader=None):
        self.session = session
        self.base_address = base_address
        self.size = size
        self._reader = reader
        if self._reader is None:
            from ..memory.manager import MemoryManager
            self._reader = MemoryManager(session).read

    def read(self, offset, size):
        """Bytes at 'offset' from the module base.

        An unavailable range is reported as ValueError, the Source contract:
        pe.Source.try_read then answers None and a directory walk stops where
        the data stops instead of aborting the parse. MemoryManager.read raises
        MemError (a PydbgError) for a page that is not committed, so it is
        translated here — in a live module a hole means "no data at this
        address", not "the analysis failed".

        OSError is left alone: try_read already handles it, and it stays a
        distinct signal when a caller bypasses try_read.
        """
        if self.size is not None and offset >= self.size:
            raise ValueError(
                f"Read past the end of the module: offset={offset:#x}")
        try:
            return self._reader(self.base_address + offset, size)
        except PydbgError as exc:
            raise ValueError(str(exc)) from exc

    def __repr__(self):
        return (f"ProcessSource(base={self.base_address:#x}, "
                f"size={self.size}, pid={getattr(self.session, 'pid', None)})")
