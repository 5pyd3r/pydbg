"""ProcessSource — a live module presented as a pe.Source.

The piece that lets a running process be parsed by the same code as a file:
pair this with LoadedView and every RVA resolves as a direct offset into the
module, which is exactly what a Source positioned at the module base means.
"""

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

        Reads through the strict memory path and lets its error out: a Source
        that quietly returned short reads would make an uncommitted page look
        like the end of the file. pe.Source.try_read turns the failure into the
        None that callers test for.
        """
        if self.size is not None and offset >= self.size:
            raise ValueError(
                f"Read past the end of the module: offset={offset:#x}")
        return self._reader(self.base_address + offset, size)

    def read_at_va(self, va, size):
        """Bytes at an absolute address inside the module."""
        return self.read(va - self.base_address, size)

    def __repr__(self):
        return (f"ProcessSource(base={self.base_address:#x}, "
                f"size={self.size}, pid={getattr(self.session, 'pid', None)})")
