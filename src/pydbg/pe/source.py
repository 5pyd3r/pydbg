"""Source layer — random-access byte providers."""

from abc import ABC, abstractmethod


class Source(ABC):
    """Abstract byte source with random access."""

    @abstractmethod
    def read(self, offset: int, size: int) -> bytes:
        """Read bytes at given offset."""


class FileSource(Source):
    """Read PE bytes from a file on disk."""

    def __init__(self, path: str):
        self._path = path
        self._file = open(path, 'rb')

    def read(self, offset: int, size: int) -> bytes:
        self._file.seek(offset)
        return self._file.read(size)

    def close(self):
        self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class BytesSource(Source):
    """Read PE bytes from an in-memory buffer."""

    def __init__(self, data: bytes):
        self._data = data

    def read(self, offset: int, size: int) -> bytes:
        if offset + size > len(self._data):
            raise ValueError(
                f"Read out of bounds: offset={offset}, size={size}, len={len(self._data)}")
        return self._data[offset:offset + size]
