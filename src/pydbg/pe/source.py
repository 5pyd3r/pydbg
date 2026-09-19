"""Source layer — random-access byte providers."""

from abc import ABC, abstractmethod


class Source(ABC):
    """Abstract byte source with random access.

    Implementations must raise OSError (or ValueError for an out-of-bounds
    in-memory buffer) when a range cannot be read; try_read turns either into
    the None that callers in pe/ actually test for.
    """

    @abstractmethod
    def read(self, offset: int, size: int) -> bytes:
        """Read bytes at given offset."""

    def try_read(self, offset: int, size: int) -> bytes | None:
        """Read, or None when the range is not fully available.

        The concrete sources disagree on their own: BytesSource raises
        ValueError past the end, FileSource returns a short slice. Every walk
        over a data directory treats both as "nothing more here", so this
        normalises them — and makes a truncated directory stop the walk rather
        than abort the whole parse, which is the normal case in reverse
        engineering (packed images, dumps, size fields that lie).
        """
        try:
            data = self.read(offset, size)
        except (ValueError, OSError):
            return None
        return data if len(data) == size else None


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
