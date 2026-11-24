"""Source layer — random-access byte providers."""

import os
from abc import ABC, abstractmethod


class Source(ABC):
    """Abstract byte source with random access.

    Implementations must raise — OSError when the underlying access failed,
    ValueError when the range is out of bounds or otherwise unavailable —
    rather than return a short slice; try_read turns either into the None that
    callers in pe/ actually test for. A source over process memory belongs in
    the ValueError group too: an uncommitted page and a range past the end are
    both just "not available" to the walkers here. A short slice is the one
    wrong answer, because it is indistinguishable from real data at the call
    site.

    `path` is where the bytes came from when they came from a file, and None
    for a memory buffer. It is what lets `PE` hand a consumer the image path
    that a sibling-PDB lookup needs.
    """

    path = None

    @abstractmethod
    def read(self, offset: int, size: int) -> bytes:
        """Read bytes at given offset."""

    def try_read(self, offset: int, size: int) -> bytes | None:
        """Read, or None when the range is not fully available.

        Every walk over a data directory treats an unavailable range as
        "nothing more here", so this makes a truncated directory stop the walk
        rather than abort the whole parse, which is the normal case in reverse
        engineering (packed images, dumps, size fields that lie).

        The length check is still here even though the sources now agree on
        raising: a subclass is free to be lenient, and this is the one place
        that decides what leniency means to the pe/ callers.
        """
        try:
            data = self.read(offset, size)
        except (ValueError, OSError):
            return None
        return data if len(data) == size else None


class FileSource(Source):
    """Read PE bytes from a file on disk."""

    def __init__(self, path: str):
        self._path = os.fspath(path)
        self._file = open(self._path, 'rb')

    @property
    def path(self):
        """The file this source reads."""
        return self._path

    def read(self, offset: int, size: int) -> bytes:
        """Read bytes at 'offset', raising ValueError for a short range.

        A file past its end used to come back as a short slice, which reads
        like data: a caller that did not check len() got a truncated structure
        with no indication anything was wrong. BytesSource has always raised
        here, so the two sources disagreed about what a failed read looks like
        and only try_read papered over it. Both raise now.
        """
        self._file.seek(offset)
        data = self._file.read(size)
        if len(data) != size:
            raise ValueError(
                f"Read out of bounds: offset={offset}, size={size}, "
                f"read={len(data)} from {self._path}")
        return data

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
