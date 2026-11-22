"""Versioned binary event stream for block-level traces (format v1).

The file is the trace: `TraceWriter` and `read_trace` have to be inverses byte
for byte, because every later step — replay, filtering, coverage — believes the
events the reader hands back. Versioning is in the header so a future reader can
refuse a file it does not understand instead of misreading every record.

The timestamp is supplied by the caller. The writer never reads the clock, so a
test can pin `ts` and the same events always produce the same bytes.
"""

import struct
from dataclasses import dataclass

MAGIC = b"PDBGTRC\0"
VERSION = 1

# kind: rva / a / b carry different fields per kind (docs/analysis-coverage.md §8.2)
BLOCK, API, MARK, MEM_READ, MEM_WRITE = 1, 2, 3, 4, 5

_HEADER = struct.Struct("<8sHH")
_RECORD = struct.Struct("<B3xIIQQQ")

HEADER_SIZE = _HEADER.size
RECORD_SIZE = _RECORD.size


@dataclass(frozen=True)
class TraceEvent:
    """One recorded event; `kind` says which fields carry meaning.

    BLOCK: rva is the block start, a is its instruction count.
    API: rva is the return address, a is the hook id.
    MARK: a is the caller's mark.
    MEM_READ / MEM_WRITE: a is the address, b is the size.
    """

    kind: int
    tid: int
    rva: int
    ts: int
    a: int = 0
    b: int = 0


class TraceFormatError(ValueError):
    """A trace file is not format v1, or ends mid-record."""


class TraceWriter:
    """Write a trace file one event at a time.

    Use it as a context manager, or call close() when done. Closing flushes the
    buffered records to the file, and closing twice is harmless; writing after
    close raises ValueError rather than appending to a file that is already
    inconsistent.
    """

    def __init__(self, path):
        self._stream = open(path, "wb")
        self._stream.write(_HEADER.pack(MAGIC, VERSION, 0))

    def write(self, event):
        """Append one event. `ts` is used as given, never re-stamped."""
        self._stream.write(_RECORD.pack(event.kind, event.tid, event.rva,
                                        event.ts, event.a, event.b))

    def flush(self):
        """Push buffered records to the file so a reader can see them."""
        self._stream.flush()

    def close(self):
        """Flush and close; safe to call more than once."""
        if not self._stream.closed:
            self._stream.flush()
            self._stream.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


def read_trace(path):
    """Yield the events of a v1 trace file in the order they were written.

    The header is checked before the first event is yielded. A file that ends
    inside a record raises TraceFormatError naming the byte offset, because the
    events read so far are only part of the trace and must not pass for all of
    it.
    """
    with open(path, "rb") as stream:
        header = stream.read(HEADER_SIZE)
        if len(header) < HEADER_SIZE:
            raise TraceFormatError(
                f"truncated trace header at offset 0: {len(header)} of "
                f"{HEADER_SIZE} bytes")
        magic, version, _flags = _HEADER.unpack(header)
        if magic != MAGIC:
            raise TraceFormatError(
                f"not a pydbg trace: bad magic {magic!r} at offset 0")
        if version != VERSION:
            raise TraceFormatError(
                f"unsupported trace version {version} at offset {len(MAGIC)}; "
                f"expected version {VERSION}")
        offset = HEADER_SIZE
        while True:
            chunk = stream.read(RECORD_SIZE)
            if not chunk:
                return
            if len(chunk) < RECORD_SIZE:
                raise TraceFormatError(
                    f"truncated record at offset {offset}: {len(chunk)} of "
                    f"{RECORD_SIZE} bytes")
            yield TraceEvent(*_RECORD.unpack(chunk))
            offset += RECORD_SIZE
