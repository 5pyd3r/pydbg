"""The event buffer a BBL stub writes into, in the target's own memory.

A detour at a block entry may not call back into the debugger — a stop per hit
is exactly what BBL instrumentation is meant to avoid. Instead the stub appends
one 36-byte trace v1 record per hit to a ring in the target and bumps a slot
counter; `EventBuffer.read()` drains it at a normal stop.

Layout, shared with the stub builder so the two cannot drift:

    offset 0   magic   8 bytes   b"PDBGBBL\\0"
    offset 8   version u32       VERSION
    offset 12  slot_size u32     SLOT_SIZE (36)
    offset 16  capacity u32      slots, a power of two
    offset 20  head     u32      writes ever, monotonic (slot counter)
    offset 24  reserved 8 bytes  zero
    offset 32  slots    capacity * 36 bytes

The header is 32 bytes although its named fields add up to 24: the specification
(§12.3) fixes a 32-byte header, so the last 8 bytes are reserved and written as
zero. `head` is the count of writes, not a byte offset; the slot for write
number `count` is `(count & (capacity - 1)) * SLOT_SIZE`, which is why parsing
can start from any count without extra state.

The stub cannot know `tid` or `ts`, so a target-side record carries zeros for
both; the trace format still reads it, and a caller must not mistake 0 for a
real thread id. The buffer is drained while the target is stopped: a writer
that is still running can advance `head` between the header read and the slot
read, and no lock in this Python object can prevent that.
"""

import struct

from ..exceptions import PydbgError
from ..trace.format import RECORD_SIZE, RECORD_STRUCT, TraceEvent

# Buffer identity, independent of the trace file's own MAGIC: a v1 trace file
# and a target-side ring are different containers with different headers.
MAGIC = b"PDBGBBL\0"
VERSION = 1

# The slot is the trace v1 record, byte for byte: the same struct the writer
# side packs, not a copy that can drift from it.
SLOT_SIZE = RECORD_SIZE
SLOT_STRUCT = RECORD_STRUCT

# Header fields plus the reserved tail that makes the header the documented 32
# bytes. HEAD_OFFSET is where the u32 slot counter lives; the stub bumps it.
HEADER_STRUCT = struct.Struct("<8sIIII8x")
HEADER_SIZE = HEADER_STRUCT.size
HEAD_OFFSET = 20

# A slot count is a u32; the arithmetic below wraps on the same boundary.
_COUNT_MASK = 0xFFFFFFFF
_U32 = struct.Struct("<I")


def _round_capacity(capacity):
    """Round a slot count up to a power of two; raise on nonsense."""
    if not isinstance(capacity, int) or capacity < 1:
        raise ValueError(f"capacity must be a positive integer, got {capacity!r}")
    return 1 << (capacity - 1).bit_length()


class EventBuffer:
    """Allocate and drain the target-side ring of trace v1 records.

    The buffer is allocated when the object is built and lives until `free()`;
    that is the shape the instrumenter needs, because the stub it writes at
    install time embeds the slot and head addresses, so they have to exist
    before the first stub is encoded.

    `capacity` is a slot *count* and is rounded up to a power of two so the ring
    index can be a mask. The allocation is `HEADER_SIZE + capacity * 36` bytes;
    the header is written immediately, so a stub can never see an uninitialised
    head.

    `read()` is deliberately pull-shaped: it returns what was written since the
    previous call and advances a local counter, never the target's. Reading is
    only safe at a stop point; if the target is still running, `head` can move
    between the header read and the slot read and a record can be torn — see
    the module docstring.
    """

    def __init__(self, dbg, capacity=4096):
        """Allocate the ring in `dbg`'s target and write its header.

        Args:
            dbg: a Debugger (or a stand-in with a `memory` attribute exposing
                MemoryManager's alloc_remote/write/read/free_remote).
            capacity: requested slot count; rounded up to a power of two.

        Raises:
            ValueError: capacity is not a positive integer.
            MemError: the target refused the allocation or the header write.
        """
        self._mem = dbg.memory
        self.capacity = _round_capacity(capacity)
        self.slot_size = SLOT_SIZE
        size = HEADER_SIZE + self.capacity * SLOT_SIZE
        base = self._mem.alloc_remote(size)
        try:
            self._mem.write(base, HEADER_STRUCT.pack(
                MAGIC, VERSION, SLOT_SIZE, self.capacity, 0))
        except Exception:
            self._release(base)          # never leave a remote allocation behind
            raise
        self._base = base
        self.address = base + HEADER_SIZE
        self.head_address = base + HEAD_OFFSET
        self._last_count = 0

    def read(self):
        """Return the records written since the previous read, oldest first.

        Returns a tuple of `TraceEvent`; an empty tuple means no new hits. The
        header is validated before anything is parsed, so a buffer that is not
        format v1 raises instead of returning a prefix that looks complete, and
        the local read counter does not advance on a failed read.

        At most `capacity` records can be returned: after more writes than that
        the oldest slots have already been overwritten, so the newest `capacity`
        are the only records that still exist.

        Raises:
            PydbgError: bad magic, unknown version, or a layout that disagrees
                with this buffer; the read counter stays where it was.
            MemError: the target refused the read.
        """
        self._require_live()
        head = self._read_head()
        delta = (head - self._last_count) & _COUNT_MASK
        if not delta:
            return ()
        available = min(delta, self.capacity)
        start = (head - available) & _COUNT_MASK
        data = self._read_slots(start, available)
        events = tuple(
            TraceEvent(*SLOT_STRUCT.unpack_from(data, offset))
            for offset in range(0, available * SLOT_SIZE, SLOT_SIZE))
        self._last_count = head
        return events

    # ── lifecycle ─────────────────────────────────────────────

    def reset(self):
        """Zero the target's head and the local read pointer.

        For tests and for reusing one allocation: it drops every record the
        target-side ring holds, so callers that still want the old events must
        read them first. The stub keeps using the same slots afterwards.
        """
        self._require_live()
        self._mem.write(self.head_address, _U32.pack(0))
        self._last_count = 0

    def free(self):
        """Release the target allocation; return cleanup warnings, never raise.

        Returns a tuple of `(what, why)` warnings — empty when the memory was
        released (or had already been). A failed release keeps the buffer
        usable and its address valid, so a teardown path can report the warning
        and still retry; only a successful release marks the buffer dead.
        """
        if self._base is None:
            return ()
        try:
            self._mem.free_remote(self._base)
        except (PydbgError, OSError) as exc:
            return (("event buffer", str(exc)),)
        self._base = None
        self._last_count = 0
        return ()

    # ── internals ─────────────────────────────────────────────

    def _require_live(self):
        """Refuse to touch memory that was already released."""
        if self._base is None:
            raise PydbgError("event buffer has been freed")

    def _read_head(self):
        """Read and validate the header; return the target's write count."""
        raw = self._read_chunk(self._base, HEADER_SIZE)
        magic, version, slot_size, capacity, head = HEADER_STRUCT.unpack(raw)
        if magic != MAGIC:
            raise PydbgError(
                f"not an event buffer at 0x{self._base:X}: bad magic {magic!r}")
        if version != VERSION:
            raise PydbgError(
                f"unsupported event buffer version {version}; expected "
                f"version {VERSION}")
        if slot_size != SLOT_SIZE:
            raise PydbgError(
                f"event buffer slot size {slot_size}; expected {SLOT_SIZE}")
        if capacity != self.capacity:
            raise PydbgError(
                f"event buffer capacity {capacity}; expected {self.capacity}")
        return head

    def _read_slots(self, start, count):
        """Read `count` slots beginning at write number `start`, ring-ordered."""
        index = start & (self.capacity - 1)
        first = min(count, self.capacity - index)
        data = self._read_chunk(self.address + index * SLOT_SIZE,
                                first * SLOT_SIZE)
        if count == first:
            return data
        return data + self._read_chunk(self.address,
                                       (count - first) * SLOT_SIZE)

    def _read_chunk(self, addr, size):
        """One bounded read; a short transfer is an error, not a record."""
        data = self._mem.read(addr, size)
        if len(data) != size:
            raise PydbgError(
                f"short event buffer read at 0x{addr:X}: {len(data)} of "
                f"{size} bytes")
        return data

    def _release(self, base):
        """Best-effort release used while the constructor is unwinding."""
        try:
            self._mem.free_remote(base)
        except (PydbgError, OSError):
            pass
