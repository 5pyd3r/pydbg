"""The target-side event buffer: layout, incremental read, wrap, cleanup.

A BBL detour writes 36-byte v1 records into a fixed ring in the target and bumps
a slot counter; Python reads them at a normal stop. Two halves have to agree for
that to be safe: the layout the stub is built from (a 32-byte header and
``capacity`` 36-byte slots) and the reader that turns slots back into
``TraceEvent``s. The constants are pinned here so a writer-side change cannot
silently reinterpret bytes, and ``read()`` is pinned as "only what is new",
because an event reported twice is a wrong trace even when the bytes are right.
"""

import os
import struct
import unittest
from types import SimpleNamespace

from pydbg.exceptions import MemError, PydbgError
from pydbg.instrument import event_buffer
from pydbg.trace.format import API, BLOCK, RECORD_SIZE, TraceEvent
from tests import TEST_TARGET_PATH

try:
    from pydbg import _pydbg  # noqa: F401

    _has_cython = True
except ImportError:
    _has_cython = False

# The record is the trace v1 record; written out here so the module's struct is
# checked against an independent copy rather than against itself.
_RECORD = struct.Struct("<B3xIIQQQ")
_U32 = struct.Struct("<I")


class FakeMemory:
    """A MemoryManager stand-in with the same call shapes as the real one.

    Regions are byte-addressed, so a test can read the header and the slots the
    way the stub would have left them. It records where the last allocation went
    because the layout test has to start from the allocation base, not from the
    slot area EventBuffer exposes.
    """

    def __init__(self):
        self.regions = {}
        self.last_alloc = None
        self.free_error = None
        self._next = 0x10000000

    def alloc_remote(self, size, protect=0x04):
        base = self._next
        self._next += 0x10000
        self.regions[base] = bytearray(size)   # VirtualAllocEx zero-fills
        self.last_alloc = base
        return base

    def free_remote(self, addr):
        if self.free_error is not None:
            raise MemError(self.free_error)
        if addr not in self.regions:
            raise MemError(f"no fake region at 0x{addr:X}")
        del self.regions[addr]

    def read(self, addr, size):
        base, offset = self._locate(addr, size)
        return bytes(self.regions[base][offset:offset + size])

    def write(self, addr, data):
        base, offset = self._locate(addr, len(data))
        self.regions[base][offset:offset + len(data)] = data

    def _locate(self, addr, size):
        for base, buf in self.regions.items():
            if base <= addr and addr + size <= base + len(buf):
                return base, addr - base
        raise MemError(f"no fake region covers 0x{addr:X}..0x{addr + size:X}")


def write_events(mem, buf, events, start=0):
    """Append records the way the stub does: slot per count, then bump head."""
    for index, event in enumerate(events):
        count = start + index
        slot = buf.address + (count & (buf.capacity - 1)) * _RECORD.size
        mem.write(slot, _RECORD.pack(
            event.kind, event.tid, event.rva, event.ts, event.a, event.b))
    mem.write(buf.head_address,
              _U32.pack((start + len(events)) & 0xFFFFFFFF))


class TestLayoutConstants(unittest.TestCase):
    """The numbers a stub and the reader must both use, checked literally."""

    def test_the_header_is_32_bytes_and_head_sits_at_offset_20(self):
        self.assertEqual(event_buffer.HEADER_SIZE, 32)
        self.assertEqual(event_buffer.HEAD_OFFSET, 20)
        self.assertEqual(event_buffer.HEADER_STRUCT.size, 32)

        raw = event_buffer.HEADER_STRUCT.pack(b"PDBGBBL\0", 1, 36, 8, 7)
        self.assertEqual(len(raw), 32)
        self.assertEqual(raw[:8], b"PDBGBBL\0")
        self.assertEqual(struct.unpack_from("<I", raw, 8)[0], 1)
        self.assertEqual(struct.unpack_from("<I", raw, 12)[0], 36)
        self.assertEqual(struct.unpack_from("<I", raw, 16)[0], 8)
        self.assertEqual(struct.unpack_from("<I", raw, 20)[0], 7)

    def test_magic_and_version_are_the_documented_numbers(self):
        self.assertEqual(event_buffer.MAGIC, b"PDBGBBL\0")
        self.assertEqual(event_buffer.VERSION, 1)

    def test_the_slot_is_the_v1_record(self):
        self.assertEqual(event_buffer.SLOT_SIZE, 36)
        self.assertEqual(event_buffer.SLOT_SIZE, RECORD_SIZE)
        self.assertEqual(event_buffer.SLOT_STRUCT.size, 36)
        self.assertEqual(
            event_buffer.SLOT_STRUCT.pack(1, 2, 3, 4, 5, 6),
            _RECORD.pack(1, 2, 3, 4, 5, 6))


class EventBufferTest(unittest.TestCase):
    """One fake target per test; the buffer is built over its memory."""

    def setUp(self):
        self.mem = FakeMemory()
        self.dbg = SimpleNamespace(memory=self.mem)


class TestAllocation(EventBufferTest):

    def test_capacity_rounds_up_to_a_power_of_two_and_the_header_records_it(self):
        buf = event_buffer.EventBuffer(self.dbg, capacity=3)
        self.assertEqual(buf.capacity, 4)
        self.assertEqual(buf.slot_size, 36)

        header = self.mem.read(self.mem.last_alloc, 32)
        self.assertEqual(header[:8], b"PDBGBBL\0")
        self.assertEqual(struct.unpack_from("<I", header, 8)[0], 1)
        self.assertEqual(struct.unpack_from("<I", header, 12)[0], 36)
        self.assertEqual(struct.unpack_from("<I", header, 16)[0], 4)
        self.assertEqual(struct.unpack_from("<I", header, 20)[0], 0,
                         "a fresh buffer has never been written")

    def test_the_slot_area_starts_after_the_header_and_head_sits_at_20(self):
        buf = event_buffer.EventBuffer(self.dbg, capacity=8)
        base = self.mem.last_alloc
        self.assertEqual(buf.head_address, base + 20)
        self.assertEqual(buf.address, base + 32)
        self.assertEqual(self.mem.read(buf.address, 36), b"\0" * 36)

    def test_the_default_capacity_is_4096_and_one_is_the_minimum(self):
        self.assertEqual(event_buffer.EventBuffer(self.dbg).capacity, 4096)
        self.assertEqual(event_buffer.EventBuffer(
            self.dbg, capacity=1).capacity, 1)

    def test_a_capacity_below_one_is_rejected_before_allocating(self):
        with self.assertRaises(ValueError):
            event_buffer.EventBuffer(self.dbg, capacity=0)
        self.assertIsNone(self.mem.last_alloc)


class TestRead(EventBufferTest):

    def setUp(self):
        super().setUp()
        self.buf = event_buffer.EventBuffer(self.dbg, capacity=8)

    def test_records_come_back_field_for_field_and_only_once(self):
        block = TraceEvent(BLOCK, tid=0, rva=0x401000, ts=0, a=5, b=0)
        api = TraceEvent(API, tid=3, rva=0x7FFE1000, ts=9,
                         a=0xC0FFEE, b=2)
        write_events(self.mem, self.buf, [block, api])

        self.assertEqual(self.buf.read(), (block, api))
        self.assertEqual(self.buf.read(), (),
                         "a second read must not report the same hits again")

    def test_a_later_read_returns_only_records_written_since(self):
        events = [TraceEvent(BLOCK, 0, 0x401000 + i, 0, a=i) for i in range(3)]
        write_events(self.mem, self.buf, events[:2])
        self.assertEqual(self.buf.read(), tuple(events[:2]))

        write_events(self.mem, self.buf, events[2:], start=2)
        self.assertEqual(self.buf.read(), (events[2],))

    def test_an_unknown_kind_is_kept_verbatim(self):
        """A record kind this version does not name is still the fact."""
        event = TraceEvent(99, tid=5, rva=0x401000, ts=77, a=1, b=2)
        write_events(self.mem, self.buf, [event])
        self.assertEqual(self.buf.read(), (event,))


class TestRingWrap(EventBufferTest):

    def test_writing_more_than_capacity_keeps_the_newest_in_order(self):
        buf = event_buffer.EventBuffer(self.dbg, capacity=2)
        events = [TraceEvent(BLOCK, 0, 0x401000 + i, 0, a=i) for i in range(3)]
        write_events(self.mem, buf, events)

        # head is 3 and capacity is 2: write 0's slot has been overwritten.
        self.assertEqual(buf.read(), (events[1], events[2]))

        later = TraceEvent(BLOCK, 0, 0x402000, 0, a=9)
        write_events(self.mem, buf, [later], start=3)
        self.assertEqual(buf.read(), (later,))


class TestHeaderValidation(EventBufferTest):
    """A buffer that is not format v1 is refused, not half-read."""

    def setUp(self):
        super().setUp()
        self.buf = event_buffer.EventBuffer(self.dbg, capacity=8)
        self.event = TraceEvent(BLOCK, 0, 0x401000, 0, a=5)
        write_events(self.mem, self.buf, [self.event])
        self.base = self.mem.last_alloc

    def test_bad_magic_raises_and_the_records_survive_for_a_later_read(self):
        good = self.mem.read(self.base, 32)
        self.mem.write(self.base, b"PDBGXXXX" + good[8:])

        with self.assertRaises(PydbgError) as caught:
            self.buf.read()
        self.assertIn("magic", str(caught.exception))

        self.mem.write(self.base, good)
        self.assertEqual(self.buf.read(), (self.event,),
                         "a refused read must not consume the events")

    def test_an_unknown_version_is_refused_the_same_way(self):
        good = self.mem.read(self.base, 32)
        self.mem.write(self.base, good[:8] + _U32.pack(2) + good[12:])

        with self.assertRaises(PydbgError) as caught:
            self.buf.read()
        self.assertIn("version", str(caught.exception))

        self.mem.write(self.base, good)
        self.assertEqual(self.buf.read(), (self.event,))


class TestReset(EventBufferTest):

    def test_reset_zeroes_the_target_head_and_the_local_read_pointer(self):
        buf = event_buffer.EventBuffer(self.dbg, capacity=8)
        event = TraceEvent(BLOCK, 0, 0x401000, 0, a=5)
        write_events(self.mem, buf, [event])
        self.assertEqual(buf.read(), (event,))

        buf.reset()
        self.assertEqual(self.mem.read(buf.head_address, 4), b"\0\0\0\0")

        fresh = TraceEvent(BLOCK, 0, 0x402000, 0, a=1)
        write_events(self.mem, buf, [fresh])       # count restarts at 0
        self.assertEqual(buf.read(), (fresh,))


class TestFree(EventBufferTest):

    def test_free_releases_the_allocation_and_reports_nothing(self):
        buf = event_buffer.EventBuffer(self.dbg, capacity=8)
        base = self.mem.last_alloc

        self.assertEqual(buf.free(), ())
        self.assertNotIn(base, self.mem.regions)
        for operation in (buf.read, buf.reset):
            with self.assertRaises(PydbgError):
                operation()

    def test_free_is_idempotent(self):
        buf = event_buffer.EventBuffer(self.dbg, capacity=8)
        self.assertEqual(buf.free(), ())
        self.assertEqual(buf.free(), ())

    def test_a_failed_release_comes_back_as_a_cleanup_warning(self):
        buf = event_buffer.EventBuffer(self.dbg, capacity=8)
        base = self.mem.last_alloc
        self.mem.free_error = "VirtualFreeEx failed"

        self.assertEqual(buf.free(),
                         (("event buffer", "VirtualFreeEx failed"),))
        self.assertIn(base, self.mem.regions,
                      "a failed free must not pretend the memory is gone")

        self.mem.free_error = None
        self.assertEqual(buf.free(), ())
        self.assertNotIn(base, self.mem.regions)


class TestLiveTarget(unittest.TestCase):
    """One real target: alloc, write a record, read it back, free, still alive."""

    @unittest.skipUnless(os.path.exists(TEST_TARGET_PATH),
                         "target not built: simple_target.exe")
    @unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
    def test_a_record_written_into_the_target_reads_back_and_frees(self):
        from tests.helpers import create_debugger, module_base, teardown

        dbg, _pid, _tid = create_debugger()
        try:
            buf = event_buffer.EventBuffer(dbg, capacity=4)
            self.assertEqual(buf.slot_size, 36)
            self.assertEqual(buf.head_address, buf.address - 12)

            event = TraceEvent(BLOCK, tid=0, rva=0x401000, ts=0, a=7, b=0)
            dbg.write_memory(buf.address, _RECORD.pack(
                event.kind, event.tid, event.rva, event.ts,
                event.a, event.b))
            dbg.write_memory(buf.head_address, _U32.pack(1))

            self.assertEqual(buf.read(), (event,),
                             "a record written through the debugger must parse")
            self.assertEqual(buf.read(), ())
            self.assertEqual(buf.free(), ())

            # The target was only a memory donor: still mapped, still running.
            self.assertEqual(dbg.read_memory(module_base(dbg), 2), b"MZ")
            self.assertEqual(dbg.get_exit_code(), 259)   # STILL_ACTIVE
        finally:
            teardown(dbg)


if __name__ == "__main__":
    unittest.main()
