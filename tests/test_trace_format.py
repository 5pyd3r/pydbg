"""The v1 trace file: what gets written, what comes back, what is refused.

A trace file is the only truth Phase 3a keeps after the target is gone, so the
reader is deliberately intolerant: a bad magic, a future version, or a partial
tail record raises instead of returning the events it happened to understand.
Half a trace that reads like a whole one is the failure this format is meant to
make impossible.
"""

import os
import tempfile
import unittest

from pydbg.trace import (
    API, BLOCK, INSTR, KIND_NAMES, MAGIC, MARK, MEM_READ, MEM_WRITE, VERSION,
    TraceEvent, TraceFormatError, TraceWriter, read_trace,
)

HEADER_SIZE = 12
RECORD_SIZE = 36


class TraceFileTest(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def path(self, name="trace.bin"):
        return os.path.join(self.dir, name)


class TestTraceEvent(TraceFileTest):

    def test_the_optional_fields_default_to_zero(self):
        event = TraceEvent(BLOCK, tid=7, rva=0x401000, ts=123)
        self.assertEqual(event.a, 0)
        self.assertEqual(event.b, 0)

    def test_an_event_cannot_be_changed_after_it_is_recorded(self):
        """Records are facts: a replay must not be able to retouch one."""
        event = TraceEvent(BLOCK, tid=7, rva=0x401000, ts=123)
        with self.assertRaises(AttributeError):
            event.rva = 0x402000

    def test_kinds_and_magic_match_the_documented_numbers(self):
        """These are the file format; changing one breaks every trace."""
        self.assertEqual(MAGIC, b"PDBGTRC\0")
        self.assertEqual(VERSION, 1)
        self.assertEqual((BLOCK, API, MARK, MEM_READ, MEM_WRITE),
                         (1, 2, 3, 4, 5))

    def test_instr_is_kind_six_and_named(self):
        """INSTR extends the vocabulary without reusing a phase-3a number."""
        self.assertEqual(INSTR, 6)
        self.assertEqual(KIND_NAMES[INSTR], "INSTR")
        self.assertNotIn(INSTR, (BLOCK, API, MARK, MEM_READ, MEM_WRITE))


class TestTraceRoundTrip(TraceFileTest):

    def test_all_record_kinds_survive_a_write_and_read_unchanged(self):
        events = [
            TraceEvent(BLOCK, 1, 0x401000, 10, a=3, b=0),
            TraceEvent(API, 2, 0x7FFE1234, 11, a=0xC0FFEE, b=0),
            TraceEvent(MARK, 3, 0x401500, 12, a=0xBEEF, b=0),
            TraceEvent(MEM_READ, 1, 0x500000, 13, a=0x500000, b=8),
            TraceEvent(MEM_WRITE, 2, 0x500010, 14, a=0x500010, b=16),
        ]
        with TraceWriter(self.path()) as writer:
            for event in events:
                writer.write(event)

        self.assertEqual(list(read_trace(self.path())), events)

    def test_an_instr_event_round_trips_and_writes_stable_bytes(self):
        """INSTR carries an address and an instruction length, nothing else.

        The same event must read back field for field and produce identical
        bytes twice: a trace is compared by file, not by re-running the target.
        """
        event = TraceEvent(INSTR, tid=7, rva=0x401000, ts=123, a=3)
        for name in ("first.bin", "second.bin"):
            with TraceWriter(self.path(name)) as writer:
                writer.write(event)

        with open(self.path("first.bin"), "rb") as first, \
                open(self.path("second.bin"), "rb") as second:
            self.assertEqual(first.read(), second.read())

        read_back = list(read_trace(self.path("first.bin")))
        self.assertEqual(read_back, [event])
        self.assertEqual((read_back[0].rva, read_back[0].a, read_back[0].b),
                         (0x401000, 3, 0))


class TestOnDiskLayout(TraceFileTest):

    def test_the_header_is_magic_then_version_then_zero_flags(self):
        with TraceWriter(self.path()):
            pass
        with open(self.path(), "rb") as stream:
            header = stream.read(HEADER_SIZE)

        self.assertEqual(header, MAGIC + b"\x01\x00" + b"\x00\x00")

    def test_one_record_is_thirty_six_little_endian_bytes(self):
        """Hand-built from §8.2 rather than re-packed: field order and pads."""
        event = TraceEvent(BLOCK, tid=2, rva=3, ts=4, a=5, b=6)
        with TraceWriter(self.path()) as writer:
            writer.write(event)

        expected = (
            MAGIC + b"\x01\x00" + b"\x00\x00" +   # magic, version, flags
            b"\x01" + b"\x00\x00\x00" +           # kind, 3 bytes padding
            b"\x02\x00\x00\x00" +                 # tid
            b"\x03\x00\x00\x00" +                 # rva
            b"\x04\x00\x00\x00\x00\x00\x00\x00" +  # ts
            b"\x05\x00\x00\x00\x00\x00\x00\x00" +  # a
            b"\x06\x00\x00\x00\x00\x00\x00\x00"    # b
        )
        with open(self.path(), "rb") as stream:
            self.assertEqual(stream.read(), expected)

    def test_the_same_events_written_twice_give_identical_files(self):
        events = [TraceEvent(BLOCK, 1, 0x1000, 100, a=2),
                  TraceEvent(MARK, 1, 0, 101, a=9)]
        for name in ("first.bin", "second.bin"):
            with TraceWriter(self.path(name)) as writer:
                for event in events:
                    writer.write(event)

        with open(self.path("first.bin"), "rb") as first, \
                open(self.path("second.bin"), "rb") as second:
            self.assertEqual(first.read(), second.read())

    def test_timestamps_are_taken_verbatim_from_the_caller(self):
        """Including the u64 extremes: the writer never re-stamps or narrows."""
        events = [TraceEvent(BLOCK, 1, 0x1000, 0),
                  TraceEvent(BLOCK, 1, 0x1000, 0xFFFFFFFFFFFFFFFF)]
        with TraceWriter(self.path()) as writer:
            for event in events:
                writer.write(event)

        self.assertEqual([event.ts for event in read_trace(self.path())],
                         [0, 0xFFFFFFFFFFFFFFFF])


class TestTraceWriterValidation(TraceFileTest):
    """write() maps a typed event onto six fixed-width fields.

    A value that does not fit is the caller's mistake, and it must be named as
    such: struct.error leaking out of pack() says which struct failed, not
    which field or what range was expected.
    """

    def refuse(self, event, field):
        with self.assertRaises(ValueError) as caught:
            with TraceWriter(self.path()) as writer:
                writer.write(event)
        self.assertIn(field, str(caught.exception))

    def test_kind_must_fit_one_byte(self):
        self.refuse(TraceEvent(256, 1, 0, 0), "kind")
        self.refuse(TraceEvent(-1, 1, 0, 0), "kind")

    def test_tid_must_fit_an_unsigned_32_bit_field(self):
        self.refuse(TraceEvent(BLOCK, 0x100000000, 0, 0), "tid")
        self.refuse(TraceEvent(BLOCK, -1, 0, 0), "tid")

    def test_rva_must_fit_an_unsigned_32_bit_field(self):
        self.refuse(TraceEvent(BLOCK, 1, 0x100000000, 0), "rva")
        self.refuse(TraceEvent(BLOCK, 1, -1, 0), "rva")

    def test_timestamp_must_fit_an_unsigned_64_bit_field(self):
        self.refuse(TraceEvent(BLOCK, 1, 0, 0x10000000000000000), "ts")
        self.refuse(TraceEvent(BLOCK, 1, 0, -1), "ts")

    def test_a_must_fit_an_unsigned_64_bit_field(self):
        self.refuse(TraceEvent(BLOCK, 1, 0, 0, a=0x10000000000000000), "a")
        self.refuse(TraceEvent(BLOCK, 1, 0, 0, a=-1), "a")

    def test_b_must_fit_an_unsigned_64_bit_field(self):
        self.refuse(TraceEvent(BLOCK, 1, 0, 0, b=0x10000000000000000), "b")
        self.refuse(TraceEvent(BLOCK, 1, 0, 0, b=-1), "b")

    def test_every_field_accepts_its_full_unsigned_width(self):
        """The limits are inclusive: this is the widest record v1 can hold."""
        event = TraceEvent(255, 0xFFFFFFFF, 0xFFFFFFFF,
                           0xFFFFFFFFFFFFFFFF,
                           a=0xFFFFFFFFFFFFFFFF, b=0xFFFFFFFFFFFFFFFF)
        with TraceWriter(self.path()) as writer:
            writer.write(event)
        self.assertEqual(list(read_trace(self.path())), [event])


class TestTraceFormatErrors(TraceFileTest):

    def write_bytes(self, data, name="trace.bin"):
        with open(self.path(name), "wb") as stream:
            stream.write(data)

    def test_trace_format_error_is_a_value_error(self):
        self.assertTrue(issubclass(TraceFormatError, ValueError))

    def test_trace_format_error_belongs_to_the_pydbg_error_tree(self):
        """A caller catching PydbgError must see a malformed trace as one of ours."""
        from pydbg.exceptions import PydbgError

        self.assertTrue(issubclass(TraceFormatError, PydbgError))

    def test_a_file_that_is_not_a_trace_is_refused(self):
        self.write_bytes(b"NOTATRAC" + b"\x01\x00" + b"\x00\x00")
        with self.assertRaises(TraceFormatError) as caught:
            list(read_trace(self.path()))
        self.assertIn("magic", str(caught.exception))
        self.assertIn("offset 0", str(caught.exception))

    def test_a_future_version_is_refused_not_guessed(self):
        """Reading v2 with the v1 layout would misread every record."""
        self.write_bytes(MAGIC + b"\x02\x00" + b"\x00\x00")
        with self.assertRaises(TraceFormatError) as caught:
            list(read_trace(self.path()))
        self.assertIn("version 2", str(caught.exception))

    def test_a_header_shorter_than_twelve_bytes_is_refused(self):
        self.write_bytes(MAGIC + b"\x01")
        with self.assertRaises(TraceFormatError) as caught:
            list(read_trace(self.path()))
        self.assertIn("offset 0", str(caught.exception))

    def test_a_partial_last_record_is_refused_with_its_offset(self):
        """One byte short of a record is a truncated file, not a short read."""
        with TraceWriter(self.path()) as writer:
            writer.write(TraceEvent(BLOCK, 1, 0x1000, 7, a=2))
        size = os.path.getsize(self.path())
        with open(self.path(), "r+b") as stream:
            stream.truncate(size - 1)

        with self.assertRaises(TraceFormatError) as caught:
            list(read_trace(self.path()))
        self.assertIn("offset 12", str(caught.exception))

    def test_events_before_a_partial_record_are_still_delivered(self):
        first = TraceEvent(BLOCK, 1, 0x1000, 7, a=2)
        second = TraceEvent(BLOCK, 1, 0x1010, 8, a=3)
        with TraceWriter(self.path()) as writer:
            writer.write(first)
            writer.write(second)
        size = os.path.getsize(self.path())
        with open(self.path(), "r+b") as stream:
            stream.truncate(size - 1)

        events = read_trace(self.path())
        self.assertEqual(next(events), first)
        with self.assertRaises(TraceFormatError):
            next(events)


class TestTraceWriterLifecycle(TraceFileTest):

    def test_a_header_only_file_is_an_empty_trace(self):
        with TraceWriter(self.path()):
            pass
        self.assertEqual(list(read_trace(self.path())), [])

    def test_closing_twice_is_harmless(self):
        event = TraceEvent(BLOCK, 1, 0x1000, 7)
        writer = TraceWriter(self.path())
        writer.write(event)
        writer.close()
        writer.close()
        self.assertEqual(list(read_trace(self.path())), [event])

    def test_writing_after_close_raises_value_error(self):
        writer = TraceWriter(self.path())
        writer.close()
        with self.assertRaises(ValueError):
            writer.write(TraceEvent(BLOCK, 1, 0x1000, 7))

    def test_flush_makes_events_readable_before_close(self):
        """A live consumer can read a trace that is still being written."""
        event = TraceEvent(MARK, 1, 0, 7, a=42)
        writer = TraceWriter(self.path())
        try:
            writer.write(event)
            writer.flush()
            self.assertEqual(list(read_trace(self.path())), [event])
        finally:
            writer.close()

    def test_the_context_manager_closes_after_an_exception(self):
        event = TraceEvent(BLOCK, 1, 0x1000, 7, a=2)
        with self.assertRaises(RuntimeError):
            with TraceWriter(self.path()) as writer:
                writer.write(event)
                raise RuntimeError("the target died mid-run")
        self.assertEqual(list(read_trace(self.path())), [event])

    def test_a_pathlib_path_is_accepted_on_both_sides(self):
        from pathlib import Path
        path = Path(self.path())
        event = TraceEvent(BLOCK, 1, 0x1000, 7, a=2)
        with TraceWriter(path) as writer:
            writer.write(event)
        self.assertEqual(list(read_trace(path)), [event])

    def test_reader_ignores_the_header_flags_it_does_not_understand(self):
        """Flags are reserved: a set bit must not make v1 unreadable."""
        event = TraceEvent(BLOCK, 1, 0x1000, 7, a=2)
        with TraceWriter(self.path()) as writer:
            writer.write(event)
        with open(self.path(), "r+b") as stream:
            stream.seek(10)
            stream.write(b"\x34\x12")
        self.assertEqual(list(read_trace(self.path())), [event])


class TestTraceScale(TraceFileTest):

    def test_ten_thousand_blocks_round_trip_without_losing_one(self):
        """The size is exact: 12 + 36 per record, no index, no padding."""
        count = 10000
        events = [
            TraceEvent(BLOCK, 1, 0x400000 + i * 0x10, 1000 + i, a=i % 7)
            for i in range(count)
        ]
        with TraceWriter(self.path()) as writer:
            for event in events:
                writer.write(event)

        self.assertEqual(os.path.getsize(self.path()),
                         HEADER_SIZE + count * RECORD_SIZE)
        read_back = list(read_trace(self.path()))
        self.assertEqual(len(read_back), count)
        self.assertEqual(read_back[0], events[0])
        self.assertEqual(read_back[-1], events[-1])
