"""Replay: the facts a trace file carries, filtered and summarized.

The file format is tested in test_trace_format.py. This module starts where that
one stops: given the events the reader hands back, what can a caller ask about
them (which ones happened, which blocks ran, and how do I hand the trace to a
tool that speaks JSONL) without a live process.
"""

import json
import os
import shutil
import tempfile
import unittest

from pydbg.trace import (
    API, BLOCK, MARK, MEM_READ, MEM_WRITE, TraceEvent, TraceWriter,
    block_coverage, filter_events, read_trace, to_jsonl,
)


def mixed_events():
    """Six events: four kinds, two threads, three address regions.

    The order is deliberate and monotonically increasing in `ts`, so a filter
    that reorders or deduplicates is visible in the assertion, not hidden by a
    sort.
    """
    return [
        TraceEvent(BLOCK, 1, 0x401000, 100, a=3),       # 0
        TraceEvent(API, 2, 0x7FFE1234, 101, a=7),       # 1
        TraceEvent(BLOCK, 2, 0x401010, 102, a=2),       # 2
        TraceEvent(MARK, 1, 0x401008, 103, a=42),       # 3
        TraceEvent(MEM_READ, 2, 0x500000, 104,
                   a=0x500000, b=8),                    # 4
        TraceEvent(BLOCK, 1, 0x401020, 105, a=1),       # 5
    ]


class TestFilterEvents(unittest.TestCase):

    def test_only_the_requested_kinds_survive_in_their_original_order(self):
        events = mixed_events()
        kept = list(filter_events(events, kinds=[BLOCK]))
        self.assertEqual(kept, [events[0], events[2], events[5]])

    def test_no_kind_filter_keeps_every_event(self):
        events = mixed_events()
        self.assertEqual(list(filter_events(events)), events)

    def test_kinds_accepts_any_iterable_of_ints(self):
        events = mixed_events()
        self.assertEqual(list(filter_events(events, kinds=(API, MARK))),
                         [events[1], events[3]])

    def test_one_threads_events_can_be_isolated(self):
        events = mixed_events()
        self.assertEqual(list(filter_events(events, tid=1)),
                         [events[0], events[3], events[5]])

    def test_criteria_combine_and_narrow_rather_than_widen(self):
        events = mixed_events()
        self.assertEqual(list(filter_events(events, kinds=[BLOCK], tid=2)),
                         [events[2]])

    def test_the_rva_range_includes_its_minimum(self):
        events = [TraceEvent(BLOCK, 1, rva, ts)
                  for ts, rva in enumerate((0x1000, 0x1010, 0x1020))]
        self.assertEqual(list(filter_events(events, rva_min=0x1010)),
                         [events[1], events[2]])

    def test_the_rva_range_excludes_its_maximum(self):
        events = [TraceEvent(BLOCK, 1, rva, ts)
                  for ts, rva in enumerate((0x1000, 0x1010, 0x1020))]
        self.assertEqual(list(filter_events(events, rva_max=0x1020)),
                         [events[0], events[1]])

    def test_both_rva_bounds_keep_only_the_half_open_interval(self):
        events = [TraceEvent(BLOCK, 1, rva, ts)
                  for ts, rva in enumerate((0x1000, 0x1010, 0x1020, 0x1030))]
        self.assertEqual(
            list(filter_events(events, rva_min=0x1010, rva_max=0x1030)),
            [events[1], events[2]])

    def test_an_empty_trace_filters_to_nothing(self):
        self.assertEqual(list(filter_events([])), [])

    def test_a_filter_that_matches_nothing_is_empty_not_an_error(self):
        events = mixed_events()
        self.assertEqual(list(filter_events(events, kinds=[MARK], tid=2)), [])

    def test_the_source_is_pulled_only_as_far_as_the_caller_reads(self):
        """A trace can outgrow memory; filtering must not read it all first."""
        events = mixed_events()
        pulled = []

        def source():
            for event in events:
                pulled.append(event)
                yield event

        filtered = filter_events(source(), kinds=[MARK])
        self.assertEqual(pulled, [])
        self.assertEqual(next(filtered), events[3])
        self.assertEqual(pulled, events[:4])


class TestBlockCoverage(unittest.TestCase):

    def test_a_block_that_ran_three_times_is_counted_three_times(self):
        events = [
            TraceEvent(BLOCK, 1, 0x401000, 10),
            TraceEvent(BLOCK, 2, 0x401000, 11),
            TraceEvent(BLOCK, 1, 0x401010, 12),
            TraceEvent(BLOCK, 1, 0x401000, 13),
        ]
        self.assertEqual(block_coverage(events),
                         {0x401000: 3, 0x401010: 1})

    def test_only_block_events_count_toward_coverage(self):
        """API/MARK/MEM events share an rva field but are not blocks."""
        events = [
            TraceEvent(API, 1, 0x401000, 10),
            TraceEvent(MARK, 1, 0x401000, 11),
            TraceEvent(MEM_READ, 1, 0x401000, 12, a=0x401000, b=4),
            TraceEvent(MEM_WRITE, 1, 0x401000, 13, a=0x401000, b=4),
            TraceEvent(BLOCK, 1, 0x401000, 14),
        ]
        self.assertEqual(block_coverage(events), {0x401000: 1})

    def test_an_empty_trace_has_no_coverage(self):
        self.assertEqual(block_coverage([]), {})

    def test_coverage_can_be_taken_of_a_filtered_stream(self):
        events = mixed_events()
        self.assertEqual(block_coverage(filter_events(events, tid=1)),
                         {0x401000: 1, 0x401020: 1})


class JsonlFileTest(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def path(self, name="trace.jsonl"):
        return os.path.join(self.dir, name)

    def read_bytes(self, name="trace.jsonl"):
        with open(self.path(name), "rb") as stream:
            return stream.read()


class TestToJsonl(JsonlFileTest):

    def test_each_event_is_one_json_object_with_its_kind_named(self):
        events = [
            TraceEvent(MARK, 2, 0x401008, 103, a=42),
            TraceEvent(BLOCK, 1, 0x401000, 100, a=3),
            TraceEvent(MEM_WRITE, 2, 0x500010, 105, a=0x500010, b=16),
        ]
        to_jsonl(events, self.path())

        with open(self.path(), encoding="utf-8") as stream:
            lines = stream.read().splitlines()
        self.assertEqual(len(lines), 3)
        self.assertEqual([json.loads(line) for line in lines], [
            {"kind": MARK, "kind_name": "MARK", "tid": 2, "rva": 0x401008,
             "ts": 103, "a": 42, "b": 0},
            {"kind": BLOCK, "kind_name": "BLOCK", "tid": 1, "rva": 0x401000,
             "ts": 100, "a": 3, "b": 0},
            {"kind": MEM_WRITE, "kind_name": "MEM_WRITE", "tid": 2,
             "rva": 0x500010, "ts": 105, "a": 0x500010, "b": 16},
        ])

    def test_every_v1_kind_gets_its_documented_name(self):
        kinds = (BLOCK, API, MARK, MEM_READ, MEM_WRITE)
        to_jsonl([TraceEvent(kind, 1, 0, 0) for kind in kinds], self.path())

        with open(self.path(), encoding="utf-8") as stream:
            rows = [json.loads(line) for line in stream]
        self.assertEqual([row["kind_name"] for row in rows],
                         ["BLOCK", "API", "MARK", "MEM_READ", "MEM_WRITE"])
        self.assertEqual([row["kind"] for row in rows], list(kinds))

    def test_a_line_is_compact_with_sorted_keys_and_a_final_newline(self):
        """Pinned literally: tools diff these files, so layout is a contract."""
        to_jsonl([TraceEvent(BLOCK, 7, 0x401000, 123, a=3)], self.path())
        self.assertEqual(
            self.read_bytes(),
            b'{"a":3,"b":0,"kind":1,"kind_name":"BLOCK",'
            b'"rva":4198400,"tid":7,"ts":123}\n')

    def test_the_same_events_written_twice_give_identical_files(self):
        events = mixed_events()
        to_jsonl(events, self.path("first.jsonl"))
        to_jsonl(events, self.path("second.jsonl"))
        self.assertEqual(self.read_bytes("first.jsonl"),
                         self.read_bytes("second.jsonl"))

    def test_an_unknown_kind_is_exported_without_an_invented_name(self):
        """`kind` is the fact; naming a kind v1 does not define would be a guess."""
        to_jsonl([TraceEvent(99, 1, 0x401000, 7)], self.path())

        with open(self.path(), encoding="utf-8") as stream:
            row = json.loads(stream.readline())
        self.assertEqual(row["kind"], 99)
        self.assertIsNone(row["kind_name"])

    def test_an_empty_trace_exports_to_an_empty_file(self):
        to_jsonl([], self.path())
        self.assertEqual(os.path.getsize(self.path()), 0)

    def test_events_that_came_from_a_trace_file_export_the_same(self):
        """The file and the in-memory stream must be interchangeable inputs."""
        events = mixed_events()
        with TraceWriter(self.path("trace.bin")) as writer:
            for event in events:
                writer.write(event)

        to_jsonl(read_trace(self.path("trace.bin")), self.path("from_file.jsonl"))
        to_jsonl(events, self.path("direct.jsonl"))
        self.assertEqual(self.read_bytes("from_file.jsonl"),
                         self.read_bytes("direct.jsonl"))


if __name__ == "__main__":
    unittest.main()
