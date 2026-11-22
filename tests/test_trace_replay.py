"""Replay: the facts a trace file carries, filtered and summarized.

The file format is tested in test_trace_format.py. This module starts where that
one stops: given the events the reader hands back, what can a caller ask about
them (which ones happened, which blocks ran, and how do I hand the trace to a
tool that speaks JSONL) without a live process.
"""

import unittest

from pydbg.trace import (
    API, BLOCK, MARK, MEM_READ, TraceEvent, filter_events,
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


if __name__ == "__main__":
    unittest.main()
