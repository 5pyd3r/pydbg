"""Consume a recorded trace: filter it, summarize it, hand it to other tools.

The event stream is the only truth a trace keeps, so everything here is a pure
function of the events it is given: no process, no clock, no global state. A
filtered stream is still in recording order, coverage counts only what actually
ran, and the JSONL export is stable enough to diff two runs byte for byte.
"""

from .format import BLOCK


def filter_events(events, kinds=None, tid=None, rva_min=None, rva_max=None):
    """Yield the events matching every given criterion, in recording order.

    `kinds` is None or an iterable of ints; `tid` keeps a single thread.
    `rva_min` is inclusive and `rva_max` is exclusive, either may be omitted.
    The result is lazy: it pulls from `events` one event at a time and only as
    far as the caller consumes.
    """
    wanted = None if kinds is None else frozenset(kinds)
    for event in events:
        if wanted is not None and event.kind not in wanted:
            continue
        if tid is not None and event.tid != tid:
            continue
        if rva_min is not None and event.rva < rva_min:
            continue
        if rva_max is not None and event.rva >= rva_max:
            continue
        yield event


def block_coverage(events):
    """Count recorded BLOCK events per block start, ignoring every other kind.

    The result maps rva to hit count and is a plain dict, so it can be sorted,
    serialized, or compared directly. An empty stream yields {}.
    """
    counts = {}
    for event in events:
        if event.kind == BLOCK:
            counts[event.rva] = counts.get(event.rva, 0) + 1
    return counts
