"""OEP-hint queries — facts about where execution might begin.

Every function here answers a question about bytes that already exist; none of
them decides that one address is the entry point. `oep_candidates` merges and
sorts the facts and hands them back; it never scores, ranks, or names a "most
likely" entry point, and `OepCandidate` has no field in which such a verdict
could be stored (spec §11.5).

Known limits, all of them inherited from the primitives this composes:

* `StackWalker` unwinds x64 only. A WOW64 (32-bit) target has no stack walk
  here, so a stack-return hint cannot be produced on one.
* There is no page-level guard monitoring. `MemoryWatch` watches one address
  with a hardware breakpoint; a page's execute or write state is not tracked,
  and nothing here waits for the first execution of a page.
* `MemoryWatch` observes **writes only**. Windows cannot tell which direction
  tripped a read/write data breakpoint, so a "watched" candidate is a write
  hit, never an execute or a read hit.
* The four debug-register slots are shared with every hardware breakpoint in
  the process (another watch, a `FunctionProbe`), so arming a watch can be
  refused with "no free debug-register slot".
* A hardware watch must be armed at a normal stop. One armed at the initial
  loader stop is dropped by the next continue.

The `.pdata`-gap query needs an `AnalysisResult`: a bare `PE` has the exception
table but no recovered function starts, and treating every record as a gap
would be a claim the analysis never made.
"""

from dataclasses import dataclass

from ..pe import PE

# The sources in canonical order. Merged candidates name their sources in this
# order, so the same set always reads the same way.
_SOURCE_ORDER = ('tls', 'pdata-gap', 'watched')


def _image_extent(pe):
    """How far the image's own address space reaches, from its sections.

    `SizeOfImage` is used as a floor: a section table can stop short of the
    mapped extent an image is allowed to use, and a callback in that tail is
    still inside the image.
    """
    sections_end = max((section.virtual_address + section.span
                        for section in pe.sections), default=0)
    return max(sections_end, pe.optional_header.size_of_image)


def tls_callbacks(pe):
    """Every TLS callback VA the image registers, in table order.

    A thin wrapper over ``pe.tls.callbacks``: an image with no TLS directory
    returns (). The stored values are VAs, so ``pe`` must have been built with
    ``va_base=<module runtime base>`` — `PE.from_source(..., va_base=...)`, as
    the live-module and analysis paths do. A file parsed against its preferred
    ``ImageBase`` is correct only when it was not relocated.

    A callback outside the window ``pe.va_base`` anchors is reported rather
    than returned: the usual cause is a wrong ``va_base`` (the directory's
    callback array and the values in it are both read relative to it), and an
    address that points outside the image would silently become a bogus OEP
    candidate downstream.

    Raises:
        ValueError: a callback VA is outside the image window. The message
            names the callback and the window, and asks for the runtime base.
    """
    tls = pe.tls
    if tls is None:
        return ()
    callbacks = tuple(tls.callbacks)
    if not callbacks:
        return callbacks

    base = pe.va_base
    end = base + _image_extent(pe)
    for va in callbacks:
        if not base <= va < end:
            raise ValueError(
                f"TLS callback VA 0x{va:X} is outside the image window "
                f"[0x{base:X}, 0x{end:X}); pass a PE whose va_base is the "
                f"module's runtime base, not the header's preferred ImageBase")
    return callbacks


def executable_ranges_outside_functions(result):
    """.pdata ranges whose own begin was never recovered as a function start.

    The exception directory is the loader's own statement that a function
    exists at ``[begin, end)``. `AnalysisResult.functions.starts` is what code
    discovery concluded. This query returns the disagreement that matters for
    an entry point: ranges the table calls a function but the analysis did not
    treat as starting one.

    Only the range's *begin* is tested. A start recovered inside the range but
    not at its begin does not make the entry's begin known, so the range stays
    whole — the question here is "was this entry accepted", not "does any byte
    in it belong to some function".

    The range is intersected with `AnalyzedImage.exec_ranges`, the single
    source of truth for what is executable, so every returned range is
    executable. A ``.pdata`` record that sits in a non-executable section
    names a stub the table describes but no CPU can enter, and is dropped
    rather than offered as an entry-point candidate (spec §11.6(5)). Ranges are
    returned ascending by begin, with overlapping and touching ranges merged; a
    degenerate record with ``end <= begin`` is dropped. A PE32 image has no
    exception directory in this parser, so it returns ().
    """
    starts = result.functions.starts
    exec_ranges = tuple(result.image.exec_ranges)
    ranges = []
    for entry in result.image.pe.exception_entries:
        begin, end = entry.begin_rva, entry.end_rva
        if end <= begin or begin in starts:
            continue
        ranges.extend(_intersect((begin, end), exec_ranges))
    return _merge_ranges(ranges)


def _intersect(span, exec_ranges):
    """The executable parts of [begin, end), in ascending order."""
    begin, end = span
    parts = []
    for low, high in exec_ranges:
        start, stop = max(begin, low), min(end, high)
        if start < stop:
            parts.append((start, stop))
    return parts


def _merge_ranges(ranges):
    """Union of [begin, end) ranges, ascending, with overlaps merged."""
    merged = []
    for begin, end in sorted(ranges):
        if merged and begin <= merged[-1][1]:
            if end > merged[-1][1]:
                merged[-1] = (merged[-1][0], end)
        else:
            merged.append((begin, end))
    return tuple(merged)


@dataclass(frozen=True)
class WatchResult:
    """One `watch_writes` run: the trace summary plus cleanup warnings.

    'summary' is `MemoryWatch.run()`'s own TraceSummary; `watched_facts` turns
    its ``mem_writes`` into the ``(rva, evidence)`` pairs `oep_candidates`
    accepts. 'warnings' is what ``disarm()`` reported — a target that exited
    during cleanup leaves "target exited during cleanup" here instead of it
    being dropped (ADR-0004: teardown failures go back to the caller).
    """

    summary: object
    warnings: tuple[str, ...] = ()


def watch_writes(dbg, addr, length=4, *, tid=None):
    """Watch one address range for writes, then disarm and return the result.

    The combination the caller would otherwise spell out: construct a
    `MemoryWatch`, ``arm()`` it, ``run()`` it, and ``disarm()`` it in a
    ``finally`` so a failed run cannot leave a hardware breakpoint behind.

    Returns:
        WatchResult: ``summary`` is `MemoryWatch.run()`'s own; ``events``
        counts writes recorded at ``addr`` (this is one address, so it is also
        the number of distinct hits), while ``blocks`` stays 0. ``warnings``
        carries ``disarm()``'s cleanup warnings, so a target that exited
        during cleanup is reported rather than swallowed.

    Known limits, all of them inherited from `MemoryWatch`:

    * **Writes only.** Windows's read/write condition cannot say which
      direction fired, so no read event is produced — a watch cannot tell an
      OEP that was *read* from one that was written.
    * **One address, 1/2/4/8 aligned bytes.** A page or region watch is not
      available; there is no guard-page monitoring anywhere in this package.
    * **Four debug-register slots, shared** with every other `MemoryWatch` and
      `FunctionProbe` in the process. A busy process makes ``arm()`` raise
      `BreakpointError` ("no free debug-register slot") rather than steal one.
    * **Arm at a normal stop.** Hardware breakpoints armed at the initial
      loader stop are dropped by the next continue; stop somewhere normal
      first (``tests.helpers.stop_at``), then arm. This wrapper arms
      immediately, so the caller owes it that stop.
    * ``run()`` can stop with ``single_step_pending``: the summary says so and
      the caller must continue that debug event before resuming the target.
      ``disarm()`` does not consume it.

    If ``run()`` raises, its exception propagates after the watch is disarmed;
    the cleanup warnings have no return value to ride on in that case.
    """
    # Imported here on purpose: `import pydbg.dump` is a cheap, extension-free
    # import today, and dragging the trace package in for a function nobody may
    # call would undo that.
    from ..trace.watch import MemoryWatch

    watch = MemoryWatch(dbg, addr, length, tid=tid)
    watch.arm()
    try:
        summary = watch.run()
    finally:
        warnings = watch.disarm()
    return WatchResult(summary=summary, warnings=warnings)


def watched_facts(summary, *, module_base):
    """Turn a memory watch summary into ``(rva, evidence)`` write facts.

    ``summary.mem_writes`` is `MemoryWatch.run()`'s (address, hit count) table;
    each entry becomes ``(address - module_base, "write@0x<address>x<count>")``,
    which is the "which address was written, and how often" fact §11.5
    promises. The caller supplies ``module_base`` because the summary records
    absolute addresses, exactly like the watch that produced them; the result
    feeds ``oep_candidates(..., watched=watched_facts(...))``.

    A summary with no recorded writes — a tracer that does not observe memory,
    or a watch that never fired — yields (). The output is ordered by
    ascending RVA, and duplicate addresses (which a single watch cannot
    produce) are summed rather than listed twice.
    """
    counts = {}
    for addr, count in getattr(summary, 'mem_writes', ()):
        rva = int(addr) - int(module_base)
        counts[rva] = counts.get(rva, 0) + int(count)
    return tuple(
        (rva, f"write@0x{rva + int(module_base):X}x{count}")
        for rva, count in sorted(counts.items()) if count)


@dataclass(frozen=True)
class OepCandidate:
    """One RVA that at least one OEP-hint query named.

    'sources' names where the facts came from: ``"tls"``, ``"pdata-gap"`` or
    ``"watched"``, in canonical order (tls, pdata-gap, watched). It is never
    empty. 'source' is a read-only property returning the first (canonical)
    source, for a caller that only wants one name.

    'evidence' is the facts themselves, as readable strings: a TLS callback's
    VA and RVA, the ``.pdata`` range whose begin was not recovered as a start,
    or the write observation `watched_facts` produces. There is deliberately no
    score, no probability and no "most likely" field — the aggregator is not
    allowed to have an opinion (spec §11.5).

    Raises:
        ValueError: 'sources' is empty.
    """

    rva: int
    sources: tuple[str, ...]
    evidence: tuple[str, ...] = ()

    def __post_init__(self):
        if isinstance(self.sources, str):
            sources = (self.sources,)
        else:
            sources = tuple(self.sources)
        if not sources:
            raise ValueError("OepCandidate needs at least one source")
        object.__setattr__(self, 'sources',
                           tuple(str(source) for source in sources))
        if isinstance(self.evidence, str):
            object.__setattr__(self, 'evidence', (self.evidence,))
        else:
            object.__setattr__(self, 'evidence', tuple(self.evidence))

    @property
    def source(self):
        """The first (canonical) source that named this RVA."""
        return self.sources[0]


def oep_candidates(pe_or_result, watched=()):
    """Every RVA named by TLS, ``.pdata``-gap or watched-write facts.

    The three fact sources are merged:

    * TLS callbacks from `tls_callbacks`, as ``"tls"``. The parser stores VAs,
      so the candidate RVA is the callback VA minus ``pe.va_base``.
    * ``.pdata`` ranges whose begin was never recovered as a function start,
      from `executable_ranges_outside_functions`, as ``"pdata-gap"``. Only an
      `AnalysisResult` (or an object shaped like one) can supply these; a bare
      `PE` has no recovered starts.
    * Caller-supplied write observations, as ``"watched"``. ``watched`` is a
      sequence of ``(rva, evidence)`` pairs, normally assembled by
      `watched_facts` from a `watch_writes` result's summary; the evidence is
      kept as a fact string.

    Candidates come back sorted by RVA and deduplicated: every fact about one
    RVA lands on one `OepCandidate`, with ``sources`` in canonical order and
    ``evidence`` in source order. Nothing beyond the RVA is ordered, scored or
    guessed — the caller decides what the facts mean. Empty input (no TLS
    callbacks, no ``.pdata`` gap, no watched writes) returns ().

    Args:
        pe_or_result: A `PE`, or an `AnalysisResult`-shaped object with
            ``.image.pe`` and ``.functions.starts``.
        watched: ``(rva, evidence)`` pairs from write observations.

    Raises:
        TypeError: neither a `PE` nor an object carrying ``.image.pe`` and
            ``.functions``.
        ValueError: from `tls_callbacks` when the PE's ``va_base`` cannot be
            the runtime base the callbacks were read against.
    """
    pe, result = _pe_and_result(pe_or_result)

    facts = {}
    for va in tls_callbacks(pe):
        rva = _callback_rva(pe, result, va)
        if rva is None:
            continue
        _add_fact(facts, rva, 'tls',
                  f"TLS callback VA 0x{va:X} at RVA 0x{rva:X}")

    if result is not None:
        for begin, end in executable_ranges_outside_functions(result):
            _add_fact(facts, begin, 'pdata-gap',
                      f".pdata range [0x{begin:X}, 0x{end:X}) begins where "
                      f"no function start was recovered")

    for rva, evidence in (() if watched is None else watched):
        _add_fact(facts, rva, 'watched', evidence)

    return _candidates(facts)


def _pe_and_result(pe_or_result):
    """Split the accepted inputs into (PE, result or None)."""
    if isinstance(pe_or_result, PE):
        return pe_or_result, None

    image = getattr(pe_or_result, 'image', None)
    functions = getattr(pe_or_result, 'functions', None)
    pe = getattr(image, 'pe', None)
    if pe is None or functions is None:
        raise TypeError(
            "oep_candidates expects a PE or an AnalysisResult-shaped object "
            "with .image.pe and .functions")
    return pe, pe_or_result


def _callback_rva(pe, result, va):
    """RVA of a TLS callback VA, or None when it is outside the image."""
    image = getattr(result, 'image', None) if result is not None else None
    convert = getattr(image, 'va_to_rva', None)
    if convert is not None:
        return convert(va)
    return va - pe.va_base


def _add_fact(facts, rva, source, evidence):
    """Record one fact under its RVA and source."""
    facts.setdefault(int(rva), {}).setdefault(source, []).append(str(evidence))


def _candidates(facts):
    """Turn the collected facts into sorted, deduplicated candidates."""
    candidates = []
    for rva in sorted(facts):
        by_source = facts[rva]
        sources = [source for source in _SOURCE_ORDER if source in by_source]
        evidence = tuple(dict.fromkeys(
            fact for source in sources for fact in by_source[source]))
        candidates.append(OepCandidate(rva, tuple(sources), evidence))
    return tuple(candidates)
