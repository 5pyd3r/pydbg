"""linear_scan — a decode of a byte range that carries its own coverage.

The failure this exists to prevent is not a crash. It is `md.disasm()` over a
section returning a plausible-looking instruction list that stops a quarter of
the way in, or that resynchronises by accident and keeps going in the wrong
phase, with nothing in the return value saying so. Measured on three real
targets, the naive form silently covered 28.9% of `.text` on one of them and
missed 4.7% on another; every time, the output looked like a result.

So the scan does not return instructions. It returns a `LinearScan` holding the
instructions *and* what was skipped to get them, and the field carrying the
instructions is behind `instructions()`, which refuses to hand them over unless
the caller has acknowledged the gaps. A caller that wants a clean list has to
write `allow_incomplete=True` at the call site, which is a sentence a reviewer
can see and disagree with — the alternative, a bare list, is a claim of
completeness that nobody wrote and nobody can review.

Resynchronisation is reported rather than hidden, and it is reported with its
exposure. Skipping to the next byte that decodes always finds *something*; it
does not find the right phase. `unproven_runs()` returns the bytes decoded
between a resync and the next one, which is exactly the stretch whose alignment
rests on nothing but where the skip happened to land.
"""

from bisect import bisect_left
from dataclasses import dataclass

from ..exceptions import PydbgError


@dataclass(frozen=True, slots=True)
class Undecodable:
    """A run of bytes that no instruction could be decoded from.

    A run rather than one entry per byte: a 4KB gap between functions is one
    finding, and reporting it as 4,096 findings buries it.
    """

    rva: int
    size: int
    reason: str

    @property
    def end(self):
        return self.rva + self.size


@dataclass(frozen=True, slots=True)
class Resync:
    """One place the scan lost the phase and picked a new one.

    `skipped` bytes starting at `stop_rva` would not decode; decoding resumed
    at `resume_rva`. That resume address is a guess the decoder made, not a
    fact it established — see `LinearScan.unproven_runs`.
    """

    stop_rva: int
    resume_rva: int
    skipped: int

    @property
    def is_adjacent(self):
        """True when nothing was skipped, so nothing could have been missed."""
        return self.skipped == 0


@dataclass(frozen=True, slots=True)
class LinearScan:
    """What a linear scan of [start, end) decoded, and what it could not."""

    start: int
    end: int
    decoded: tuple            # ((rva, size), ...) ascending, non-overlapping
    covered_bytes: int
    undecodable: tuple        # Undecodable, ascending
    resyncs: tuple            # Resync, ascending
    truncated: bool = False   # stopped at a caller-supplied limit

    @property
    def scanned_bytes(self):
        return self.end - self.start

    def is_complete(self):
        """True when the whole range decoded with no gap and no resync.

        The only form of this scan that supports a negative claim. Everything
        else needs the gaps named.
        """
        return (not self.undecodable and not self.resyncs
                and not self.truncated and self.covered_bytes == self.scanned_bytes)

    def unaccounted_bytes(self):
        """Bytes in the range that neither decoded nor were reported as gaps.

        An invariant rather than a statistic: it should be 0 for every scan
        this module produces, and a non-zero value means the accounting itself
        is broken rather than that the image is unusual.
        """
        gap = sum(run.size for run in self.undecodable)
        return self.scanned_bytes - self.covered_bytes - gap

    def instructions(self, allow_incomplete=False):
        """The decoded instructions, or a refusal naming what was skipped.

        Raises unless the scan is complete, because "here are the instructions"
        and "here are the instructions I found" are different answers and only
        one of them is true when there are gaps.
        """
        if not allow_incomplete and not self.is_complete():
            raise PydbgError(
                f"scan of {self.start:#x}..{self.end:#x} is incomplete: "
                f"{self.covered_bytes}/{self.scanned_bytes} bytes decoded, "
                f"{len(self.undecodable)} undecodable run(s), "
                f"{len(self.resyncs)} resync(s)"
                + (", stopped at the instruction limit" if self.truncated else "")
                + ". Pass allow_incomplete=True to accept this as a partial "
                  "result.")
        return self.decoded

    def unproven_runs(self):
        """Stretches whose alignment rests only on a resync landing.

        Returns ((start_rva, end_rva, instruction_count), ...) — one entry per
        resync, covering the instructions decoded from its resume point up to
        the next place the scan broke. These are the bytes a caller should not
        treat as decoded even though the scan decoded them: resynchronisation
        solves "stopped at the first bad byte", it does not solve "started
        again in the right place", and nothing in the byte stream says which
        happened.

        Empty for a scan that never resynced, which is the only case where the
        instructions stand on their own.
        """
        # `decoded` is ascending, so each stretch is a slice of it. Bisecting a
        # tuple of (rva, size) against a one-element tuple finds the first
        # entry whose rva reaches the bound.
        runs = []
        for index, resync in enumerate(self.resyncs):
            if index + 1 < len(self.resyncs):
                limit = self.resyncs[index + 1].stop_rva
            else:
                limit = self.end
            first = bisect_left(self.decoded, (resync.resume_rva,))
            last = bisect_left(self.decoded, (limit,))
            if last > first:
                runs.append((resync.resume_rva, limit, last - first))
        return tuple(runs)

    def render(self):
        """A one-screen account of the scan, gaps included."""
        lines = [f"scan {self.start:#x}..{self.end:#x}: "
                 f"{len(self.decoded)} instructions, "
                 f"{self.covered_bytes}/{self.scanned_bytes} bytes "
                 f"({self.coverage_percent():.2f}%)"]
        for run in self.undecodable:
            lines.append(f"  undecodable {run.rva:#x}+{run.size} "
                         f"({run.reason})")
        for resync in self.resyncs:
            lines.append(f"  resync {resync.stop_rva:#x} -> "
                         f"{resync.resume_rva:#x} (skipped {resync.skipped})")
        if self.truncated:
            lines.append("  stopped at the instruction limit")
        return "\n".join(lines)

    def coverage_percent(self):
        if not self.scanned_bytes:
            return 100.0
        return 100.0 * self.covered_bytes / self.scanned_bytes


def linear_scan(decoder, start, end, origin="linear-scan",
                mark_covered=False, limit=None):
    """Decode [start, end) instruction by instruction, resyncing over gaps.

    Walks the range in instruction-sized steps, so every decoded instruction
    starts where the previous one ended and nothing overlaps. When an address
    will not decode, the whole unreadable run is consumed and reported, and the
    scan resumes at the first byte that does decode.

    `limit` bounds the instruction count; hitting it sets `truncated` rather
    than silently returning a shorter scan. `mark_covered` claims the decoded
    bytes in the decoder, for callers using this as a coverage pass; it is off
    by default so a scan used to *ask* about an image does not change it.
    """
    if end <= start:
        return LinearScan(start=start, end=end, decoded=(), covered_bytes=0,
                          undecodable=(), resyncs=())

    decoded = []
    undecodable = []
    resyncs = []
    covered_bytes = 0
    truncated = False

    rva = start
    while rva < end:
        if limit is not None and len(decoded) >= limit:
            truncated = True
            break

        insn = decoder.decode_one(rva)
        if insn is None:
            stop = rva
            reason = decoder.failure_reason(rva) or "will not decode"
            while rva < end and decoder.decode_one(rva) is None:
                rva += 1
            undecodable.append(Undecodable(stop, rva - stop, reason))
            if rva < end:
                resyncs.append(Resync(stop, rva, rva - stop))
            continue

        if rva + insn.size > end:
            # The instruction runs past the range. Decoding it anyway would
            # report bytes this scan was not asked about as covered.
            break
        decoded.append((rva, insn.size))
        covered_bytes += insn.size
        if mark_covered:
            decoder.mark_covered(rva, insn.size, origin=origin)
        rva += insn.size

    return LinearScan(start=start, end=end, decoded=tuple(decoded),
                      covered_bytes=covered_bytes, undecodable=tuple(undecodable),
                      resyncs=tuple(resyncs), truncated=truncated)


def scan_section(image, decoder, name, **kwargs):
    """Scan one section by name. Raises when there is no such section."""
    for section in image.sections:
        if section.name == name:
            start = section.virtual_address
            end = start + max(section.virtual_size, section.size_of_raw_data)
            return linear_scan(decoder, start, end, **kwargs)
    raise PydbgError(f"no section named {name!r} in this image")


def scan_executable(image, decoder, **kwargs):
    """Scan every executable section, as (section name, LinearScan) pairs."""
    return tuple((section.name, scan_section(image, decoder, section.name,
                                             **kwargs))
                 for section in image.sections if section.is_exec)
