"""Tests for linear_scan — the decode that reports its own coverage.

The behaviour under test is not "does it decode x86". It is whether a scan
that did *not* decode everything can be mistaken for one that did. Every test
here is written so that it fails when the scan goes back to returning a bare
list, because that is the shape of the defect: the numbers come out lower, or
the list comes out shorter, and nothing says so.
"""

import unittest

from tests.pe_builder import PEBuilder

IMAGE_BASE = 0x400000
TEXT_RVA = 0x1000

NOP = b"\x90"
RET = b"\xc3"


def gap(size):
    """'size' bytes that no instruction starts at, laid out to stay that way.

    Opcode 0xff with modrm 0xff selects group 5, /7 — no such instruction — so
    a run of 0xff bytes fails at every offset but the last: there the modrm
    comes from whatever follows the gap. The trailing 0x3f supplies a modrm
    that is invalid too (reg field 7), so the run really is 'size' long, and
    0x3f decodes on its own as `aas`, which gives the scan somewhere to resume.

    Without the guard the gap silently ends one byte early and the byte after
    it is swallowed into a six-byte `call` decoded out of `ff 90 90 90 90 90`.
    `TestTheFixture` pins both halves of that.
    """
    return b"\xff" * size + b"\x3f"


def build_text(code, entry_rva=TEXT_RVA):
    """A PE32 image whose .text is 'code' at RVA 0x1000."""
    builder = PEBuilder(magic=0x10B, image_base=IMAGE_BASE,
                        entry_rva=entry_rva)
    builder.add_section(".text", code, TEXT_RVA)
    return builder.build()


def analyze(code):
    from pydbg.analysis import analyze_bytes
    return analyze_bytes(build_text(code))


def rvas(scan, **kwargs):
    return [rva for rva, _size in scan.instructions(**kwargs)]


class TestTheFixture(unittest.TestCase):
    """The control for every other test in this file.

    If capstone ever learns to decode `ff ff`, the gap tests stop testing a
    gap — they would pass with the scan reporting no gap at all, which is the
    exact false negative this module exists to prevent. So the fixture asserts
    its own precondition rather than assuming it.
    """

    def test_the_gap_filler_really_is_undecodable(self):
        result = analyze(b"\xff" * 4)
        for offset in range(4):
            self.assertIsNone(result.decoder.decode_one(TEXT_RVA + offset),
                              f"0xff run decodes at offset {offset}")
        self.assertEqual(result.decoder.failure_reason(TEXT_RVA),
                         "disassembler produced nothing")

    def test_the_guard_byte_stops_the_last_gap_byte_from_decoding(self):
        """The mistake the guard exists to prevent, stated as a test."""
        ungarded = analyze(NOP * 4 + b"\xff" * 4 + NOP * 4 + RET)
        scan = ungarded.scan(TEXT_RVA, TEXT_RVA + 13)

        # One byte short of the gap, and the tail is a `call` — not a nop.
        self.assertEqual(scan.undecodable[0].size, 3)

        guarded = analyze(NOP * 4 + gap(4) + NOP * 4 + RET)
        scan = guarded.scan(TEXT_RVA, TEXT_RVA + 14)
        self.assertEqual(scan.undecodable[0].size, 4)

    def test_the_decodable_fixture_really_decodes(self):
        """The positive control for the same call."""
        result = analyze(NOP)
        self.assertIsNotNone(result.decoder.decode_one(TEXT_RVA))


class TestCleanScan(unittest.TestCase):
    def test_a_range_that_decodes_completely_is_complete(self):
        code = NOP * 8 + RET
        scan = analyze(code).scan(TEXT_RVA, TEXT_RVA + len(code))

        self.assertTrue(scan.is_complete())
        self.assertEqual(scan.undecodable, ())
        self.assertEqual(scan.resyncs, ())
        self.assertEqual(scan.unproven_runs(), ())
        self.assertEqual(scan.coverage_percent(), 100.0)

    def test_a_complete_scan_hands_over_its_instructions(self):
        code = NOP * 8 + RET
        scan = analyze(code).scan(TEXT_RVA, TEXT_RVA + len(code))

        instructions = scan.instructions()
        self.assertEqual(len(instructions), 9)
        self.assertEqual(instructions[0], (TEXT_RVA, 1))
        self.assertEqual(rvas(scan), list(range(TEXT_RVA, TEXT_RVA + 9)))

    def test_instructions_are_non_overlapping_and_cover_the_range(self):
        code = NOP * 4 + b"\x55\x8b\xec" + RET      # push ebp; mov ebp,esp; ret
        scan = analyze(code).scan(TEXT_RVA, TEXT_RVA + len(code))

        end = TEXT_RVA
        for rva, size in scan.instructions():
            self.assertEqual(rva, end)
            end += size
        self.assertEqual(end, TEXT_RVA + len(code))
        self.assertEqual(scan.covered_bytes, len(code))


class TestGapsAreReported(unittest.TestCase):
    def test_a_gap_makes_the_scan_incomplete(self):
        code = NOP * 4 + gap(4) + NOP * 4 + RET
        scan = analyze(code).scan(TEXT_RVA, TEXT_RVA + len(code))

        self.assertFalse(scan.is_complete())
        self.assertEqual(len(scan.undecodable), 1)
        self.assertEqual(scan.covered_bytes, len(code) - 4)

    def test_a_gap_is_one_run_not_one_entry_per_byte(self):
        """A 16-byte hole is one finding. Reporting 16 buries it."""
        code = NOP * 4 + gap(16) + NOP * 4 + RET
        scan = analyze(code).scan(TEXT_RVA, TEXT_RVA + len(code))

        runs = scan.undecodable
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0].rva, TEXT_RVA + 4)
        self.assertEqual(runs[0].size, 16)
        self.assertEqual(runs[0].end, TEXT_RVA + 20)

    def test_an_incomplete_scan_refuses_to_hand_over_instructions(self):
        from pydbg.exceptions import PydbgError

        code = NOP * 4 + gap(4) + NOP * 4 + RET      # 4 + 5 + 4 + 1
        scan = analyze(code).scan(TEXT_RVA, TEXT_RVA + len(code))

        with self.assertRaises(PydbgError) as caught:
            scan.instructions()
        message = str(caught.exception)
        # The refusal has to be actionable, or the caller's only move is to
        # give up rather than to decide the partial result is acceptable.
        self.assertIn("incomplete", message)
        self.assertIn("10/14", message)
        self.assertIn("allow_incomplete=True", message)

    def test_the_same_scan_hands_them_over_when_asked_explicitly(self):
        code = NOP * 4 + gap(4) + NOP * 4 + RET
        scan = analyze(code).scan(TEXT_RVA, TEXT_RVA + len(code))

        self.assertEqual(rvas(scan, allow_incomplete=True),
                         [TEXT_RVA + i for i in range(4)]
                         + [TEXT_RVA + 8 + i for i in range(6)])

    def test_an_unreadable_region_is_reported_as_a_gap_too(self):
        """Past the last section there is nothing to decode — also a gap."""
        code = NOP * 4
        scan = analyze(code).scan(TEXT_RVA, TEXT_RVA + 64)

        self.assertFalse(scan.is_complete())
        self.assertEqual(len(scan.undecodable), 1)
        self.assertEqual(scan.undecodable[0].reason,
                         "not in any mapped section")


class TestResyncExposure(unittest.TestCase):
    """Resynchronisation finds *a* phase, not necessarily the *right* one."""

    def test_resync_records_where_it_stopped_and_resumed(self):
        code = NOP * 4 + gap(4) + NOP * 4 + RET
        scan = analyze(code).scan(TEXT_RVA, TEXT_RVA + len(code))

        self.assertEqual(len(scan.resyncs), 1)
        resync = scan.resyncs[0]
        self.assertEqual(resync.stop_rva, TEXT_RVA + 4)
        self.assertEqual(resync.resume_rva, TEXT_RVA + 8)
        self.assertEqual(resync.skipped, 4)
        self.assertFalse(resync.is_adjacent)

    def test_bytes_decoded_after_a_resync_are_flagged_as_unproven(self):
        code = NOP * 4 + gap(4) + NOP * 4 + RET
        scan = analyze(code).scan(TEXT_RVA, TEXT_RVA + len(code))

        runs = scan.unproven_runs()
        self.assertEqual(len(runs), 1)
        start, end, count = runs[0]
        self.assertEqual(start, TEXT_RVA + 8)
        self.assertEqual(end, TEXT_RVA + len(code))
        self.assertEqual(count, 6)     # aas, 4 nops, ret

    def test_a_clean_scan_has_nothing_unproven(self):
        """The other half of the claim: no resync means no exposure."""
        code = NOP * 8 + RET
        scan = analyze(code).scan(TEXT_RVA, TEXT_RVA + len(code))

        self.assertEqual(scan.unproven_runs(), ())

    def test_two_gaps_give_two_exposures_not_one_long_one(self):
        code = NOP * 2 + gap(2) + NOP * 2 + gap(2) + NOP * 2
        scan = analyze(code).scan(TEXT_RVA, TEXT_RVA + len(code))

        self.assertEqual(len(scan.resyncs), 2)
        runs = scan.unproven_runs()
        self.assertEqual(len(runs), 2)
        # The first exposure ends where the second gap begins, so the two
        # stretches are not silently merged into one.
        self.assertEqual(runs[0][1], TEXT_RVA + 7)
        self.assertEqual(runs[1][0], TEXT_RVA + 9)


class TestAccounting(unittest.TestCase):
    def test_every_byte_is_accounted_for(self):
        cases = {
            "clean": (NOP * 8 + RET, 9),
            "one gap": (NOP * 4 + gap(4) + NOP * 4 + RET, 14),
            "two gaps": (NOP * 2 + gap(2) + NOP * 2 + gap(2) + NOP * 2, 12),
            "gap at the end of the range":
                (NOP * 4 + gap(4), 8),
        }
        for name, (code, scanned) in cases.items():
            with self.subTest(case=name):
                scan = analyze(code).scan(TEXT_RVA, TEXT_RVA + scanned)
                self.assertEqual(scan.unaccounted_bytes(), 0)
                self.assertEqual(
                    scan.covered_bytes
                    + sum(run.size for run in scan.undecodable),
                    scan.scanned_bytes)

    def test_a_gap_at_the_end_of_the_range_needs_no_resync(self):
        scan = analyze(NOP * 4 + gap(4)).scan(TEXT_RVA, TEXT_RVA + 8)

        self.assertEqual(len(scan.undecodable), 1)
        self.assertEqual(scan.resyncs, ())

    def test_a_truncated_scan_says_so_instead_of_stopping_quietly(self):
        code = NOP * 8 + RET
        scan = analyze(code).scan(TEXT_RVA, TEXT_RVA + len(code), limit=3)

        self.assertTrue(scan.truncated)
        self.assertFalse(scan.is_complete())
        self.assertEqual(len(scan.decoded), 3)
        self.assertLess(scan.coverage_percent(), 100.0)

    def test_a_truncated_scan_is_not_called_complete_even_though_it_hit_no_gap(self):
        """Truncation and cleanliness are independent, and both must be said."""
        scan = analyze(NOP * 8).scan(TEXT_RVA, TEXT_RVA + 8, limit=3)

        self.assertEqual(scan.undecodable, ())
        self.assertEqual(scan.resyncs, ())
        self.assertFalse(scan.is_complete())

    def test_coverage_is_measured_against_the_range_not_the_image(self):
        code = NOP * 8 + RET
        scan = analyze(code).scan(TEXT_RVA, TEXT_RVA + 4)

        self.assertEqual(scan.scanned_bytes, 4)
        self.assertEqual(scan.covered_bytes, 4)
        self.assertEqual(scan.coverage_percent(), 100.0)

    def test_an_empty_range_is_complete_rather_than_an_error(self):
        scan = analyze(NOP * 8).scan(TEXT_RVA, TEXT_RVA)

        self.assertEqual(scan.decoded, ())
        self.assertTrue(scan.is_complete())


class TestEntryPoints(unittest.TestCase):
    def test_scan_section_by_name(self):
        result = analyze(NOP * 8 + RET)
        scan = result.scan_section(".text")

        self.assertEqual(scan.start, TEXT_RVA)
        self.assertTrue(scan.is_complete())

    def test_an_unknown_section_raises_rather_than_returning_nothing(self):
        from pydbg.exceptions import PydbgError

        result = analyze(NOP * 8 + RET)
        with self.assertRaises(PydbgError):
            result.scan_section(".nope")

    def test_scan_text_returns_one_scan_per_executable_section(self):
        result = analyze(NOP * 8 + RET)
        scans = result.scan_text()

        self.assertEqual([name for name, _ in scans], [".text"])
        self.assertTrue(scans[0][1].is_complete())

    def test_marking_coverage_is_opt_in(self):
        """Asking about an image must not change it.

        The entry point returns immediately, so the sweep decodes byte 0x1000
        and nothing else; the range scanned below is one the run never reached,
        which is what makes the count attributable to the scan.
        """
        code = RET + NOP * 4 + gap(4) + NOP * 4 + RET
        region = (TEXT_RVA + 1, TEXT_RVA + 5)

        result = analyze(code)
        self.assertEqual(result.decoder.covered_in(*region), 0)
        result.scan(*region)
        self.assertEqual(result.decoder.covered_in(*region), 0)

    def test_a_scan_can_claim_the_bytes_it_decoded_when_asked(self):
        code = RET + NOP * 4 + gap(4) + NOP * 4 + RET
        region = (TEXT_RVA + 1, TEXT_RVA + 5)

        result = analyze(code)
        scan = result.scan(*region, mark_covered=True)

        self.assertTrue(scan.is_complete())
        self.assertEqual(result.decoder.covered_in(*region), 4)


class TestIndependenceFromTheSweep(unittest.TestCase):
    """A scan answers about a range the seed sweep may never have reached.

    The sweep follows seeds, so its silence about a region means the region was
    never queued — not that it was decoded and found empty. This pins the
    difference, because reading one as the other is how a coverage number gets
    quoted for a range nobody looked at.
    """

    def test_a_region_the_sweep_never_reached_still_scans(self):
        # The entry point returns immediately, so the sweep decodes 0x1000 and
        # stops. Everything after it is unreached but perfectly decodable.
        code = RET + NOP * 8 + RET
        result = analyze(code)
        scan = result.scan(TEXT_RVA + 1, TEXT_RVA + len(code))

        self.assertEqual(result.decoder.size_of(TEXT_RVA + 1), 0)
        self.assertTrue(scan.is_complete())
        self.assertEqual(len(scan.instructions()), 9)


if __name__ == "__main__":
    unittest.main()
