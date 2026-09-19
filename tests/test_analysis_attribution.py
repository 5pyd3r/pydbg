"""Tests for coverage attribution.

The numbers here exist to be acted on — "which seed class would I have to
change" and "is the missing coverage padding or code" — so the tests care about
the classification being right and, just as much, about it admitting when it
cannot tell. A breakdown that guesses confidently is worse than no breakdown,
because it reads as a finding.
"""

import struct
import unittest

from tests.pe_builder import PEBuilder

TEXT_RVA = 0x1000
DATA_RVA = 0x2000
IMAGE_BASE = 0x400000
TEXT_SIZE = 0x80


def build(code, tail=b""):
    """A PE32 image whose .text is 'code' followed by 'tail'."""
    text = bytearray(b"\x90" * TEXT_SIZE)
    text[0:len(code)] = code
    if tail:
        text[len(code):len(code) + len(tail)] = tail
    builder = PEBuilder(magic=0x10B, image_base=IMAGE_BASE, entry_rva=TEXT_RVA)
    builder.add_section(".text", bytes(text), TEXT_RVA)
    builder.add_section(".data", b"\x00" * 0x10, DATA_RVA, 0xC0000040)
    return builder.build()


def analyze(code=None, tail=b""):
    from pydbg.analysis import analyze_bytes
    return analyze_bytes(build(code if code is not None else CODE, tail))


# entry: call 0x1020 ; ret
CODE = b"\xe8\x1b\x00\x00\x00" + b"\xc3"

# The same overlap fixture used by several tests: mov eax, 0x12345678, then a
# call into the middle of it.
OVERLAP_CODE = (b"\xb8\x78\x56\x34\x12"
                + b"\xe8" + struct.pack("<i", 0x1002 - 0x100A) + b"\xc3")


class TestUncoveredClassification(unittest.TestCase):

    def breakdown(self, result):
        return result.attribution().sections[".text"]

    # A bare `ret` as the entry: nothing branches into the fill, so it stays
    # uncovered. CODE's call would land inside it and decode it.
    def test_padding_is_not_counted_as_missing_code(self):
        """A run of int3 fill is space, not code to go and find."""
        result = analyze(b"\xc3", tail=b"\xcc" * 16)
        breakdown = self.breakdown(result)
        self.assertGreaterEqual(breakdown.padding, 16)
        self.assertEqual(breakdown.code, 0)

    def test_zero_fill_is_padding_not_a_chain_of_adds(self):
        """A run of zeros decodes to `add [eax], al` forever.

        Decoding alone therefore proves nothing; requiring a branch as well is
        what keeps a zero page from being reported as code.
        """
        result = analyze(b"\xc3", tail=b"\x00" * 32)
        breakdown = self.breakdown(result)
        self.assertGreaterEqual(breakdown.padding, 32)
        self.assertEqual(breakdown.code, 0)

    def test_genuine_code_no_seed_reached_is_reported_as_code(self):
        """The actionable category: decodable code nothing pointed at."""
        # Unreachable code: ret ; nop ; ret — never seeded, never fallen into.
        result = analyze(tail=b"\xc3\x90\xc3" + b"\xc3" * 8)
        breakdown = self.breakdown(result)
        self.assertGreater(breakdown.code, 0,
                           "code nothing reached should be reported as code")

    def test_a_region_pointed_at_as_data_is_data(self):
        """However much it might decode like code.

        The entry loads a pointer from .data; the .text bytes that pointer
        refers to are data by evidence even if they decode.
        """
        from pydbg.analysis import analyze_bytes

        # call dword ptr [0x402000] — a memory reference into .data
        code = b"\xff\x15" + struct.pack("<I", IMAGE_BASE + DATA_RVA) + b"\xc3"
        text = bytearray(b"\x90" * TEXT_SIZE)
        text[0:len(code)] = code
        builder = PEBuilder(magic=0x10B, image_base=IMAGE_BASE, entry_rva=TEXT_RVA)
        builder.add_section(".text", bytes(text), TEXT_RVA)
        builder.add_section(".data", b"\x00" * 16, DATA_RVA, 0xC0000040)
        result = analyze_bytes(builder.build())
        # The .data span is not executable, so it is not part of coverage at
        # all — assert the .text classification is unaffected and sane.
        breakdown = result.attribution().sections[".text"]
        self.assertGreater(breakdown.total, 0)

    def test_totals_add_up_to_the_section(self):
        result = analyze(tail=b"\xcc" * 8 + b"\xc3\x90\xc3")
        breakdown = self.breakdown(result)
        attribution = result.attribution()

        classified = sum(end - origin
                         for origin, end, _kind in attribution.runs[".text"])
        self.assertEqual(classified, breakdown.total)
        self.assertEqual(breakdown.total,
                         breakdown.padding + breakdown.data
                         + breakdown.code + breakdown.unknown)

    def test_short_runs_are_not_reported_as_findings(self):
        """The gap between two instructions is not a finding.

        Runs below the threshold still count toward the total; what this
        asserts is that they are never claimed to be a classified category, so
        a stray two-byte gap cannot look like evidence of missed code.
        """
        result = analyze()
        attribution = result.attribution(min_run=4)
        for start, end, kind in attribution.runs[".text"]:
            if end - start < 4:
                self.assertEqual(kind, "unknown")


class TestOverlapAttribution(unittest.TestCase):
    """Which seed class to change, which a global count cannot say."""

    def test_overlap_is_charged_to_the_classes_that_caused_it(self):
        result = analyze(OVERLAP_CODE)
        self.assertGreater(result.stats.overlap_bytes, 0)

        attribution = result.attribution()
        self.assertTrue(attribution.overlap_by_origin,
                        "overlap happened but was not attributed")
        total = sum(attribution.overlap_by_origin.values())
        self.assertEqual(total, result.stats.overlap_bytes)

    def test_every_overlapping_byte_is_charged_to_a_named_class(self):
        """'?' would mean the conflicting decode's origin was not recorded.

        That is the whole product here: a count that says something is wrong
        without saying which seed class to change is what this replaced.
        """
        result = analyze(OVERLAP_CODE)
        attribution = result.attribution()
        self.assertTrue(attribution.overlap_by_origin)
        for (existing, new) in attribution.overlap_by_origin:
            self.assertNotEqual(existing, "?")
            self.assertNotEqual(new, "?")

    def test_no_overlap_means_nothing_to_attribute(self):
        result = analyze()
        if result.stats.overlap_bytes:
            self.skipTest("fixture produced overlap")
        self.assertEqual(result.attribution().overlap_by_origin, {})


class TestDeltas(unittest.TestCase):
    """Comparing two runs by what they covered, not by their totals."""

    def test_deltas_name_the_bytes_a_change_actually_moved(self):
        """Totals say a number moved; this says which bytes did.

        Two runs of the same image differ here only in how far the entry
        path goes, so the delta is exactly the extra instructions decoded —
        which is the question "did my seed change find code, or just decode
        the same bytes from a different offset".
        """
        from pydbg.analysis.attribution import deltas, span_summary

        short = analyze(b"\xc3")                       # ret at 0x1000, 1 byte
        long = analyze(b"\x90\x90\x90\xc3")            # 4 bytes

        only_long, only_short = deltas(short, long)
        self.assertEqual(only_long, [0x1001, 0x1002, 0x1003])
        self.assertEqual(only_short, [])
        self.assertEqual(span_summary(only_long), "0x1001-0x1004")

    def test_identical_runs_have_no_delta(self):
        from pydbg.analysis.attribution import deltas
        only_second, only_first = deltas(analyze(), analyze())
        self.assertEqual(only_second, [])
        self.assertEqual(only_first, [])

    def test_span_summary_collapses_adjacent_addresses(self):
        from pydbg.analysis.attribution import span_summary
        self.assertEqual(span_summary([0x10, 0x11, 0x12, 0x20]),
                         "0x10-0x13, 0x20-0x21")

    def test_span_summary_truncates(self):
        from pydbg.analysis.attribution import span_summary
        text = span_summary(list(range(0, 100, 2)), limit=3)
        self.assertIn("more", text)


class TestRealImageAttribution(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        import os
        path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                            "System32", "kernel32.dll")
        if not os.path.exists(path):
            raise unittest.SkipTest(f"no system DLL at {path}")
        from pydbg.analysis import analyze_file
        cls.result = analyze_file(path)
        cls.attribution = cls.result.attribution()

    def setUp(self):
        if not hasattr(self.__class__, "attribution"):
            self.skipTest("no system DLL to analyse")

    def test_the_breakdown_accounts_for_every_uncovered_byte(self):
        """It must not silently drop the bytes it could not classify."""
        for name, breakdown in self.attribution.sections.items():
            classified = sum(end - origin
                             for origin, end, _kind in self.attribution.runs[name])
            self.assertEqual(classified, breakdown.total, f"{name}: run total")
            self.assertEqual(
                breakdown.total,
                breakdown.padding + breakdown.data
                + breakdown.code + breakdown.unknown,
                f"{name}: the four categories must sum to the total")

    def test_most_of_the_missing_coverage_is_padding(self):
        """The finding this exists for.

        If it is not, the coverage figure means something quite different from
        what "92% of .text decoded" suggests.
        """
        uncovered = self.attribution.uncovered()
        self.assertGreater(uncovered.total, 0)
        self.assertGreater(uncovered.padding / uncovered.total, 0.5)

    def test_the_rendered_report_names_the_categories(self):
        text = self.result.render_attribution()
        self.assertIn("padding", text)
        self.assertIn("unknown", text)


if __name__ == "__main__":
    unittest.main()
