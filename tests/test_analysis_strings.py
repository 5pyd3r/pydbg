"""Strings, per-section entropy, and packing hints.

These are the S8 facts that need no disassembly: what text an image contains,
where it sits, and the cheap signals that say the image may be packed. The
tests pin the two ways this goes quietly wrong — a UTF-16 string reported as
ASCII fragments, and an entropy number computed over the wrong bytes — because
both produce output that looks like a finding.
"""

import os
import struct
import unittest

from pydbg.analysis import (
    extract_strings, packing_hints, section_entropy, strings_in_bytes,
)
from pydbg.pe import PE

from tests.pe_builder import PEBuilder, build_loaded_image_with_one_import

TARGET_X64 = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "target", "simple_target_x64.exe")


def widen_virtual_size(image, index, virtual_size):
    """Give one section a virtual-only tail in an already-built image.

    PEBuilder derives both size fields from the data, so a section whose
    virtual_size exceeds size_of_raw_data — the uninitialised-tail shape — has
    to be introduced after the fact.
    """
    image = bytearray(image)
    e_lfanew = struct.unpack_from("<I", image, 0x3C)[0]
    optional_size = struct.unpack_from("<H", image, e_lfanew + 20)[0]
    header = e_lfanew + 24 + optional_size + index * 40
    struct.pack_into("<I", image, header + 8, virtual_size)
    return bytes(image)


class TestStringsInBytes(unittest.TestCase):
    """Extraction from a bare byte blob, with no PE in the way."""

    def test_printable_runs_become_strings_at_their_offset(self):
        """The RVA is where the run starts, not where the blob does."""
        found = strings_in_bytes(b"\x00hello\x00world\x00")
        self.assertEqual([(s.rva, s.encoding, s.text) for s in found],
                         [(1, "ascii", "hello"), (7, "ascii", "world")])

    def test_a_run_shorter_than_min_length_is_dropped(self):
        """The threshold is in characters, so 'abc' is not a string at 4."""
        found = strings_in_bytes(b"\x00abc\x00abcd", min_length=4)
        self.assertEqual([s.text for s in found], ["abcd"])

    def test_base_rva_is_added_to_each_offset(self):
        found = strings_in_bytes(b"\x00hello", base_rva=0x1000)
        self.assertEqual(found[0].rva, 0x1001)

    def test_a_utf16_string_is_one_finding_not_ascii_fragments(self):
        """The UTF-16 pass claims its bytes before ASCII looks at anything.

        Scanning ASCII first turns "Hello" in UTF-16LE into five
        one-character runs, which the threshold drops; scanning both
        independently reports five ASCII fragments and a UTF-16 string over
        the same bytes.
        """
        found = strings_in_bytes("Hello".encode("utf-16-le"))
        self.assertEqual([(s.rva, s.encoding, s.text) for s in found],
                         [(0, "utf-16le", "Hello")])

    def test_utf16_min_length_counts_characters_not_bytes(self):
        data = "Hello".encode("utf-16-le")
        self.assertEqual([s.text for s in strings_in_bytes(data, min_length=5)],
                         ["Hello"])
        self.assertEqual(strings_in_bytes(data, min_length=6), [])

    def test_a_utf16_run_cannot_start_inside_an_ascii_run(self):
        """The NUL terminating an ASCII string is a valid UTF-16 high byte.

        Without a boundary rule the last character of "hello\\0" is read as
        the first of the following UTF-16 run, yielding "hell" + "oWide"
        over the same bytes.
        """
        found = strings_in_bytes(b"hello\x00" + "Wide".encode("utf-16-le"))
        self.assertEqual([(s.rva, s.encoding, s.text) for s in found],
                         [(0, "ascii", "hello"), (6, "utf-16le", "Wide")])

    def test_a_utf16_run_may_start_after_a_non_printable_byte(self):
        found = strings_in_bytes(b"\x00" + "Wide".encode("utf-16-le"))
        self.assertEqual([(s.rva, s.encoding, s.text) for s in found],
                         [(1, "utf-16le", "Wide")])

    def test_mixed_encodings_do_not_overlap(self):
        """Every reported run is a different slice of the input.

        Offsets are spelled out so a scan that claims the wrong bytes fails
        here rather than producing a plausible-looking list.
        """
        data = (b"\x00hello\x00"
                + "Wide".encode("utf-16-le")
                + b"\x00\x01\x02"
                + b"\x00world\x00")
        found = strings_in_bytes(data)
        self.assertEqual([(s.rva, s.encoding, s.text) for s in found],
                         [(1, "ascii", "hello"),
                          (7, "utf-16le", "Wide"),
                          (19, "ascii", "world")])
        spans = [(s.rva, s.rva + len(s.text) *
                  (2 if s.encoding == "utf-16le" else 1))
                 for s in found]
        for (_start, end), (next_start, _next_end) in zip(spans, spans[1:]):
            self.assertLessEqual(end, next_start, "reported runs overlap")


class TestSectionEntropy(unittest.TestCase):
    """Entropy is a claim about one section's bytes, so size travels with it."""

    def entropy_of(self, data, name=".data"):
        builder = PEBuilder(magic=0x10B, image_base=0x400000)
        builder.add_section(name, data, 0x1000)
        return section_entropy(PE(builder.build()))[0]

    def test_one_repeated_byte_is_zero_entropy(self):
        """Both all-zero and all-'A' are legitimately zero, not a failure."""
        self.assertEqual(self.entropy_of(b"\x00" * 4096).entropy, 0.0)
        self.assertEqual(self.entropy_of(b"A" * 4096).entropy, 0.0)

    def test_a_uniform_byte_distribution_is_eight_bits(self):
        found = self.entropy_of(bytes(range(256)))
        self.assertAlmostEqual(found.entropy, 8.0, delta=1e-9)

    def test_every_section_is_reported_in_table_order(self):
        """A section missing from the list is indistinguishable from a clean
        one, so unreadable sections still appear, at 0.0 with size 0."""
        builder = PEBuilder(magic=0x10B, image_base=0x400000)
        builder.add_section(".zero", b"\x00" * 256, 0x1000)
        builder.add_section(".flat", bytes(range(256)), 0x2000)
        builder.add_section(".same", b"A" * 4096, 0x3000)
        builder.add_section(".empty", b"", 0x4000)
        found = section_entropy(PE(builder.build()))

        self.assertEqual([s.name for s in found],
                         [".zero", ".flat", ".same", ".empty"])
        self.assertEqual([s.size for s in found], [256, 256, 4096, 0])
        self.assertEqual(found[0].entropy, 0.0)
        self.assertAlmostEqual(found[1].entropy, 8.0, delta=1e-9)
        self.assertEqual(found[2].entropy, 0.0)
        self.assertEqual(found[3].entropy, 0.0)

    def test_a_truncated_section_is_zero_rather_than_an_exception(self):
        builder = PEBuilder(magic=0x10B, image_base=0x400000)
        builder.add_section(".text", b"\x00hello\x00", 0x1000)
        found = section_entropy(PE(builder.build()[:-1]))
        self.assertEqual([(s.name, s.entropy, s.size) for s in found],
                         [(".text", 0.0, 0)])

    def test_a_virtual_only_tail_does_not_hide_the_raw_bytes(self):
        """FileView refuses a read that runs past size_of_raw_data.

        Asking for the whole span would report 0.0 for a section whose
        file-backed prefix is readable, which reads as "no entropy here"
        rather than "most of this section was not measured".
        """
        builder = PEBuilder(magic=0x20B, image_base=0x140000000)
        builder.add_section(".data", bytes(range(256)), 0x1000)
        pe = PE(widen_virtual_size(builder.build(), 0, 0x8000))
        found = section_entropy(pe)
        self.assertEqual([(s.name, s.size) for s in found], [(".data", 256)])
        self.assertAlmostEqual(found[0].entropy, 8.0, delta=1e-9)


class TestPackingHints(unittest.TestCase):
    """Cheap evidence, reported as separate facts rather than a verdict.

    Each signal is individually weak and individually meaningful: a section
    that is both writable and executable is suspicious without any entropy
    story, and a high-entropy section is unremarkable in some legitimate
    images. Folding them into one "packed: yes" would throw that away.
    """

    def build(self, sections):
        builder = PEBuilder(magic=0x10B, image_base=0x400000)
        rva = 0x1000
        for name, data, characteristics in sections:
            builder.add_section(name, data, rva, characteristics)
            rva += 0x1000
        return PE(builder.build())

    def test_writable_executable_and_high_entropy_sections_are_reported(self):
        pe = self.build([
            (".text", b"\x90" * 0x100, 0x60000020),
            (".wx", bytes(range(256)) * 8, 0xE0000020),
            ("UPX0", b"\x00" * 0x100, 0x40000040),
        ])
        hints = packing_hints(pe)
        self.assertEqual(hints.high_entropy_sections, [".wx"])
        self.assertEqual(hints.write_exec_sections, [".wx"])
        self.assertEqual(hints.suspicious_section_names, ["UPX0"])
        self.assertTrue(hints.low_import_count)

    def test_plain_sections_raise_no_packing_signal(self):
        """A normal image must not look packed merely for existing."""
        pe = self.build([
            (".text", b"\x90" * 0x100, 0x60000020),
            (".rdata", b"\x00" * 0x200, 0x40000040),
        ])
        hints = packing_hints(pe)
        self.assertEqual(hints.high_entropy_sections, [])
        self.assertEqual(hints.write_exec_sections, [])
        self.assertEqual(hints.suspicious_section_names, [])

    def test_suspicious_names_match_case_insensitively(self):
        pe = self.build([
            (".text", b"\x90" * 0x100, 0x60000020),
            ("UPX0", b"\x00" * 0x10, 0x40000040),
            (".Themida", b"\x00" * 0x10, 0x40000040),
        ])
        self.assertEqual(packing_hints(pe).suspicious_section_names,
                         ["UPX0", ".Themida"])

    def test_the_thresholds_are_arguments(self):
        pe = self.build([(".flat", bytes(range(256)), 0x60000020)])
        self.assertEqual(
            packing_hints(pe, entropy_threshold=8.5).high_entropy_sections, [])

    def test_import_count_is_compared_with_the_threshold(self):
        image, _iat = build_loaded_image_with_one_import()
        pe = PE(image)
        self.assertEqual(len(pe.imports), 1)
        self.assertTrue(packing_hints(pe).low_import_count)
        self.assertFalse(
            packing_hints(pe, low_import_threshold=1).low_import_count)


class TestExtractStrings(unittest.TestCase):
    """Walking a PE's sections, where addresses become RVAs for real."""

    def build(self):
        builder = PEBuilder(magic=0x10B, image_base=0x400000)
        builder.add_section(".text", b"\x00hello\x00", 0x1000)
        builder.add_section(".rdata", b"\x00world\x00", 0x2000)
        return PE(builder.build())

    def test_every_section_is_searched_by_default(self):
        found = extract_strings(self.build())
        self.assertEqual([(s.rva, s.text) for s in found],
                         [(0x1001, "hello"), (0x2001, "world")])

    def test_a_named_subset_limits_the_search(self):
        pe = self.build()
        self.assertEqual(
            [s.text for s in extract_strings(pe, sections=[".rdata"])],
            ["world"])
        self.assertEqual(extract_strings(pe, sections=[".missing"]), [])

    def test_min_length_reaches_the_per_section_scan(self):
        self.assertEqual(extract_strings(self.build(), min_length=6), [])

    def test_results_are_in_address_order_not_section_order(self):
        """The section table is not a promise about RVAs; the output is."""
        builder = PEBuilder(magic=0x10B, image_base=0x400000)
        builder.add_section(".late", b"\x00late\x00", 0x3000)
        builder.add_section(".early", b"\x00early\x00", 0x1000)
        found = extract_strings(PE(builder.build()))
        self.assertEqual([s.text for s in found], ["early", "late"])
        self.assertEqual([s.rva for s in found], [0x1001, 0x3001])

    def test_an_unreadable_section_is_skipped_rather_than_raised(self):
        builder = PEBuilder(magic=0x10B, image_base=0x400000)
        builder.add_section(".text", b"\x00hello\x00", 0x1000)
        pe = PE(builder.build()[:-1])
        self.assertEqual(extract_strings(pe), [])

    def test_a_virtual_only_tail_still_yields_its_strings(self):
        builder = PEBuilder(magic=0x20B, image_base=0x140000000)
        builder.add_section(".data", b"\x00hello\x00", 0x1000)
        pe = PE(widen_virtual_size(builder.build(), 0, 0x8000))
        self.assertEqual([(s.rva, s.text) for s in extract_strings(pe)],
                         [(0x1001, "hello")])

    @unittest.skipUnless(
        os.path.exists(TARGET_X64),
        "target not built: tests/target/simple_target_x64.exe")
    def test_every_string_on_a_real_image_lands_in_a_section(self):
        """The RVA is usable only if it points back into the image."""
        pe = PE.from_file(TARGET_X64)
        found = extract_strings(pe)
        self.assertGreaterEqual(len(found), 1)
        ranges = [(section.virtual_address,
                   section.virtual_address + section.span)
                  for section in pe.sections]
        for string in found:
            self.assertIn(string.encoding, ("ascii", "utf-16le"))
            self.assertTrue(
                any(start <= string.rva < end for start, end in ranges),
                f"{string.text!r} at {string.rva:#x} is outside every section")


class TestDegenerateInput(unittest.TestCase):
    """Malformed input is ordinary here, so every entry point has an answer.

    A scanner that raises on a truncated section turns a bad sample into a
    crashed run; a scanner that returns an empty list says what it could not
    read.
    """

    def test_no_printable_bytes_yields_nothing(self):
        self.assertEqual(strings_in_bytes(b"\x00\x01\x02\x03"), [])
        self.assertEqual(strings_in_bytes(b""), [])

    def test_min_length_one_keeps_single_characters(self):
        self.assertEqual([s.text for s in strings_in_bytes(b"A", min_length=1)],
                         ["A"])
        self.assertEqual(
            [s.text for s in strings_in_bytes(b"A\x00", min_length=1)],
            ["A"])

    def test_an_image_with_no_sections_has_no_entropy_rows(self):
        self.assertEqual(section_entropy(PE(PEBuilder().build())), [])

    def test_hints_on_a_truncated_image_are_all_negative_but_the_imports(self):
        builder = PEBuilder(magic=0x10B, image_base=0x400000)
        builder.add_section(".text", b"\x90" * 0x100, 0x60000020)
        hints = packing_hints(PE(builder.build()[:-1]))
        self.assertEqual(hints.high_entropy_sections, [])
        self.assertEqual(hints.write_exec_sections, [])
        self.assertEqual(hints.suspicious_section_names, [])
        self.assertTrue(hints.low_import_count)


if __name__ == "__main__":
    unittest.main()
