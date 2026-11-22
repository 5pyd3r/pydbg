"""Strings, per-section entropy, and packing hints.

These are the S8 facts that need no disassembly: what text an image contains,
where it sits, and the cheap signals that say the image may be packed. The
tests pin the two ways this goes quietly wrong — a UTF-16 string reported as
ASCII fragments, and an entropy number computed over the wrong bytes — because
both produce output that looks like a finding.
"""

import os
import unittest

from pydbg.analysis import section_entropy, strings_in_bytes
from pydbg.pe import PE

from tests.pe_builder import PEBuilder

TARGET_X64 = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "target", "simple_target_x64.exe")


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

    def test_mixed_encodings_do_not_overlap(self):
        """Every reported run is a different slice of the input.

        The UTF-16 string is fenced by non-NUL filler on purpose. A single NUL
        after an ASCII string is also the high byte of a UTF-16 character, so
        the two encodings are genuinely ambiguous there; the spec's
        UTF-16-first order settles it by joining, and this fixture avoids
        asserting an answer the spec leaves undefined.
        """
        data = (b"\x00hello\x00"
                + b"\x01\x02\x03"
                + "Wide".encode("utf-16-le")
                + b"\x01\x02\x03"
                + b"\x00world\x00")
        found = strings_in_bytes(data)
        self.assertEqual([(s.rva, s.encoding, s.text) for s in found],
                         [(1, "ascii", "hello"),
                          (10, "utf-16le", "Wide"),
                          (22, "ascii", "world")])
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


if __name__ == "__main__":
    unittest.main()
