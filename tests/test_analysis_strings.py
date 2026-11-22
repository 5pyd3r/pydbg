"""Strings, per-section entropy, and packing hints.

These are the S8 facts that need no disassembly: what text an image contains,
where it sits, and the cheap signals that say the image may be packed. The
tests pin the two ways this goes quietly wrong — a UTF-16 string reported as
ASCII fragments, and an entropy number computed over the wrong bytes — because
both produce output that looks like a finding.
"""

import os
import unittest

from pydbg.analysis import strings_in_bytes

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


if __name__ == "__main__":
    unittest.main()
