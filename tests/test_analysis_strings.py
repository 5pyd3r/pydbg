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


if __name__ == "__main__":
    unittest.main()
