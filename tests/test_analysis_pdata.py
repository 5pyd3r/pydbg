"""Tests for .pdata-backed function extents (spec §7.2(1)).

An x64 image's exception directory is the loader's own record of where every
function begins *and ends*. The analysis already seeded function starts from
the `begin_rva` half; these tests pin the other half, because an extent derived
from "the next function starts here" is a guess that happens to be wrong
whenever the linker pads or orders the functions differently.
"""

import struct
import unittest

from tests.pe_builder import PEBuilder

IMAGE_BASE = 0x140000000
TEXT_RVA = 0x1000
PDATA_RVA = 0x2000


class TestExactExtents(unittest.TestCase):
    """`FunctionTable.set_exact_extents` — an exact range beats the heuristic."""

    def test_an_exact_extent_is_not_cut_off_by_the_next_start(self):
        """The old rule stops at the next start; the loader's end does not.

        A function whose decode runs up to the next entry would be reported as
        0x50 bytes wide here. `.pdata` says it ends at 0x1030, and that is the
        authoritative answer: the gap between 0x1030 and 0x1050 is padding, not
        function body.
        """
        from pydbg.analysis.functions import FunctionTable

        table = FunctionTable()
        table.add_start(0x1000, confident=True)
        table.add_start(0x1050, confident=True)
        # The sweep decodes straight through the padding and past 0x1050.
        table.note_instruction(0x1000, 0x50)
        table.note_instruction(0x1050, 0x50)
        table.set_exact_extents({0x1000: 0x30})
        table.invalidate()

        self.assertEqual(table.extent_of(0x1000), 0x30)
        self.assertEqual(table.extent_of(0x1050), 0x50,
                         "a start with no exact range keeps the old rule")

    def test_a_negative_size_falls_back_to_the_old_rule(self):
        """A nonsense record describes no function; it must not truncate one."""
        from pydbg.analysis.functions import FunctionTable

        table = FunctionTable()
        table.add_start(0x1000, confident=True)
        table.note_instruction(0x1000, 0x20)
        table.set_exact_extents({0x1000: -4})

        self.assertEqual(table.extent_of(0x1000), 0x20)

    def test_invalidate_keeps_the_exact_table(self):
        """The sweep invalidates after pruning starts; `.pdata` is not derived.

        Losing the exact ranges there would silently return the analysis to
        the "next start" guess after the sweep had already been told the truth.
        """
        from pydbg.analysis.functions import FunctionTable

        table = FunctionTable()
        table.add_start(0x1000, confident=True)
        table.set_exact_extents({0x1000: 0x30})
        self.assertEqual(table.extent_of(0x1000), 0x30)

        table.invalidate()
        self.assertEqual(table.extent_of(0x1000), 0x30)

    def test_an_exact_range_for_an_unknown_start_invents_nothing(self):
        """A record whose begin the analysis never decoded is not a function."""
        from pydbg.analysis.functions import FunctionTable

        table = FunctionTable()
        table.add_start(0x1000, confident=True)
        table.set_exact_extents({0x2000: 0x30})

        self.assertNotIn(0x2000, table.starts)
        self.assertNotIn(0x2000, table.extents())


def build_text():
    """Code from 0x1000 through 0x1090, with two functions the sweep reaches.

    0x1000 is the entry point and its first instruction calls 0x1050, so both
    are function starts whether or not `.pdata` seeds them — which is what
    makes an image with the directory removed comparable to one with it.

    0x1000..0x104F  A's body, continuing into padding
    0x1050..0x108F  B's body
    0x1090          ret
    """
    code = b"\xe8" + struct.pack("<i", 0x4B)     # call 0x1050
    code += b"\x90" * 0x4B                       # 0x1005..0x104F
    code += b"\x90" * 0x40                       # 0x1050..0x108F
    code += b"\xc3"                              # 0x1090
    return code


def pdata_image(entries, with_directory=True, code=None):
    """A PE32+ whose .pdata holds the given (begin, end) RUNTIME_FUNCTIONs.

    The .pdata section sits at 0x2000 and is not executable, so a record that
    begins there exercises "a begin outside code" without the seed reader
    having to reject a mapped address.
    """
    builder = PEBuilder(magic=0x20B, image_base=IMAGE_BASE,
                        entry_rva=TEXT_RVA)
    builder.add_section(".text", build_text() if code is None else code,
                        TEXT_RVA)
    payload = b"".join(struct.pack("<III", begin, end, 0)
                       for begin, end in entries)
    builder.add_section(".pdata", payload, PDATA_RVA, 0x40000040)
    if with_directory:
        builder.add_dir(3, PDATA_RVA, len(payload))
    return builder.build()


class TestPdataExtents(unittest.TestCase):
    """The analyzer feeds `.pdata` ends into the function table."""

    def analyze(self, entries, with_directory=True, code=None):
        from pydbg.analysis import analyze_bytes
        return analyze_bytes(pdata_image(entries, with_directory, code))

    def test_pdata_ends_beat_the_next_start(self):
        """A: [0x1000, 0x1030), next start 0x1050 → 0x30, not 0x50.

        The sweep decodes straight from A's body through B's and stops at the
        ret at 0x1090, so the old rule reports 0x50 for A and 0x41 for B.
        """
        result = self.analyze([(0x1000, 0x1030), (0x1050, 0x1080)])

        self.assertEqual(result.functions.extent_of(0x1000), 0x30)
        self.assertEqual(result.functions.extent_of(0x1050), 0x30,
                         "B has no next start; its decode still overshoots")

    def test_without_the_directory_the_old_extents_are_unchanged(self):
        """Directory 3 deleted: every extent equals its pre-.pdata value.

        0x1000 runs to the next start 0x1050 (0x50 bytes); 0x1050 runs to the
        end of decoded bytes, the ret at 0x1090 plus its own byte (0x41).
        Both numbers come from the fixture, not from running the old code.
        """
        result = self.analyze([(0x1000, 0x1030), (0x1050, 0x1080)],
                              with_directory=False)

        self.assertEqual(result.functions.extents(),
                         {0x1000: 0x50, 0x1050: 0x41})

    def test_a_begin_that_was_never_decoded_is_not_a_function(self):
        """A record with begin 0x2000 in .pdata invents no function there.

        0x2000 is the .pdata section itself, which is not executable, so no
        seed reaches it. The exact range must not turn a table entry into a
        function on its own.
        """
        result = self.analyze([(0x2000, 0x2030)])

        self.assertNotIn(0x2000, result.functions.starts)
        self.assertNotIn(0x2000, result.functions.extents())

    def test_records_that_end_at_or_before_begin_are_ignored(self):
        """A record that cannot describe a range must not shrink a function.

        The text is 0x11 bytes of decoded code; a fallback to the old rule
        therefore reports 0x11. Applying `end - begin` literally would report
        0, and a negative value would remove the function's extent entirely.
        """
        text = b"\x90" * 0x10 + b"\xc3"       # 0x1000..0x1010

        for end in (0x1000, 0x0F00):
            with self.subTest(end=end):
                result = self.analyze([(0x1000, end)], code=text)
                self.assertEqual(result.functions.extent_of(0x1000), 0x11)


if __name__ == "__main__":
    unittest.main()
