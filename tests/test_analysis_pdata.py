"""Tests for .pdata-backed function extents (spec §7.2(1)).

An x64 image's exception directory is the loader's own record of where every
function begins *and ends*. The analysis already seeded function starts from
the `begin_rva` half; these tests pin the other half, because an extent derived
from "the next function starts here" is a guess that happens to be wrong
whenever the linker pads or orders the functions differently.
"""

import unittest


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


if __name__ == "__main__":
    unittest.main()
