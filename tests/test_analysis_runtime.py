"""Tests for the CFG, the text reports, and analysing a live module.

The live-process case is the one that cannot be checked by reading: a module
under ASLR is not at the base its own header claims, so an analyzer that
translates addresses against the preferred base finds nothing and reports
success. Only running it against a real process distinguishes the two.
"""

import unittest

from tests.pe_builder import PEBuilder

TEXT_RVA = 0x1000
IMAGE_BASE = 0x400000


def build_image(code):
    builder = PEBuilder(magic=0x10B, image_base=IMAGE_BASE,
                        entry_rva=TEXT_RVA)
    builder.add_section(".text", code, TEXT_RVA)
    return builder.build()


def analyze(code):
    from pydbg.analysis import analyze_bytes
    return analyze_bytes(build_image(code))


RET = b"\xc3"
NOP = b"\x90"

# A small function with one conditional branch. The byte before the branch
# target is deliberately NOT padding (0x55), so the target is not mistaken for
# a function entry — otherwise the analyzer splits it off and there is no
# single function left to build a CFG over.
#
#   0x1000: test eax, eax   (85 c0)
#   0x1002: jne 0x1009      (75 05)  -> target 0x1009, fallthrough 0x1004
#   0x1004: ret
#   0x1005: filler ... 0x1008: 55 (unreachable)
#   0x1009: ret
BRANCHED = b"\x85\xc0\x75\x05" + RET + b"\xcc\x90\x90\x55" + RET
BRANCH_TARGET = 0x1009
FALLTHROUGH = 0x1004


class TestFunctionCFG(unittest.TestCase):

    def cfg_of(self, code, rva=TEXT_RVA):
        return analyze(code).cfg_of(rva)

    def test_conditional_branch_yields_two_successors(self):
        cfg = self.cfg_of(BRANCHED)
        entry = cfg.blocks[TEXT_RVA]
        kinds = {kind for kind, _ in entry.successors}
        self.assertEqual(kinds, {"jcc", "fall"})
        self.assertIn(("jcc", BRANCH_TARGET), entry.successors)
        self.assertIn(("fall", FALLTHROUGH), entry.successors)
        self.assertTrue(cfg.complete)
        self.assertEqual(cfg.unresolved(), ())

    def test_an_unresolved_branch_is_named_not_dropped(self):
        """`jmp eax` has no static target, and saying so is the point.

        Dropping the edge leaves a function that looks like it simply ends
        there, which reads as complete.
        """
        from pydbg.analysis.cfg import INDIRECT
        # 0x1000: jmp eax (ff e0)
        cfg = self.cfg_of(b"\xff\xe0")
        self.assertFalse(cfg.complete)
        self.assertEqual(cfg.blocks[TEXT_RVA].successors, ((INDIRECT, None),))
        self.assertEqual(cfg.unresolved(), ((TEXT_RVA, INDIRECT),))

    def test_ret_is_a_terminal_that_does_not_make_the_graph_incomplete(self):
        """We know a ret returns — that is resolved, not unknown."""
        cfg = self.cfg_of(RET)
        self.assertTrue(cfg.complete)
        self.assertEqual(cfg.unresolved(), ())

    def test_an_indirect_call_is_reported_but_does_not_end_the_block(self):
        """A call returns, so it does not branch within this function.

        Its target is still a hole in the call graph, which is why it is
        reported separately rather than folded into the successors — and why
        the block carries on to the ret rather than stopping at the call.
        """
        # 0x1000: call eax (ff d0)  0x1002: ret
        cfg = self.cfg_of(b"\xff\xd0" + RET)
        self.assertEqual(cfg.indirect_calls, (TEXT_RVA,))
        block = cfg.blocks[TEXT_RVA]
        self.assertEqual(block.instructions, (TEXT_RVA, TEXT_RVA + 2))
        self.assertEqual(block.successors, (("ret", None),))

    def test_running_past_the_decoded_region_is_not_a_clean_end(self):
        """A block that just stops must not read as a resolved fallthrough."""
        cfg = self.cfg_of(NOP * 4)     # nops into nothing, no ret
        self.assertFalse(cfg.complete)
        self.assertIn(("fall", None), cfg.blocks[TEXT_RVA].successors)

    def test_block_limit_truncates_loudly(self):
        """Hitting the limit must not read as a finished graph."""
        full = self.cfg_of(BRANCHED)
        self.assertEqual(len(full.blocks), 3)      # entry, fallthrough, target

        limited = analyze(BRANCHED).cfg_of(TEXT_RVA, max_blocks=1)
        self.assertTrue(limited.truncated)
        self.assertFalse(limited.complete)

    def test_edges_lists_only_known_destinations(self):
        cfg = self.cfg_of(BRANCHED)
        self.assertTrue(cfg.edges())
        for _src, _kind, dst in cfg.edges():
            self.assertIsNotNone(dst)


class TestDotRendering(unittest.TestCase):

    def test_unresolved_edges_appear_as_nodes(self):
        """The picture must show the gap, not merely be small."""
        from pydbg.analysis import cfg_to_dot
        cfg = analyze(b"\xff\xe0").cfg_of(TEXT_RVA)
        source = cfg_to_dot(cfg)
        self.assertIn("indirect?", source)
        self.assertIn("style=dashed", source)


class TestReports(unittest.TestCase):

    def setUp(self):
        self.result = analyze(b"\x75\x02" + RET + NOP + RET)

    def test_summary_reports_coverage_with_overlap(self):
        text = self.result.render_summary()
        self.assertIn("instructions", text)
        self.assertIn("overlap", text)      # the qualifier travels with it
        self.assertIn(".text", text)

    def test_functions_render_shows_confidence(self):
        text = self.result.render_functions()
        self.assertIn("conf", text)
        self.assertIn("0x00001000", text)

    def test_xrefs_render_groups_by_kind(self):
        text = analyze(b"\xe8\x03\x00\x00\x00" + RET + NOP * 3 + RET
                       ).render_xrefs()
        self.assertIn("branch", text)

    def test_rendering_is_stable_across_runs(self):
        """Two runs must be diffable; the numbers are compared by hand."""
        again = analyze(b"\x75\x02" + RET + NOP + RET)
        self.assertEqual(self.result.render_summary(), again.render_summary())
        self.assertEqual(self.result.render_coverage(),
                         again.render_coverage())

    def test_listing_annotates_references(self):
        text = analyze(b"\xe8\x03\x00\x00\x00" + RET + NOP * 3 + RET
                       ).render_listing(TEXT_RVA, 16)
        self.assertIn("call", text)
        self.assertIn("branch->", text)


class TestLiveProcessSource(unittest.TestCase):
    """Analyzing a module inside a real process, through LoadedView."""

    def setUp(self):
        from tests.helpers import create_debugger
        self.dbg, self.pid, self.tid = create_debugger()
        from tests.helpers import module_base
        self.base = module_base(self.dbg)

    def tearDown(self):
        from tests.helpers import teardown
        teardown(self.dbg)

    def test_reads_a_module_at_its_runtime_base(self):
        from pydbg.analysis.process_source import ProcessSource
        source = ProcessSource(self.dbg._session, self.base)
        self.assertEqual(source.read(0, 2), b"MZ")

    def test_reading_past_the_module_bound_fails(self):
        """Without a bound, a read past the end walks into the next mapping."""
        from pydbg.analysis.process_source import ProcessSource
        source = ProcessSource(self.dbg._session, self.base, size=0x100)
        with self.assertRaises(ValueError):
            source.read(0x200, 4)

    def test_analyzes_a_live_module(self):
        """The end-to-end guard for the runtime-base translation.

        The module is not where its header says it is, so an analyzer that
        translates against the preferred base finds no operands, resolves no
        cross-references and reports an empty result as success.
        """
        from pydbg.analysis import analyze_process
        result = analyze_process(self.dbg._session, self.base)

        self.assertGreater(result.stats.insns, 0)
        # The module is translated against where it actually loaded, not the
        # base its own header prefers.
        self.assertEqual(result.image.image_base, self.base)
        self.assertEqual(result.image.pe.va_base, self.base)
        self.assertGreater(result.stats.xrefs, 0,
                           "no references resolved: wrong address base?")

    def test_the_live_and_on_disk_paths_agree_on_the_code(self):
        """Same image, two sources, same entry point and same instruction mode.

        Not a byte comparison: a live module has had its relocations applied
        and may have been patched since it was written, so the bytes are not
        owed to match. What must match is where the code is and how it decodes.
        """
        import os

        from pydbg.analysis import analyze_file, analyze_process
        from tests import TEST_TARGET_PATH

        if not os.path.exists(TEST_TARGET_PATH):
            self.skipTest("no test target on disk")

        live = analyze_process(self.dbg._session, self.base)
        from_disk = analyze_file(TEST_TARGET_PATH)

        self.assertEqual(live.image.mode, from_disk.image.mode)
        entry = from_disk.image.pe.optional_header.entry_point_rva
        self.assertIn(entry, live.functions.starts)
        self.assertIn(entry, from_disk.functions.starts)


class TestAlreadyParsedImage(unittest.TestCase):

    def test_analysis_does_not_need_the_file_again(self):
        """A PE parsed once can be analyzed without re-reading it."""
        from pydbg.analysis import analyze_pe
        from pydbg.pe import PE

        pe = PE(build_image(b"\x75\x02" + RET + NOP + RET))
        result = analyze_pe(pe)
        self.assertGreater(result.stats.insns, 0)


if __name__ == "__main__":
    unittest.main()
