"""Tests for the §F backlog cleared out of the analysis and disasm layers.

Each of these was recorded in targets/pydbg-gaps.md as a known limitation. The
tests exist so the limitation stays closed: several of them are about silent
truncation and mislabelling, which by definition produce no error when they
come back.
"""

import struct
import unittest

from tests.pe_builder import PEBuilder

TEXT_RVA = 0x1000
IMAGE_BASE = 0x400000


def build(code, size=0x80):
    text = bytearray(b"\x90" * size)
    text[0:len(code)] = code
    builder = PEBuilder(magic=0x10B, image_base=IMAGE_BASE,
                        entry_rva=TEXT_RVA)
    builder.add_section(".text", bytes(text), TEXT_RVA)
    return builder.build()


def analyze(code, **kwargs):
    from pydbg.analysis import analyze_bytes
    return analyze_bytes(build(code), **kwargs)


RET = b"\xc3"


class TestEntryEvidence(unittest.TestCase):
    """F5 — a branch target is not a function start just because it decodes."""

    def test_a_start_inside_an_evidenced_function_is_demoted(self):
        """The error surface the byte test cannot close.

        A pointer landing in the middle of a known function is a mis-seeded
        block, not a second function — and the byte before it is often padding
        by coincidence, which is exactly what the old filter read as evidence.
        """
        from pydbg.analysis.functions import FunctionTable

        table = FunctionTable()
        table.add_start(0x1000, confident=True)
        table.add_start(0x1010, confident=False)     # inside, by the bytes
        table.note_instruction(0x1000, 4)
        table.note_instruction(0x1004, 0x20)
        table.invalidate()

        self.assertEqual(table.prune_starts_inside_functions(), 1)
        self.assertNotIn(0x1010, table.starts)
        self.assertIn(0x1010, table.code_seeds, "it must stay decoded")

    def test_a_start_outside_every_function_survives(self):
        from pydbg.analysis.functions import FunctionTable

        table = FunctionTable()
        table.add_start(0x1000, confident=True)
        table.add_start(0x2000, confident=False)
        table.note_instruction(0x1000, 4)
        table.invalidate()

        self.assertEqual(table.prune_starts_inside_functions(), 0)
        self.assertIn(0x2000, table.starts)

    def test_an_address_inside_a_decoded_instruction_is_not_an_entry(self):
        """A pointer two bytes into a mov cannot begin a function."""
        from pydbg.analysis.seeds import looks_like_entry

        result = analyze(b"\x8b\x43\x08" + RET)      # mov eax,[ebx+8] ; ret
        # 0x1002 is inside the mov, but is preceded by 0x43 — not padding — so
        # this only tests the byte rule; the decoder rule is what matters.
        self.assertFalse(looks_like_entry(result.image, 0x1002,
                                          decoder=result.decoder))
        # And the decoder agrees about which instruction owns the byte.
        self.assertEqual(result.decoder.enclosing_instruction(0x1002), 0x1000)
        self.assertEqual(result.decoder.enclosing_instruction(0x1000), 0x1000)

    def test_pruning_leaves_coverage_alone(self):
        """Demoted starts are still decoded — the code does not vanish."""
        result = analyze(b"\xe8\x1b\x00\x00\x00" + RET)
        self.assertGreater(result.coverage[".text"].covered, 0)


class TestSeedClassToggles(unittest.TestCase):
    """F9 — measuring one class's contribution needed a code edit."""

    def test_naming_a_subset_runs_only_that_subset(self):
        from pydbg.analysis.seeds import SeedProvider

        result = analyze(RET)
        provider = SeedProvider(result.image)
        everything = provider.collect()
        only_entry = provider.collect(("entry_point",))
        self.assertIn(TEXT_RVA, everything.confident)
        self.assertIn(TEXT_RVA, only_entry.confident)
        self.assertLessEqual(len(only_entry.found), len(everything.found))

    def test_an_empty_selection_yields_nothing(self):
        from pydbg.analysis.seeds import SeedProvider
        seeds = SeedProvider(analyze(RET).image).collect(())
        self.assertEqual(seeds.found, {})
        self.assertEqual(seeds.confident, set())
        self.assertEqual(seeds.tentative, set())

    def test_the_config_reaches_the_provider(self):
        from pydbg.analysis import SeedConfig
        result = analyze(RET, config=SeedConfig(seed_classes=("data_pointers",)))
        # The entry point was not seeded, so it is not a function start.
        self.assertNotIn(TEXT_RVA, result.functions.starts)


class TestInstructionBudget(unittest.TestCase):
    """F10 — the per-sweep budget did not bound the whole run."""

    def test_the_ceiling_stops_the_run(self):
        from pydbg.analysis import SeedConfig
        code = b"\x90" * 0x40 + RET
        capped = analyze(code, config=SeedConfig(max_total_instructions=5))
        uncapped = analyze(code)
        self.assertEqual(capped.stats.insns, 5)
        self.assertGreater(uncapped.stats.insns, 5)

    def test_an_exhausted_budget_is_reported_not_silent(self):
        """A run that stopped early must not read as a complete analysis."""
        from pydbg.analysis import SeedConfig
        capped = analyze(b"\x90" * 0x40 + RET,
                         config=SeedConfig(max_total_instructions=5))
        self.assertTrue(capped.stats.budget_exhausted)
        self.assertFalse(analyze(b"\x90" * 8 + RET).stats.budget_exhausted)


class TestCFGTruncation(unittest.TestCase):
    """F11 — 'truncated' did not say whether the cause was size or data."""

    def test_hitting_the_block_limit_says_so(self):
        from pydbg.analysis import SeedConfig
        # A chain of conditional branches produces many blocks.
        code = b"".join(b"\x75\x00" for _ in range(20)) + RET
        result = analyze(code, config=SeedConfig(max_instructions=1000))
        cfg = result.cfg_of(TEXT_RVA, max_blocks=2)
        self.assertTrue(cfg.truncated)
        self.assertEqual(cfg.truncated_reason, "block_limit")

    def test_running_out_of_decoded_code_says_that_instead(self):
        result = analyze(b"\x90\x90\x90\x90")        # nops into nothing
        cfg = result.cfg_of(TEXT_RVA)
        self.assertFalse(cfg.complete)
        self.assertEqual(cfg.truncated_reason, "undecoded")


class TestIndexedMemory(unittest.TestCase):
    """F12 — the indexed form was only recognised with no base register."""

    def decode(self, code, mode="x86"):
        from pydbg.disasm.engine import DisasmEngine
        return DisasmEngine(mode=mode).disasm(0x100000, code)[0]

    def test_an_indexed_operand_with_a_base_is_named(self):
        # mov eax, [ebx + ecx*4 + 0x10]
        operand = self.decode(b"\x8b\x44\x8b\x10").operands[1]
        self.assertTrue(operand.is_indexed_mem)

    def test_a_table_operand_without_a_base_is_still_a_table(self):
        # jmp dword ptr [ecx*4 + 0x401000]
        operand = self.decode(
            b"\xff\x24\x8d" + struct.pack("<I", IMAGE_BASE + 0x1000)).operands[0]
        self.assertTrue(operand.is_indexed_mem)
        self.assertTrue(operand.is_table_mem)

    def test_an_indexed_operand_with_a_base_is_not_claimed_as_a_table(self):
        """Its displacement is relative to a base the analysis cannot know.

        Calling it a table base would put a made-up address in the index.
        """
        operand = self.decode(b"\x8b\x44\x8b\x10").operands[1]
        self.assertFalse(operand.is_table_mem)
        self.assertFalse(operand.is_absolute_mem)


if __name__ == "__main__":
    unittest.main()
