"""Data-section references, and being able to say what the index is missing.

F18, the pydbg half: the cross-reference index was built from decoded
instructions only. That is a definition rather than a bug, which is why the
wrong answer looked right — a vtable or callback table entry is not an
instruction, so no amount of decoding produces it, and `callers_of()` answered
"nobody references this" for exactly the addresses those tables exist to name.
On a Delphi target that is not an edge case: most of the code is reached
through pointers and appears nowhere else.

The readers that find those pointers were already in `SeedProvider`; their
positions were used as decode seeds and dropped. The fix keeps the slot and
emits an `Xref(target, DATA)` from it, so the two halves below are the same
change seen from two sides: the index gains the references, and the result
says which classes went into it, so an empty answer can no longer be mistaken
for a fact it does not support.

These tests are written to fail if the producer is removed, not merely if the
numbers move. `callers_of` returning () *is* the defect, so the assertions go
through the kind set as well — a count alone cannot distinguish "found the
pointer" from "found something else".
"""

import os
import struct
import unittest

from tests.pe_builder import PEBuilder

IMAGE_BASE = 0x400000
IMAGE_BASE64 = 0x140000000
TEXT_RVA = 0x1000
DATA_RVA = 0x2000
RET = b"\xc3"
NOP = b"\x90"


def _build(magic=0x10B, entry_rva=TEXT_RVA):
    base = IMAGE_BASE64 if magic == 0x20B else IMAGE_BASE
    return PEBuilder(magic=magic, image_base=base, entry_rva=entry_rva), base


def _pointer_image(data_pointer_to=0x1020, magic=0x10B):
    """A .text with an entry and a function, and a .data pointer to the latter."""
    builder, base = _build(magic)
    # 0x1000: entry, straight-line, ends at a ret so the sweep stops there.
    # 0x1009-0x101f: padding, so 0x1020 is preceded by a 0x90 and reads as an
    # entry. 0x1020: the function only the data slot names.
    code = NOP * 8 + RET + NOP * 0x17 + b"\x55" + RET
    builder.add_section(".text", code, TEXT_RVA)
    slot_size = 8 if magic == 0x20B else 4
    stored = (base + data_pointer_to).to_bytes(slot_size, "little")
    builder.add_section(".data", stored + b"\x00" * slot_size, DATA_RVA,
                        0xC0000040)
    return builder.build(), base


class TestDataSectionPointers(unittest.TestCase):
    """The producers: a slot holding a code address becomes a reference."""

    def analyze(self, data, **kwargs):
        from pydbg.analysis import analyze_bytes
        return analyze_bytes(data, **kwargs)

    def test_a_data_pointer_is_a_caller(self):
        """The whole gap, in one assertion.

        Nothing in the code names 0x1020 — no call, no jump, no immediate —
        so an index built from instructions has it as referenced by nobody.
        The .data slot at 0x2000 says otherwise.
        """
        from pydbg.analysis import RefKind
        result = self.analyze(_pointer_image()[0])

        self.assertEqual(result.callers_of(0x1020), (DATA_RVA,))
        self.assertEqual(result.data_refs_of(0x1020), (DATA_RVA,))
        self.assertIn(RefKind.DATA, result.ref_kinds_of(0x1020))

    def test_the_source_is_the_slot_not_an_instruction(self):
        """0x2000 is where the pointer lives; there is no instruction there.

        The distinction is load-bearing the other way round too: a caller that
        wants a site it can disassemble has to filter by kind, because feeding
        a data slot to a decoder decodes the bytes of the pointer.
        """
        from pydbg.analysis import RefKind

        result = self.analyze(_pointer_image()[0])
        refs = result.xrefs_of(0x1020, RefKind.DATA)

        self.assertEqual([ref.source for ref in refs], [DATA_RVA])
        self.assertEqual(result.image.section_of(DATA_RVA).name, ".data")

    def test_a_relocation_slot_is_a_caller(self):
        """DIR64 on x64, HIGHLOW on x86: the loader's own fixup list.

        This is the strongest statement of "this RVA holds a pointer" that an
        image carries, and it was used only to pick decode seeds.
        """
        from tests.test_seeds import build_reloc_seed_image

        data, _base = build_reloc_seed_image(kind=10, magic=0x20B)
        result = self.analyze(data)

        self.assertEqual(result.data_refs_of(0x1010), (DATA_RVA,))
        self.assertGreater(result.stats.data_refs, 0)

    def test_a_jump_table_entry_is_a_caller(self):
        """A switch table is a data slot per entry, not one reference per table.

        The table base already had a TABLE reference from the `jmp` that reads
        it. The case bodies did not have one from anywhere — the table is the
        only thing naming them.
        """
        base = IMAGE_BASE
        table_rva = 0x1040
        # jmp dword ptr [eax*4 + table]
        code = (b"\xff\x24\x85" + (base + table_rva).to_bytes(4, "little"))
        code += NOP * (table_rva - TEXT_RVA - len(code))
        code += struct.pack("<II", base + 0x1060, base + 0x1070)
        code += NOP * (0x1080 - len(code))
        builder, _ = _build()
        builder.add_section(".text", code, TEXT_RVA)
        result = self.analyze(builder.build())

        self.assertIn(0x1040, result.xrefs, "the table base is not referenced")
        self.assertEqual(result.data_refs_of(0x1060), (table_rva,))
        self.assertEqual(result.data_refs_of(0x1070), (table_rva + 4,))

    def test_a_data_pointer_does_not_claim_the_address_is_a_function(self):
        """A pointer says something names it. That is not "something calls it".

        The two-tier split exists for this: promoting pointer evidence to a
        confident start would make every misread dword in a data section a
        function with evidence behind it, which is the shape of error that
        makes an extent stop in the middle of the real function before it.
        """
        result = self.analyze(_pointer_image()[0])

        self.assertIn(0x1020, result.functions.code_seeds)
        self.assertNotIn(0x1020, result.functions.confident)

    def test_the_class_moves_no_function_start(self):
        """The F5 invariant, restated for this producer.

        A pointer says something *names* an address, never that anything calls
        it, so adding the class must leave the recovered function set exactly
        where it was. Promoting pointer evidence would turn every misread
        dword in a data section into a start with evidence behind it, which is
        the shape of error that cuts a function in half at the address a
        stale pointer happened to name.

        Asserted as a diff between two runs rather than against a number, so
        it stays true as the rest of the traversal changes.
        """
        from pydbg.analysis import SeedConfig

        data, _ = _pointer_image()
        with_data = self.analyze(
            data, config=SeedConfig(seed_classes=("entry_point",
                                                  "data_pointers")))
        without = self.analyze(data,
                               config=SeedConfig(seed_classes=("entry_point",)))

        self.assertGreater(with_data.stats.data_refs, 0)
        self.assertEqual(without.stats.data_refs, 0)
        self.assertEqual(with_data.functions.confident,
                         without.functions.confident)
        self.assertEqual(with_data.functions.starts, without.functions.starts)

    def test_a_tentative_start_is_not_promoted_by_a_pointer_to_it(self):
        """A jump target that looks like an entry, also named by a data slot.

        Two weak kinds of evidence are not one strong kind: the start stays
        tentative, so a caller reading `confident` learns nothing new from the
        pointer.
        """
        base = IMAGE_BASE
        code = b""
        code += b"\xe9" + (0x1030 - (TEXT_RVA + 5)).to_bytes(4, "little")
        code += NOP * (0x1030 - TEXT_RVA - len(code))
        code += b"\x55" + RET
        builder, _ = _build()
        builder.add_section(".text", code, TEXT_RVA)
        stored = (base + 0x1030).to_bytes(4, "little")
        builder.add_section(".data", stored + b"\x00" * 4, DATA_RVA,
                            0xC0000040)
        # The jump target's own bytes are decoded, which credits this one
        # address to the nearest *confident* start. Assert on the trait that
        # survives that: decoded, and never confident.
        result = self.analyze(builder.build())

        self.assertIn(0x1030, result.functions.code_seeds)
        self.assertNotIn(0x1030, result.functions.confident)
        self.assertEqual(result.data_refs_of(0x1030), (DATA_RVA,))

    def test_an_address_nothing_names_is_still_unreferenced(self):
        """The false-positive guard: saying "yes" everywhere would be useless.

        0x1010 sits after the entry's ret, so nothing decodes it, and no slot
        points at it. The index must still be able to answer nobody.
        """
        from pydbg.analysis import RefKind

        result = self.analyze(_pointer_image()[0])

        self.assertEqual(result.callers_of(0x1010), ())
        self.assertEqual(result.data_refs_of(0x1010), ())
        self.assertEqual(result.ref_kinds_of(0x1010), ())
        self.assertIn(RefKind.DATA, result.ref_kinds(),
                      "the class was produced; this address is just not in it")

    def test_the_pointer_slot_is_the_one_holding_the_value(self):
        """Read the bytes rather than trusting the arithmetic."""
        data, base = _pointer_image()
        result = self.analyze(data)
        slot = result.data_refs_of(0x1020)[0]

        self.assertEqual(result.image.read_rva(slot, 4),
                         (base + 0x1020).to_bytes(4, "little"))

    def test_the_stat_counts_the_index_not_the_reads(self):
        """Two readers can name one slot; the index holds it once."""
        result = self.analyze(_pointer_image()[0])
        counted = sum(1 for refs in result.xrefs.values() for ref in refs
                      if ref.kind == 5)

        self.assertEqual(result.stats.data_refs, counted)
        self.assertGreater(result.stats.data_refs, 0)


class TestEveryRefKindHasAProducer(unittest.TestCase):
    """A kind declared in the enum and emitted by nothing is the F18 shape.

    `RefKind.DATA` was in the public enum and labelled in the reports while no
    code in the analysis package produced it, and nothing said so. This pins
    the structural statement — every declared kind is reachable — on a fixture
    that exercises all five, because a real image need not contain all of them
    (kernel32 produces no IMM and no TABLE reference at all).
    """

    def build_all_kinds(self):
        """One image containing each of the five kinds.

        BRANCH/IMM/MEM from three instructions, TABLE from an indirect jump
        through a table, DATA from a bare pointer in .data.
        """
        base = IMAGE_BASE
        table_rva = 0x1060
        code = b""
        code += b"\xe8" + (0x1040 - (TEXT_RVA + 5)).to_bytes(4, "little")
        code += b"\xb8" + (base + DATA_RVA).to_bytes(4, "little")    # imm
        code += b"\xa1" + (base + DATA_RVA).to_bytes(4, "little")    # [abs]
        code += b"\xff\x24\x85" + (base + table_rva).to_bytes(4, "little")
        code += NOP * (table_rva - TEXT_RVA - len(code))
        code += struct.pack("<II", base + 0x1080, base + 0x1090)
        code += NOP * (0x10a0 - len(code))
        code += b"\x55" + RET                                        # 0x1080
        code += NOP * (0x1090 - len(code)) + b"\x55" + RET

        builder, _ = _build()
        builder.add_section(".text", code, TEXT_RVA)
        stored = (base + 0x1080).to_bytes(4, "little")
        builder.add_section(".data", stored + b"\x00" * 4, DATA_RVA,
                            0xC0000040)
        return builder.build()

    def test_every_declared_kind_is_produced(self):
        from pydbg.analysis import RefKind, analyze_bytes

        result = analyze_bytes(self.build_all_kinds())

        self.assertEqual(set(result.ref_kinds()), set(RefKind),
                         "a kind in the enum that no run produces is a class "
                         "of reference missing from every answer")
        self.assertIn(RefKind.IMM, result.ref_kinds_of(DATA_RVA))
        self.assertIn(RefKind.MEM, result.ref_kinds_of(DATA_RVA))
        self.assertIn(RefKind.BRANCH, result.ref_kinds_of(0x1040))
        self.assertIn(RefKind.TABLE, result.ref_kinds_of(0x1060))
        self.assertIn(RefKind.DATA, result.ref_kinds_of(0x1080))


class TestXrefGaps(unittest.TestCase):
    """The second half: an empty answer has to be able to say what it rests on.

    `callers_of` returning () means "no reference of any kind this run
    collected". These tests are about the run being able to say when it did
    not collect a kind at all — the difference between a fact and a blind
    spot, which is the whole of F18's second half.
    """

    def analyze(self, data, **kwargs):
        from pydbg.analysis import analyze_bytes, SeedConfig
        return analyze_bytes(data, config=SeedConfig(**kwargs))

    def test_a_default_run_reports_no_gaps(self):
        result = self.analyze(_pointer_image()[0])

        self.assertEqual(result.xref_gaps, ())
        self.assertTrue(result.xrefs_are_complete())

    def test_a_seed_class_that_was_not_run_is_named(self):
        """Turning a class off must not read as the binary having none.

        Naming a subset of seed classes is a supported way to measure one
        class's contribution. It is also the way a caller accidentally
        produces "nothing references this" for a whole target.
        """
        result = self.analyze(_pointer_image()[0],
                              seed_classes=("entry_point",))

        self.assertEqual(result.callers_of(0x1020), (),
                         "the class really was not run")
        self.assertFalse(result.xrefs_are_complete())
        self.assertTrue(any("data_pointers" in gap for gap in result.xref_gaps))
        self.assertTrue(any("relocation_pointers" in gap
                            for gap in result.xref_gaps))

    def test_collection_off_is_a_gap_not_an_empty_binary(self):
        result = self.analyze(_pointer_image()[0], collect_xrefs=False)

        self.assertEqual(result.xrefs, {})
        self.assertFalse(result.xrefs_are_complete())
        self.assertTrue(any("collect_xrefs" in gap
                            for gap in result.xref_gaps))

    def test_an_exhausted_budget_truncates_the_index(self):
        """The sweep stopping early shortens the index, not just the coverage."""
        result = self.analyze(_pointer_image()[0], max_total_instructions=2)

        self.assertTrue(result.stats.budget_exhausted)
        self.assertFalse(result.xrefs_are_complete())
        self.assertTrue(any("ceiling" in gap for gap in result.xref_gaps))

    def test_a_data_pointer_ceiling_is_a_gap(self):
        """The scanner's own cap is a second way to be short by construction."""
        from pydbg.analysis import AnalyzedImage
        from pydbg.analysis.seeds import SeedProvider

        data, _base = _pointer_image()
        image = AnalyzedImage.from_bytes(data)
        seeds = SeedProvider(image, max_data_pointers=1).collect(
            ("data_pointers",))

        self.assertIn("data_pointers", seeds.truncated)

    def test_the_gaps_are_rendered(self):
        """The summary carries the warning; the command carries the reason.

        Same split as the call graph: the one-screen overview says the answer
        is qualified, and the detail is a command away rather than absent.
        """
        partial = self.analyze(_pointer_image()[0],
                               seed_classes=("entry_point",))
        whole = self.analyze(_pointer_image()[0])

        self.assertIn("data_pointers", partial.render_xref_gaps())
        self.assertIn("classes not collected", partial.render_summary())
        self.assertNotIn("classes not collected", whole.render_summary())
        self.assertIn("complete", whole.render_xref_gaps())


class TestReporting(unittest.TestCase):
    """What the output says, since "looks normal" is how this went unnoticed."""

    def analyze(self, data, **kwargs):
        from pydbg.analysis import analyze_bytes, SeedConfig
        return analyze_bytes(data, config=SeedConfig(**kwargs))

    def test_the_summary_counts_the_data_references(self):
        result = self.analyze(_pointer_image()[0])
        summary = result.render_summary()

        self.assertIn("from data slots", summary)
        self.assertIn("data", summary.split("reference kinds")[1].split("\n")[0])

    def test_xrefs_are_grouped_under_their_kind(self):
        result = self.analyze(_pointer_image()[0])
        text = result.render_xrefs(target=0x1020)

        self.assertIn("data", text)
        self.assertIn(f"{DATA_RVA:#x}", text)
        self.assertNotIn("branch", text)

    def test_a_complete_index_says_so_rather_than_nothing(self):
        result = self.analyze(_pointer_image()[0])

        self.assertIn("complete", result.render_xref_gaps())


class TestRealImageDataRefs(unittest.TestCase):
    """A real DLL, so a fixture cannot be the only thing that agrees."""

    KERNEL32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                            "System32", "kernel32.dll")

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(cls.KERNEL32):
            raise unittest.SkipTest(f"no system DLL at {cls.KERNEL32}")
        from pydbg.analysis import analyze_file
        # Once for the class: the analysis is half a minute and every test
        # here reads the same immutable result.
        cls.result = analyze_file(cls.KERNEL32)

    def test_pointers_in_the_image_become_references(self):
        """Zero here means the producer is inert on every real image.

        The fixtures are also where a reader that only works on hand-built
        layouts would pass while contributing nothing to the images that
        matter, which is the failure mode the seed classes were fixed for.
        """
        self.assertGreater(self.result.stats.data_refs, 0)
        self.assertIn(5, [int(kind) for kind in self.result.ref_kinds()])

    def test_a_real_image_has_no_xref_gaps(self):
        self.assertEqual(self.result.xref_gaps, ())

    def test_data_refs_point_at_the_bytes_they_claim(self):
        """Read the slot back and check the pointer really is there.

        The index is only worth trusting if the sources it names hold the
        value it claims; an off-by-one in the stride or the section base would
        otherwise produce a plausible-looking slot that contains something
        else entirely.
        """
        image = self.result.image
        slot_size = image.slot_size
        checked = 0
        for target, refs in self.result.xrefs.items():
            for ref in refs:
                if ref.kind != 5:
                    continue
                raw = image.read_rva(ref.source, slot_size)
                self.assertIsNotNone(raw, f"slot {ref.source:#x} unreadable")
                self.assertEqual(int.from_bytes(raw, "little"),
                                 image.rva_to_va(target))
                checked += 1
                if checked >= 200:
                    break
        self.assertGreater(checked, 0, "no DATA references to check")

    def test_an_untouched_address_still_answers_nobody(self):
        """The negative that has to survive: not every address is referenced."""
        result = self.result
        unreferenced = [rva for rva in range(0x2000, 0x4000, 0x10)
                        if not result.xrefs.get(rva)]
        self.assertTrue(unreferenced,
                        "every address referenced would mean the index is noise")
        for rva in unreferenced[:20]:
            self.assertEqual(result.callers_of(rva), ())
            self.assertEqual(result.data_refs_of(rva), ())


if __name__ == "__main__":
    unittest.main()
