"""Tests for the seed classes.

Seeds decide what the answer can possibly contain — recursive descent only
finds what something points at — so a seed class that silently returns nothing
does not look like a failure. It looks like a binary with fewer functions. Two
of the tests below exist specifically to catch that shape: on a 64-bit image,
a reader that uses 32-bit pointers finds *nothing at all* rather than finding
half of everything.
"""

import os
import struct
import unittest

from tests.pe_builder import PEBuilder

TEXT_RVA = 0x1000
DATA_RVA = 0x2000
RELOC_RVA = 0x3000


def _base(magic=0x20B):
    return 0x140000000 if magic == 0x20B else 0x400000


def build_reloc_seed_image(kind, magic=0x20B, target_rva=0x1010):
    """An image whose .reloc names a slot holding a pointer into .text."""
    base = _base(magic)
    slot_size = 8 if magic == 0x20B else 4

    builder = PEBuilder(magic=magic, image_base=base, entry_rva=TEXT_RVA)
    builder.add_section(".text", b"\x90" * 0x40, TEXT_RVA)
    stored = (base + target_rva).to_bytes(slot_size, "little")
    builder.add_section(".data", stored + b"\x00" * 8, DATA_RVA, 0xC0000040)

    # One relocation block, one entry, fixing up the slot at DATA_RVA.
    entry = (kind << 12) | 0
    block = struct.pack("<II", DATA_RVA, 8 + 2) + struct.pack("<H", entry)
    payload = block + struct.pack("<II", 0, 0)
    builder.add_section(".reloc", payload, RELOC_RVA, 0x42000040)
    builder.add_dir(5, RELOC_RVA, len(payload))
    return builder.build(), base


def build_data_pointer_image(magic=0x20B, target_rva=0x1020):
    """An image whose .data holds a bare pointer into .text."""
    base = _base(magic)
    slot_size = 8 if magic == 0x20B else 4
    builder = PEBuilder(magic=magic, image_base=base, entry_rva=TEXT_RVA)
    builder.add_section(".text", b"\x90" * 0x40, TEXT_RVA)
    stored = (base + target_rva).to_bytes(slot_size, "little")
    builder.add_section(".data", stored + b"\x00" * slot_size, DATA_RVA,
                        0xC0000040)
    return builder.build()


class TestLooksLikeEntry(unittest.TestCase):

    def image(self, code=b"\x90" * 0x40, magic=0x20B):
        from pydbg.analysis import AnalyzedImage
        builder = PEBuilder(magic=magic, image_base=_base(magic),
                            entry_rva=TEXT_RVA)
        builder.add_section(".text", code, TEXT_RVA)
        return AnalyzedImage.from_bytes(builder.build())

    def test_a_call_target_is_taken_on_trust(self):
        from pydbg.analysis.seeds import looks_like_entry
        # Preceded by a nop-invalid byte, but something calls it.
        image = self.image(b"\x90" * 8 + b"\x55" + b"\x90" * 8)
        self.assertTrue(looks_like_entry(image, 0x1008, is_call_target=True))

    def test_padding_before_the_address_is_weak_evidence(self):
        from pydbg.analysis.seeds import looks_like_entry
        image = self.image()
        self.assertTrue(looks_like_entry(image, 0x1010))

    def test_an_address_outside_the_image_is_not_an_entry(self):
        from pydbg.analysis.seeds import looks_like_entry
        self.assertFalse(looks_like_entry(self.image(), 0x1050))

    def test_the_first_byte_of_a_section_is_an_entry(self):
        from pydbg.analysis.seeds import looks_like_entry
        self.assertTrue(looks_like_entry(self.image(), TEXT_RVA))

    def test_a_mid_instruction_address_is_not(self):
        from pydbg.analysis.seeds import looks_like_entry
        # 0x1010 follows 0xB8, which is not padding, a ret or an int3.
        image = self.image(b"\x90" * 0x10 + b"\xb8" + b"\x90" * 0x10)
        self.assertFalse(looks_like_entry(image, 0x1011))


class TestSeedClasses(unittest.TestCase):

    def seeds(self, data):
        from pydbg.analysis import AnalyzedImage
        from pydbg.analysis.seeds import SeedProvider
        return SeedProvider(AnalyzedImage.from_bytes(data)).collect()

    def test_relocation_pointer_is_seeded_from_dir64(self):
        """The 64-bit relocation kind, which the prototype never handled.

        Handling only HIGHLOW (3) is a 32-bit assumption, and it empties this
        class entirely on x64 — the single largest seed source, measured at
        80.9% of overlap bytes, silently contributing nothing.
        """
        data, _ = build_reloc_seed_image(kind=10, magic=0x20B)
        seeds = self.seeds(data)
        self.assertIn(0x1010, seeds.tentative)
        self.assertEqual(seeds.classes().get("relocation_pointers"), 1)

    def test_relocation_pointer_is_seeded_from_higlow(self):
        data, _ = build_reloc_seed_image(kind=3, magic=0x10B)
        seeds = self.seeds(data)
        self.assertIn(0x1010, seeds.tentative)

    def test_an_absolute_relocation_carries_no_address(self):
        """Kind 0 is padding and points nowhere; reading it seeds nothing."""
        data, _ = build_reloc_seed_image(kind=0, magic=0x20B)
        self.assertEqual(self.seeds(data).classes().get("relocation_pointers"),
                         None)

    def test_pointer_seeds_are_tentative_not_confident(self):
        """A pointer is a guess. Saying so is the point of the two sets."""
        data, _ = build_reloc_seed_image(kind=10, magic=0x20B)
        seeds = self.seeds(data)
        self.assertNotIn(0x1010, seeds.confident)

    def test_data_pointer_is_found_on_a_64_bit_image(self):
        """A 32-bit read can never equal a 64-bit VA.

        With the pointer width hard-coded to 4 — the prototype's assumption —
        this scan does not find half the pointers on a PE32+ image. It finds
        none, because no 32-bit value satisfies a 64-bit image window.
        """
        seeds = self.seeds(build_data_pointer_image(magic=0x20B))
        self.assertIn(0x1020, seeds.tentative)
        self.assertEqual(seeds.classes().get("data_pointers"), 1)

    def test_data_pointer_is_found_on_a_32_bit_image(self):
        seeds = self.seeds(build_data_pointer_image(magic=0x10B))
        self.assertIn(0x1020, seeds.tentative)

    def test_tls_callbacks_are_confident(self):
        """They run before the entry point, so they are functions outright."""
        from tests.test_pe_directories import build_tls_image
        data, _image_base, expected = build_tls_image(0x20B)
        seeds = self.seeds(data)
        self.assertEqual(seeds.classes().get("tls_callbacks"), len(expected))

    def test_exception_table_entries_are_confident(self):
        """The loader's own function table — the strongest class there is."""
        from tests.test_pe_directories import build_pdata_image
        seeds = self.seeds(build_pdata_image())
        self.assertEqual(seeds.classes().get("exception_table"), 2)

    def test_entry_point_is_confident(self):
        builder = PEBuilder(magic=0x20B, image_base=_base(0x20B),
                            entry_rva=TEXT_RVA)
        builder.add_section(".text", b"\x90" * 0x10, TEXT_RVA)
        seeds = self.seeds(builder.build())
        self.assertIn(TEXT_RVA, seeds.confident)
        self.assertEqual(seeds.classes().get("entry_point"), 1)


class TestSweepTimeSeeds(unittest.TestCase):
    """Seeds that can only be found once decoding has started."""

    def analyze(self, code, magic=0x20B):
        from pydbg.analysis import analyze_bytes
        builder = PEBuilder(magic=magic, image_base=_base(magic),
                            entry_rva=TEXT_RVA)
        builder.add_section(".text", code, TEXT_RVA)
        return analyze_bytes(builder.build())

    def test_jump_table_targets_become_code_seeds_not_function_starts(self):
        """A case body is not a function entry.

        Recording one as a start cuts the function containing the switch into
        pieces at every case, corrupting every extent that spans it.
        """
        base = _base(0x20B)
        # 0x1000: jmp qword ptr [rip+disp] -> a table at 0x1080 holding
        # pointers to 0x1020 and 0x1030.
        table_rva = 0x1080
        disp = table_rva - (TEXT_RVA + 6)
        code = b"\xff\x25" + struct.pack("<i", disp) + b"\x90" * (0x80 - 6)
        code += struct.pack("<QQ", base + 0x1020, base + 0x1030)
        result = self.analyze(code)

        self.assertIn(0x1080, result.xrefs, "table reference not recovered")
        self.assertIn(0x1020, result.functions.code_seeds)
        self.assertNotIn(0x1020, result.functions.starts)

    def _sweep_through_iat(self, opcode):
        """Run a sweep over one instruction: `jmp`/`call` [rip+disp] -> IAT."""
        from pydbg.analysis import AnalyzedImage
        from pydbg.analysis.engine import StaticAnalyzer

        base = _base(0x20B)
        builder = PEBuilder(magic=0x20B, image_base=base, entry_rva=TEXT_RVA)
        disp = 0x1040 - (TEXT_RVA + 6)
        code = opcode + struct.pack("<i", disp) + b"\x90" * 8
        builder.add_section(".text", code, TEXT_RVA)
        builder.add_section(".rdata", b"\x00" * 0x20, 0x1040, 0x40000040)

        analyzer = StaticAnalyzer(AnalyzedImage.from_bytes(builder.build()))
        analyzer._iat_slots = {0x1040}      # as the import table would report
        # Queued as a code seed, not as a known entry: the question is whether
        # the sweep promotes it, and starting it as an entry would answer yes
        # before the code under test ever ran.
        analyzer._enqueue_code_seed(TEXT_RVA)
        analyzer._sweep_from(TEXT_RVA)
        return analyzer

    def test_a_jump_through_the_iat_is_a_thunk(self):
        """An import thunk is a one-instruction function.

        Nothing calls it directly — callers go through it — so a call graph
        built without recognising it knows the call sites but not the functions
        they reach.
        """
        analyzer = self._sweep_through_iat(b"\xff\x25")      # jmp [rip+disp]
        self.assertIn(TEXT_RVA, analyzer.functions.confident)

    def test_a_call_through_the_iat_is_not_a_thunk(self):
        """`call [IAT]` is an ordinary call site inside a real function.

        Counting it as an entry would invent a function at every place the
        program imports something.
        """
        analyzer = self._sweep_through_iat(b"\xff\x15")      # call [rip+disp]
        self.assertNotIn(TEXT_RVA, analyzer.functions.confident)


class TestRealImageSeeds(unittest.TestCase):
    """End-to-end against a real x64 image: the classes must not be empty."""

    KERNEL32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                            "System32", "kernel32.dll")

    def setUp(self):
        if not os.path.exists(self.KERNEL32):
            self.skipTest(f"no system DLL at {self.KERNEL32}")
        from pydbg.analysis import AnalyzedImage
        from pydbg.analysis.seeds import SeedProvider
        self.seeds = SeedProvider(
            AnalyzedImage.from_file(self.KERNEL32)).collect()

    def test_relocations_produce_seeds(self):
        """The DIR64 guard: zero here means the whole class is inert.

        Without this, a 32-bit-only relocation reader passes every fixture test
        and contributes nothing on the images that matter most.
        """
        self.assertGreater(self.seeds.classes().get("relocation_pointers", 0), 0)

    def test_exception_table_produces_seeds(self):
        self.assertGreater(self.seeds.classes().get("exception_table", 0), 0)

    def test_exports_and_entry_point_produce_seeds(self):
        self.assertGreater(self.seeds.classes().get("exports", 0), 0)
        self.assertEqual(self.seeds.classes().get("entry_point"), 1)


if __name__ == "__main__":
    unittest.main()
