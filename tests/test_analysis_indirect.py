"""Tests for indirect branch resolution.

`call [esi+0x18]` has no target in the instruction, which is why one target's
entry point appeared nowhere in the call graph: it was reachable only through
one. Constant propagation resolves the subset where the register was loaded
from somewhere known, and everything else is recorded as a site so the
incompleteness is visible rather than implied.
"""

import struct
import unittest

from tests.pe_builder import PEBuilder

TEXT_RVA = 0x1000
DATA_RVA = 0x2000
IMAGE_BASE = 0x400000
FUNCTION_RVA = 0x1020


TEXT_SIZE = 0x40      # must cover FUNCTION_RVA, or the target is not code


def build(code, data):
    """A PE32 image with 'code' in .text and 'data' in .data.

    .text is padded to TEXT_SIZE and a `ret` is planted at FUNCTION_RVA, so a
    resolved indirect call lands on a real executable address rather than past
    the end of the section.
    """
    text = bytearray(b"\x90" * TEXT_SIZE)
    text[0:len(code)] = code
    text[FUNCTION_RVA - TEXT_RVA] = 0xC3

    builder = PEBuilder(magic=0x10B, image_base=IMAGE_BASE,
                        entry_rva=TEXT_RVA)
    builder.add_section(".text", bytes(text), TEXT_RVA)
    builder.add_section(".data", data, DATA_RVA, 0xC0000040)
    return builder.build()


def analyze(code, data=b"\x00" * 0x10):
    from pydbg.analysis import analyze_bytes
    return analyze_bytes(build(code, data))


RET = b"\xc3"


def mov_eax(value):
    """mov eax, imm32"""
    return b"\xb8" + struct.pack("<I", value)


CALL_EAX_INDIRECT = b"\xff\x10"        # call dword ptr [eax]


class TestConstantPropagation(unittest.TestCase):

    def test_a_register_loaded_with_a_slot_address_resolves_the_call(self):
        """mov eax, <slot> ; call [eax] — the slot holds a code pointer."""
        slot_va = IMAGE_BASE + DATA_RVA
        code = mov_eax(slot_va) + CALL_EAX_INDIRECT + RET
        data = struct.pack("<I", IMAGE_BASE + FUNCTION_RVA)
        result = analyze(code, data)

        self.assertEqual(result.stats.indirect_resolved, 1)
        self.assertIn(FUNCTION_RVA, result.xrefs)
        # The call is the second instruction, after the 5-byte mov.
        sources = [x.source for x in result.xrefs[FUNCTION_RVA]]
        self.assertEqual(sources, [TEXT_RVA + 5])
        # A resolved indirect call is a call target, so it is a function.
        self.assertIn(FUNCTION_RVA, result.functions.confident)

    def test_a_register_loaded_from_memory_resolves_the_call(self):
        """mov eax, [table] ; call [eax] — one more indirection."""
        table_va = IMAGE_BASE + DATA_RVA
        slot_va = IMAGE_BASE + DATA_RVA + 4       # the second dword
        code = (mov_eax(table_va)
                + b"\x8b\x00"                 # mov eax, [eax]
                + CALL_EAX_INDIRECT + RET)
        data = (struct.pack("<I", slot_va)
                + struct.pack("<I", IMAGE_BASE + FUNCTION_RVA))
        result = analyze(code, data)
        self.assertEqual(result.stats.indirect_resolved, 1)
        self.assertIn(FUNCTION_RVA, result.xrefs)

    def test_lea_of_a_table_then_an_indexed_call_resolves(self):
        """lea eax, [table] ; call [eax+4]"""
        table_va = IMAGE_BASE + DATA_RVA
        code = (b"\x8d\x05" + struct.pack("<I", table_va)   # lea eax, [table]
                + b"\xff\x50\x04"                            # call [eax+4]
                + RET)
        data = b"\x00" * 4 + struct.pack("<I", IMAGE_BASE + FUNCTION_RVA)
        result = analyze(code, data)
        self.assertEqual(result.stats.indirect_resolved, 1)
        self.assertIn(FUNCTION_RVA, result.xrefs)

    def test_an_unknown_register_stays_unknown(self):
        """call [esi+0x18] with nothing loading esi — the documented case."""
        code = b"\xff\x56\x18" + RET      # call dword ptr [esi + 0x18]
        result = analyze(code)

        self.assertEqual(result.stats.indirect_resolved, 0)
        calls = result.indirect_call_sites()
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].is_call)
        self.assertIn("esi", calls[0].text)
        self.assertFalse(result.call_graph_is_complete())

    def test_an_unrecognised_instruction_forgets_what_was_known(self):
        """Conservative on purpose: a clobbered register must not stay known.

        `push ebp` does not touch eax, but nothing here proves that, and
        assuming it would risk a fabricated call edge. Forgetting costs a
        resolution and cannot cost correctness.
        """
        slot_va = IMAGE_BASE + DATA_RVA
        code = mov_eax(slot_va) + b"\x55" + CALL_EAX_INDIRECT + RET
        data = struct.pack("<I", IMAGE_BASE + FUNCTION_RVA)
        result = analyze(code, data)

        self.assertEqual(result.stats.indirect_resolved, 0)
        self.assertEqual(len(result.indirect_call_sites()), 1)

    def test_propagation_does_not_cross_a_branch(self):
        """A conditional jump is not a recognised form, so state is dropped."""
        slot_va = IMAGE_BASE + DATA_RVA
        code = (mov_eax(slot_va) + b"\x75\x00"        # jne +0
                + CALL_EAX_INDIRECT + RET)
        data = struct.pack("<I", IMAGE_BASE + FUNCTION_RVA)
        result = analyze(code, data)
        self.assertEqual(result.stats.indirect_resolved, 0)


class TestNoFabricatedEdges(unittest.TestCase):
    """A wrong call edge is worse than a missing one — nothing can tell."""

    def test_a_slot_holding_a_data_address_does_not_resolve(self):
        """The slot's contents must land in executable memory.

        Without that check `call [IAT]` "resolves" in a file image, where the
        slot holds the RVA of the import-name struct rather than the imported
        function, and records a call edge to a string.
        """
        slot_a = IMAGE_BASE + DATA_RVA
        code = mov_eax(slot_a) + CALL_EAX_INDIRECT + RET
        # Points into .data, which is in the image but is not code.
        data = struct.pack("<I", IMAGE_BASE + DATA_RVA + 8)
        result = analyze(code, data)

        self.assertEqual(result.stats.indirect_resolved, 0)
        self.assertEqual(len(result.indirect_call_sites()), 1)

    def test_the_same_slot_resolves_when_it_holds_code(self):
        """Control for the test above: the only difference is the target.

        Without this, 'does not resolve' would also pass if resolution were
        simply broken.
        """
        slot_a = IMAGE_BASE + DATA_RVA
        code = mov_eax(slot_a) + CALL_EAX_INDIRECT + RET
        data = struct.pack("<I", IMAGE_BASE + FUNCTION_RVA)
        result = analyze(code, data)

        self.assertEqual(result.stats.indirect_resolved, 1)
        self.assertEqual(len(result.indirect_call_sites()), 0)

    def test_a_pointer_outside_the_image_does_not_resolve(self):
        code = mov_eax(IMAGE_BASE + DATA_RVA) + CALL_EAX_INDIRECT + RET
        data = struct.pack("<I", 0xDEADBEEF)
        result = analyze(code, data)
        self.assertEqual(result.stats.indirect_resolved, 0)


class TestIndirectSitesAreReported(unittest.TestCase):

    def test_sites_are_listed_with_their_operand_text(self):
        result = analyze(b"\xff\x56\x18" + b"\xff\x53\x20" + RET)
        text = result.render_indirect_sites()
        self.assertIn("esi", text)
        self.assertIn("ebx", text)
        self.assertIn("incomplete", text)

    def test_summary_reports_both_halves(self):
        """Resolved alone reads as progress even while most sites are unknown."""
        result = analyze(b"\xff\x56\x18" + RET)
        summary = result.render_summary()
        self.assertIn("0 resolved", summary)
        self.assertIn("unresolved", summary)

    def test_a_jump_is_listed_but_is_not_a_call_site(self):
        # jmp dword ptr [esi] — a switch or tail dispatch, not a call.
        result = analyze(b"\xff\x26" + RET)
        self.assertEqual(len(result.indirect_sites), 1)
        self.assertEqual(result.indirect_call_sites(), ())


class TestRealImageIndirectSites(unittest.TestCase):
    """Both halves must be non-zero on a real image, and reported."""

    @classmethod
    def setUpClass(cls):
        import os
        path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                            "System32", "kernel32.dll")
        if not os.path.exists(path):
            raise unittest.SkipTest(f"no system DLL at {path}")
        # Once for the class: a full sweep of a real binary is seconds, and
        # doing it per test made this module the slowest in the suite.
        from pydbg.analysis import analyze_file
        cls.result = analyze_file(path)

    def setUp(self):
        if not hasattr(self.__class__, "result"):
            self.skipTest("no system DLL to analyse")

    def test_some_indirect_branches_resolve(self):
        self.assertGreater(self.result.stats.indirect_resolved, 0)

    def test_some_stay_unknown_and_the_graph_says_so(self):
        """The call graph is still incomplete, and must not read as complete."""
        self.assertGreater(self.result.stats.indirect_unknown, 0)
        self.assertFalse(self.result.call_graph_is_complete())
        self.assertIn("incomplete", self.result.render_summary())


if __name__ == "__main__":
    unittest.main()
