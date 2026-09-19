"""Tests for the static analysis core.

Code fixtures are hand-assembled x86 bytes with the encodings written out, so
each one says exactly which instructions it contains. Several of these tests
exist to pin a specific way the traversal can be wrong — a conditional jump
treated as terminal, a call followed inline, a decode repeated and counted
twice — because those produce plausible-looking output rather than errors.
"""

import unittest

from tests.pe_builder import PEBuilder

IMAGE_BASE = 0x400000
TEXT_RVA = 0x1000


def build_text(code, entry_rva=TEXT_RVA):
    """A PE32 image whose .text is 'code' at RVA 0x1000."""
    builder = PEBuilder(magic=0x10B, image_base=IMAGE_BASE,
                        entry_rva=entry_rva)
    builder.add_section(".text", code, TEXT_RVA)
    return builder.build()


def rel32(call_rva, target_rva):
    """The rel32 for a 5-byte call/jmp at 'call_rva' reaching 'target_rva'."""
    return (target_rva - (call_rva + 5)) & 0xFFFFFFFF


def call_to(target_rva, at_rva=TEXT_RVA):
    return b"\xe8" + rel32(at_rva, target_rva).to_bytes(4, "little")


RET = b"\xc3"
NOP = b"\x90"


class TestTraversalRules(unittest.TestCase):
    """The traversal semantics, each pinned by a case that would otherwise
    pass for the wrong reason."""

    def analyze(self, code, **kwargs):
        from pydbg.analysis import analyze_bytes
        return analyze_bytes(build_text(code), **kwargs)

    def test_reaches_a_function_only_a_call_reveals(self):
        """The fixpoint. A callee named nowhere but a call instruction.

        Without folding discovered call targets back into the worklist, this
        function is never decoded — the difference between 7% and 99% coverage
        on a real binary, entirely made of functions like this one.
        """
        code = call_to(0x1020) + RET + NOP * (0x1020 - 0x1006) + RET
        result = self.analyze(code)

        self.assertIn(0x1020, result.functions.starts)
        self.assertIn(0x1020, result.functions.confident,
                      "a call target is the strongest evidence there is")
        # 5-byte call + ret at 0x1005 + ret at 0x1020. If the callee were not
        # swept, the last byte would be missing.
        self.assertEqual(result.coverage[".text"].covered, 7)

    def test_conditional_jump_is_not_terminal(self):
        """Both the target AND the fallthrough must be decoded.

        Treating a conditional jump as terminal silently drops every false
        branch — the fallthrough path here would never be decoded, and the
        count would be 3 rather than 4.
        """
        # 0x1000: jne 0x1004 (75 02)  fallthrough 0x1002, target 0x1004
        # 0x1002: ret
        # 0x1003: nop   <- unreachable, must NOT be decoded
        # 0x1004: ret
        code = b"\x75\x02" + RET + NOP + RET
        result = self.analyze(code)

        # "Reached", not "a function starts here": a branch target inside
        # its own function is decoded as a code seed, not an entry.
        self.assertTrue(result.decoder.is_decoded(0x1004),
                        "branch target was never decoded")
        self.assertEqual(result.coverage[".text"].covered, 4)

    def test_call_does_not_inline_the_callee(self):
        """A call queues its target; it does not follow it.

        Following it inline runs into the callee's `ret` and ends the caller's
        path early, so the instruction after the call is never decoded and the
        count drops from 8 to 6.
        """
        # 0x1000: call 0x1020
        # 0x1005: nop          <- must still be decoded
        # 0x1006: ret
        # 0x1020: ret
        code = call_to(0x1020) + NOP + RET + NOP * (0x1020 - 0x1007) + RET
        result = self.analyze(code)

        self.assertIn(0x1020, result.functions.starts, "callee not registered")
        self.assertEqual(result.coverage[".text"].covered, 8)

    def test_ret_ends_the_path(self):
        """Nothing after a ret is decoded when only the entry point seeds it."""
        code = RET + NOP + NOP + NOP
        result = self.analyze(code)
        self.assertEqual(result.coverage[".text"].covered, 1)

    def test_unconditional_jump_ends_the_path_but_queues_the_target(self):
        """The bytes the jump passes over stay undecoded.

        If the jump were treated as conditional, the path would also continue
        into 0x1002 and the count would be 5 rather than 3.
        """
        # 0x1000: jmp 0x1004 (eb 02)  0x1002: nop (skipped)  0x1004: ret
        code = b"\xeb\x02" + NOP + NOP + RET
        result = self.analyze(code)
        # Reached, not "a function starts here": the target is inside the
        # function it belongs to, so it is decoded as a code seed.
        self.assertTrue(result.decoder.is_decoded(0x1004))
        self.assertEqual(result.coverage[".text"].covered, 3)

    def test_the_traversal_terminates(self):
        """A self-referential jump must not loop forever."""
        # 0x1000: jmp 0x1000 (eb fe) — an infinite loop in the target.
        result = self.analyze(b"\xeb\xfe")
        self.assertEqual(result.stats.insns, 1)


class TestAddressSpace(unittest.TestCase):
    """Decoding happens at the VA, which is what makes targets meaningful."""

    def test_a_direct_call_target_lands_inside_the_image(self):
        """Decoding at the RVA puts every relative target in the wrong space.

        Capstone derives a branch target from the base it is given, so passing
        an RVA yields RVA-shaped targets that then fail the image window test —
        and the result is zero cross-references on a binary full of them.
        """
        from pydbg.analysis import analyze_bytes
        result = analyze_bytes(build_text(call_to(0x1020) + RET +
                                          NOP * (0x1020 - 0x1006) + RET))
        self.assertTrue(result.xrefs, "no cross-references recovered at all")
        self.assertIn(0x1020, result.xrefs)
        sources = [x.source for x in result.xrefs[0x1020]]
        self.assertEqual(sources, [0x1000], "xref source should be an RVA")

    def test_callers_of_returns_the_calling_instruction(self):
        from pydbg.analysis import analyze_bytes
        result = analyze_bytes(build_text(call_to(0x1020) + RET +
                                          NOP * (0x1020 - 0x1006) + RET))
        self.assertEqual(result.callers_of(0x1020), (0x1000,))

    def test_a_small_immediate_is_not_treated_as_a_reference(self):
        """Only VAs inside the image count.

        Accepting any small constant as an RVA fills the index with noise, so
        `mov eax, 0x1234` must not produce a reference to RVA 0x1234.
        """
        from pydbg.analysis import analyze_bytes
        # 0x1000: mov eax, 0x1234 (b8 34 12 00 00)  0x1005: ret
        result = analyze_bytes(build_text(b"\xb8\x34\x12\x00\x00" + RET))
        self.assertEqual(result.stats.xrefs, 0)


class TestCoverageAccounting(unittest.TestCase):
    """Coverage is only honest with its overlap reported alongside."""

    def test_overlap_is_counted_when_decodes_collide(self):
        """A call into the middle of an instruction overlaps its bytes.

        Asserted rather than assumed: a counter that always reads zero looks
        exactly like a clean decode, and zero is the most reassuring — and
        therefore most misleading — number this metric could report.
        """
        from pydbg.analysis import analyze_bytes
        # 0x1000: mov eax, 0x12345678   (b8 78 56 34 12) — 5 bytes
        # 0x1005: call 0x1002           — a target INSIDE the mov, the shape a
        #                                 bad seed produces
        # 0x100a: ret
        # The call's target decodes to `push esi` / `xor al, 0x12`, which land
        # on bytes the mov already claimed.
        code = b"\xb8\x78\x56\x34\x12" + call_to(0x1002, 0x1005) + RET
        result = analyze_bytes(build_text(code))
        self.assertGreater(result.stats.overlap_bytes, 0)
        self.assertGreater(result.stats.overlap_conflicts, 0)

    def test_covered_never_exceeds_the_section(self):
        from pydbg.analysis import analyze_bytes
        result = analyze_bytes(build_text(call_to(0x1020) + RET +
                                          NOP * (0x1020 - 0x1006) + RET))
        report = result.coverage[".text"]
        self.assertLessEqual(report.covered, report.total)
        self.assertGreater(report.ratio, 0.0)
        self.assertLessEqual(report.ratio, 1.0)

    def test_a_callee_reached_twice_is_not_double_counted(self):
        """A path arriving where a sweep already decoded must be a no-op.

        The call queues 0x1008, and the caller's own fallthrough walks into it
        before that sweep runs. Re-claiming those bytes would count them as a
        conflict, making a clean decode look broken.
        """
        from pydbg.analysis import analyze_bytes
        # 0x1000: call 0x1008 (e8 03 00 00 00)  0x1005..0x1007: nop  0x1008: ret
        code = call_to(0x1008) + NOP * 3 + RET
        result = analyze_bytes(build_text(code))
        self.assertEqual(result.stats.overlap_bytes, 0)
        self.assertEqual(result.stats.overlap_conflicts, 0)

    def test_a_truncated_instruction_is_recorded_as_undecodable(self):
        """A seed that lands somewhere that will not decode is information.

        Recording these is what turns "coverage stopped here" into a statement
        about which seed was wrong, instead of silence.
        """
        from pydbg.analysis import analyze_bytes
        # A section holding the first two bytes of a five-byte call: nothing
        # capstone can decode a complete instruction from.
        result = analyze_bytes(build_text(b"\xe8\x01"))
        self.assertIn(TEXT_RVA, result.undecodable)


class TestFunctionTable(unittest.TestCase):

    def table(self, starts):
        from pydbg.analysis.functions import FunctionTable
        table = FunctionTable()
        for rva in starts:
            table.add_start(rva, confident=True)
        table.invalidate()
        return table

    def test_containing_finds_the_enclosing_function(self):
        table = self.table([0x1000, 0x1100, 0x1200])
        self.assertEqual(table.containing(0x1050), 0x1000)
        self.assertEqual(table.containing(0x1100), 0x1100)
        self.assertEqual(table.containing(0x11FF), 0x1100)

    def test_containing_before_the_first_start_is_none(self):
        table = self.table([0x1000])
        self.assertIsNone(table.containing(0x0FFF))

    def test_extent_is_bounded_by_the_next_start(self):
        """A function cannot run past where the next one begins."""
        from pydbg.analysis.functions import FunctionTable
        table = FunctionTable()
        table.add_start(0x1000, confident=True)
        table.add_start(0x1010, confident=True)
        # An instruction that claims far past the next function's start.
        table.note_instruction(0x1000, 4)
        table.note_instruction(0x1008, 0x40)
        table.invalidate()
        self.assertEqual(table.extent_of(0x1000), 0x10)

    def test_extents_match_the_naive_computation(self):
        """The bisect-backed extents must agree with the obvious O(n*m) form."""
        from pydbg.analysis.functions import FunctionTable
        table = FunctionTable()
        starts = [0x1000, 0x1100, 0x1200]
        for rva in starts:
            table.add_start(rva, confident=True)
        claims = {0x1000: 8, 0x1050: 4, 0x1100: 16, 0x1200: 2}
        for rva, size in claims.items():
            table.note_instruction(rva, size)
        table.invalidate()

        extents = table.extents()
        for start in starts:
            limit = min([s for s in starts if s > start], default=None)
            expected = max((rva + size for rva, size in claims.items()
                            if rva >= start and (limit is None or rva < limit)),
                           default=start)
            expected = max(expected - start, 0)
            if limit is not None:
                expected = min(expected, limit - start)
            self.assertEqual(extents[start], expected, f"start {start:#x}")


class TestImageGeometry(unittest.TestCase):

    def test_exec_sections_are_recognised(self):
        """Needs Characteristics parsed as a full dword.

        It used to be read as the high 16 bits only, so no section ever matched
        IMAGE_SCN_MEM_EXECUTE and the analyzer found nothing to walk.
        """
        from pydbg.analysis import AnalyzedImage
        image = AnalyzedImage.from_bytes(build_text(RET))
        text = image.section_of(TEXT_RVA)
        self.assertIsNotNone(text)
        self.assertTrue(text.is_exec)
        self.assertTrue(image.is_exec(TEXT_RVA))

    def test_va_translation_rejects_what_is_outside_the_image(self):
        from pydbg.analysis import AnalyzedImage
        image = AnalyzedImage.from_bytes(build_text(RET))
        self.assertEqual(image.va_to_rva(IMAGE_BASE + TEXT_RVA), TEXT_RVA)
        self.assertIsNone(image.va_to_rva(0x1234))
        self.assertIsNone(image.va_to_rva(IMAGE_BASE + image.span + 0x1000))

    def test_slot_size_follows_the_image(self):
        """Every seed reader's stride comes from here.

        Hard-coding 4 is the prototype's 32-bit assumption, and on a PE32+
        image it reads the low half of every pointer and the high half of the
        one before it.
        """
        from pydbg.analysis import AnalyzedImage
        self.assertEqual(AnalyzedImage.from_bytes(build_text(RET)).slot_size, 4)

        pe32plus = PEBuilder(magic=0x20B, image_base=0x140000000)
        pe32plus.add_section(".text", RET, TEXT_RVA)
        self.assertEqual(
            AnalyzedImage.from_bytes(pe32plus.build()).slot_size, 8)


if __name__ == "__main__":
    unittest.main()
