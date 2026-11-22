"""Tests for the decompiler core: S0 extent, S1 IR, S2 block expressions, S5 text.

Every fixture is hand-encoded machine code placed in a synthetic PE32+ section
by tests/pe_builder.py. Nothing here needs a real target: each byte is written
out in the test, so an expectation that moves says which encoding moved with it.
"""

import re
import unittest

from pydbg.pe import PE
from tests.pe_builder import PEBuilder

IMAGE_BASE = 0x140000000
TEXT_RVA = 0x1000


def build(code, entry_rva=TEXT_RVA, magic=0x20B, image_base=IMAGE_BASE):
    """A PE whose .text is 'code' at RVA 0x1000."""
    builder = PEBuilder(magic=magic, image_base=image_base,
                        entry_rva=entry_rva)
    builder.add_section(".text", code, TEXT_RVA)
    return PE(builder.build())


def analyze(code, entry_rva=TEXT_RVA, magic=0x20B, image_base=IMAGE_BASE):
    from pydbg.analysis import analyze_pe
    return analyze_pe(build(code, entry_rva=entry_rva, magic=magic,
                            image_base=image_base))


def decompile(code, rva=TEXT_RVA, magic=0x20B, image_base=IMAGE_BASE,
              **kwargs):
    from pydbg.analysis import decompile_function
    return decompile_function(
        analyze(code, magic=magic, image_base=image_base), rva, **kwargs)


# Encodings, named so the fixtures read as the instructions they are.
RET = b"\xc3"
NOP = b"\x90"
MOV_EAX_5 = b"\xb8\x05\x00\x00\x00"
ADD_EAX_3 = b"\x83\xc0\x03"


class TestStraightLine(unittest.TestCase):
    """A single block, lowered to register updates and a return."""

    def test_mov_then_add_renders_as_register_updates(self):
        """The three lines the API promises for a trivial function.

        'eax = 5' and 'eax = eax + 3' are separate statements on purpose: the
        update stays visible rather than being folded into 'eax = 8', which is
        what makes the output a listing of the instructions and not a claim
        that the function was evaluated.
        """
        result = decompile(MOV_EAX_5 + ADD_EAX_3 + RET)

        self.assertIsNotNone(result)
        self.assertIn("eax = 5", result.text)
        self.assertIn("eax = eax + 3", result.text)
        self.assertIn("return eax;", result.text)
        self.assertTrue(result.complete)
        self.assertEqual(result.warnings, ())
        self.assertEqual(result.blocks, (TEXT_RVA,))
        self.assertEqual(result.unhandled, ())


class TestBlockExpressions(unittest.TestCase):
    """S2: aliases, copies, constants and dead writes inside one block."""

    def test_lea_and_store_keep_the_operand_shape(self):
        """`lea eax,[rcx+8]` then `mov [rcx+8],eax` survives as the same shape.

        The effective address of the `lea` is arithmetic; the store's operand is
        memory. Both have to be readable as `[rcx + 8]`/`rcx + 8`, and neither
        may be spelled as a fabricated pointer.
        """
        result = decompile(bytes.fromhex("8d4108894108c3"))

        self.assertIn("eax = rcx + 8;", result.text)
        self.assertIn("[rcx + 8] = eax;", result.text)

    def test_register_copy_is_propagated_within_the_block(self):
        """`mov rdx,rax; mov rcx,rdx` reads as `rcx = rax`, not `rcx = rdx`."""
        result = decompile(bytes.fromhex("4889c24889d1c3"))

        self.assertIn("rdx = rax;", result.text)
        self.assertIn("rcx = rax;", result.text)

    def test_alias_write_kills_a_copy_that_depended_on_it(self):
        """A write to `eax` invalidates a copy whose source was `rax`.

        `rdx = rax` is true only until something writes any part of the rax
        family. The `mov eax, ecx` in the middle is exactly that, so the later
        `rcx = rdx` must not be rewritten to `rcx = rax`.
        """
        result = decompile(bytes.fromhex("4889c289c84889d1c3"))

        self.assertIn("rcx = rdx;", result.text)
        self.assertNotIn("rcx = rax;", result.text)

    def test_rip_relative_operand_resolves_like_refs_memory_address(self):
        """A fixed-address operand is resolved by the analysis's one converter.

        `refs.memory_address` is the single place an operand becomes an RVA.
        The lift must not recompute `next_instruction + disp` and the renderer
        must not print a `[rip + disp]` the reader has to finish resolving: the
        address is computed once and carried as an RVA.
        """
        from pydbg.analysis.refs import memory_address
        from pydbg.disasm.engine import OP_MEM
        code = bytes.fromhex("8b0500000000" "c3")     # mov eax, [rip]
        result = analyze(code)
        insn = result.decoder.decode_one(TEXT_RVA)
        operand = next(op for op in insn.operands if op.kind == OP_MEM)

        expected = memory_address(insn, operand, result.image)
        decompiled = decompile(code)

        self.assertEqual(expected, TEXT_RVA + 6)
        self.assertIn(f"[0x{expected:x}]", decompiled.text)

    def test_constant_is_folded_into_an_unrelated_destination(self):
        """A known constant on a source operand folds: `imul eax,ecx,4` -> 20.

        The destination of a read-modify-write keeps its spelling, but a
        constant read from elsewhere is real information and is folded.
        """
        result = decompile(bytes.fromhex("b9050000006bc104c3"))

        self.assertIn("ecx = 5;", result.text)
        self.assertIn("eax = 20;", result.text)

    def test_dead_write_is_kept_as_a_comment_not_dropped(self):
        """An overwritten write leaves the statement stream but not the text.

        `eax = 5` is dead because `eax = 6` follows with no read between. The
        instruction still has to be visible: its address and its code are kept
        on a `// dead:` line.
        """
        result = decompile(bytes.fromhex("b805000000" "b806000000" "c3"))

        self.assertIn("eax = 6;", result.text)
        dead_lines = [line for line in result.text.splitlines()
                      if line.strip().startswith("// dead:")]
        self.assertEqual(len(dead_lines), 1, result.text)
        self.assertIn("eax = 5", dead_lines[0])
        self.assertIn("@0x1000", dead_lines[0])

    def test_arithmetic_is_not_dead_even_when_its_result_is(self):
        """`add` also sets flags, so an unused register result is not enough.

        A later branch may read the flags this instruction wrote. Dropping the
        statement would leave the condition attached to a different
        instruction, which is a silent semantic change rather than cleanup.
        """
        result = decompile(bytes.fromhex("83c001" "b806000000" "c3"))

        self.assertIn("eax = eax + 1;", result.text)
        self.assertNotIn("// dead:", result.text)


class TestBlockSet(unittest.TestCase):
    """`blocks` is the CFG's own block set, not the renderer's block set."""

    def test_blocks_are_the_cfg_starts_and_extra_blocks_is_empty(self):
        """Without a jump table there is nothing the CFG did not build."""
        from pydbg.analysis import build_function_cfg, decompile_function
        code = bytes.fromhex("85c07704" "83c001" "c3" "55" "c3")
        result = analyze(code)
        cfg = build_function_cfg(result.decoder, result.image,
                                 result.functions, TEXT_RVA)

        decompiled = decompile_function(result, TEXT_RVA)

        self.assertEqual(decompiled.blocks, tuple(sorted(cfg.blocks)))
        self.assertEqual(decompiled.extra_blocks, ())


class TestUnhandled(unittest.TestCase):
    """Instructions outside the model stay visible and are counted once."""

    def test_cpuid_is_opaque_and_named_in_the_result(self):
        result = decompile(bytes.fromhex("0fa2c3"))

        self.assertEqual(result.unhandled, ((TEXT_RVA, "cpuid"),))
        self.assertEqual(result.text.count("// unhandled:"), 1)
        self.assertIn("// unhandled: cpuid", result.text)

    def test_every_opaque_instruction_has_exactly_one_line(self):
        """Two unmodelled instructions, two named entries, two comment lines."""
        result = decompile(bytes.fromhex("0fa20f05c3"))

        self.assertEqual(result.unhandled,
                         ((TEXT_RVA, "cpuid"), (TEXT_RVA + 2, "syscall")))
        self.assertEqual(result.text.count("// unhandled:"),
                         len(result.unhandled))

    def test_a_control_register_destination_is_opaque_not_a_dead_write(self):
        """`mov cr0, rax` changes the machine, so it cannot be a dead write.

        cr0 is not a general-purpose register: the integer model has no value
        for it and writing it has hardware effects a removed statement would
        erase. It belongs in the honest `// unhandled:` form, not in the
        `// dead:` comment that says "this instruction did nothing".
        """
        result = decompile(bytes.fromhex("0f22c0c3"))     # mov cr0, rax

        self.assertEqual(result.unhandled, ((TEXT_RVA, "mov"),))
        self.assertIn("// unhandled: mov cr0, rax", result.text)
        self.assertNotIn("// dead:", result.text)
        self.assertNotIn("cr0 =", result.text)

    def test_the_supported_subset_produces_no_opaque_statements(self):
        """mov/lea/add/cmp/test/jcc/call/ret/push/pop/nop are all modelled."""
        result = decompile(bytes.fromhex(
            "90"                     # nop
            "50"                     # push rax
            "58"                     # pop rax
            "b805000000"             # mov eax, 5
            "83c003"                 # add eax, 3
            "8d4801"                 # lea ecx, [rax + 1]
            "85c0"                   # test eax, eax
            "c3"                     # ret
        ))

        self.assertEqual(result.unhandled, (), result.text)


class TestControlFlow(unittest.TestCase):
    """Labels, gotos and conditions, with the entry block labelled by name."""

    def test_jump_forward_and_call_use_labels_and_goto(self):
        """A forward `jmp` becomes a goto, and the call names its callee."""
        code = bytearray(b"\x55" * 0x21)
        code[0:2] = bytes.fromhex("eb04")            # jmp 0x1006
        code[6:11] = bytes.fromhex("e815000000")     # call 0x1020
        code[0x0b] = 0xC3
        code[0x20] = 0xC3

        result = decompile(bytes(code))

        self.assertEqual(result.blocks, (TEXT_RVA, TEXT_RVA + 6))
        self.assertIn("goto L_1006;", result.text)
        self.assertIn("L_1006:", result.text)
        self.assertIn("sub_1020();", result.text)
        self.assertTrue(result.complete)

    def test_conditional_branch_keeps_its_flag_condition(self):
        """`je` is modelled as zf, which is the table's contract."""
        result = decompile(bytes.fromhex("83f8057404c3") + b"\x55" * 3 + b"\xc3")

        self.assertEqual(result.blocks, (TEXT_RVA, 0x1005, 0x1009))
        self.assertIn("eflags = cmp(eax, 5);", result.text)
        self.assertIn("if (eflags.zf) goto L_1009;", result.text)

    def test_unsigned_above_reads_cf_and_zf_together(self):
        result = decompile(bytes.fromhex("85c07704c3") + b"\x55" * 3 + b"\xc3")

        self.assertIn("if (!eflags.cf && !eflags.zf) goto L_1008;",
                      result.text)

    def test_indirect_jump_is_reported_incomplete(self):
        """A jump through a register has no target; saying so is the contract."""
        result = decompile(bytes.fromhex("ffe0"))

        self.assertFalse(result.complete)
        self.assertEqual(result.warnings, ("unresolved edges",))
        self.assertIn("goto *rax;", result.text)

    def test_a_backward_jump_targets_the_function_label(self):
        """The entry block has one label -- `sub_<hex>` -- and goto uses it.

        Emitting `goto L_1000;` would name a label that is never defined,
        because the entry is introduced by its function name.
        """
        result = decompile(bytes.fromhex("ebfe"))      # jmp to itself

        self.assertIn("goto sub_1000;", result.text)
        self.assertNotIn("L_1000", result.text)


class TestNoSilentDrop(unittest.TestCase):
    """Every decoded instruction in the CFG must appear in the text."""

    def test_every_cfg_instruction_is_referenced(self):
        """The union of label references and address comments covers the CFG.

        This is the acceptance check from the spec, written as set equality
        rather than a spot check: a spot check passes while one instruction in
        the middle has quietly vanished.
        """
        from pydbg.analysis import build_function_cfg
        code = bytes.fromhex("85c07704" "83c001" "c3" "55" "c3")
        result = analyze(code)
        decompiled = decompile(code)

        cfg = build_function_cfg(result.decoder, result.image,
                                 result.functions, TEXT_RVA)
        instructions = {rva for block in cfg.blocks.values()
                        for rva in block.instructions}

        comments = {int(value, 16)
                    for value in re.findall(r"@0x([0-9a-f]+)",
                                            decompiled.text)}
        labels = {int(value, 16)
                  for value in re.findall(r"L_([0-9a-f]+)",
                                          decompiled.text)}
        self.assertEqual(comments | labels, instructions,
                         f"missing from text:\n{decompiled.text}")
        self.assertEqual(decompiled.text.count("// unhandled:"),
                         len(decompiled.unhandled))


class TestFailureAndHonesty(unittest.TestCase):
    """The boundaries: not a function, nothing to decode, truncated, stable."""

    def test_an_rva_that_is_not_a_function_start_returns_none(self):
        result = analyze(MOV_EAX_5 + ADD_EAX_3 + RET)
        from pydbg.analysis import decompile_function

        self.assertIsNone(decompile_function(result, 0x1005))

    def test_a_function_with_nothing_decodable_returns_none(self):
        """An entry point whose bytes never decode has no decompilation."""
        self.assertIsNone(decompile(b"\xc4"))

    def test_truncation_is_reported_in_complete_and_warnings(self):
        code = bytearray(b"\x55" * 0x21)
        code[0:2] = bytes.fromhex("eb04")
        code[6:11] = bytes.fromhex("e815000000")
        code[0x0b] = 0xC3
        code[0x20] = 0xC3
        result = analyze(bytes(code))
        from pydbg.analysis import decompile_function

        truncated = decompile_function(result, TEXT_RVA, max_blocks=1)
        self.assertIsNotNone(truncated)
        self.assertFalse(truncated.complete)
        self.assertIn("truncated", truncated.warnings)
        self.assertEqual(truncated.blocks, (TEXT_RVA,))

    def test_two_calls_produce_byte_identical_text(self):
        """No set iteration order reaches the text."""
        code = bytes.fromhex("85c07704" "83c001" "c3" "55" "c3")
        result = analyze(code)
        from pydbg.analysis import decompile_function

        first = decompile_function(result, TEXT_RVA)
        second = decompile_function(result, TEXT_RVA)
        self.assertEqual(first.text.encode("utf-8"),
                         second.text.encode("utf-8"))


class TestFlagDeclarations(unittest.TestCase):
    """The EFLAGS pseudo-register contract the spec states in ir.py."""

    def lower_first(self, code):
        """The statements one instruction lowers to, inside a decodable image."""
        from pydbg.analysis.decompile import ir

        result = analyze(code + RET)
        insn = result.decoder.decode_one(TEXT_RVA)
        return ir.lower_instruction(result.decoder, result.image, insn)

    def test_arithmetic_declares_all_six_flags(self):
        from pydbg.analysis.decompile import ir

        self.assertEqual(ir.flags_written("add"), ir.EFLAGS_REGISTERS)
        self.assertEqual(len(ir.flags_written("sub")), 6)

    def test_a_branch_declares_only_the_flags_it_reads(self):
        from pydbg.analysis.decompile import ir

        self.assertEqual(ir.flags_read("je"), ("zf",))
        self.assertEqual(ir.flags_read("ja"), ("cf", "zf"))
        self.assertEqual(ir.flags_read("jg"), ("zf", "sf", "of"))

    def test_not_does_not_claim_to_write_flags(self):
        from pydbg.analysis.decompile import ir

        self.assertEqual(ir.flags_written("not"), ())

    def test_flag_writing_statements_carry_the_flags(self):
        """The declaration has to reach the statements, or it is decorative.

        `add`, `cmp` and `test` all write all six flags in the conservative
        model; the statement they lower to says so.
        """
        from pydbg.analysis.decompile import ir

        for name, code in (("add", "83c003"), ("cmp", "83f805"),
                           ("test", "85c0")):
            with self.subTest(instruction=name):
                stmt = self.lower_first(bytes.fromhex(code))[0]
                self.assertEqual(stmt.flags_written, ir.ALL_FLAGS)

    def test_a_branch_statement_carries_the_flags_it_reads(self):
        """A branch reads the condition table's subset, not all six."""
        for code, expected in (("7400", ("zf",)), ("7700", ("cf", "zf"))):
            with self.subTest(condition=expected):
                stmt = self.lower_first(bytes.fromhex(code))[0]
                self.assertEqual(stmt.flags_read, expected)

    def test_not_carries_no_flags_through_recovery(self):
        """`not` has no flag effect, and expression recovery keeps that fact."""
        from pydbg.analysis.decompile import expr, ir

        stmt = self.lower_first(bytes.fromhex("f7d0"))[0]
        self.assertEqual(stmt.flags_written, ())
        block = ir.IRBlock(rva=TEXT_RVA, stmts=(stmt,))
        recovered = expr.recover({TEXT_RVA: block}, "x64")
        self.assertEqual(recovered[TEXT_RVA].stmts[0].flags_written, ())

    def test_arithmetic_flags_survive_expression_recovery(self):
        """Recovery rebuilds the statement; it must carry the declaration over."""
        from pydbg.analysis.decompile import expr, ir

        stmt = self.lower_first(bytes.fromhex("83c003"))[0]
        block = ir.IRBlock(rva=TEXT_RVA, stmts=(stmt,))
        recovered = expr.recover({TEXT_RVA: block}, "x64")
        self.assertEqual(recovered[TEXT_RVA].stmts[0].flags_written,
                         ir.ALL_FLAGS)


class TestArchitecture(unittest.TestCase):
    """The stack pointer is named after the image, not hard-coded."""

    def test_x86_stack_operations_use_esp(self):
        """A 32-bit image moves 4 bytes through esp; 'rsp' would be a fiction."""
        result = decompile(bytes.fromhex("5058c3"), magic=0x10B,
                           image_base=0x400000)

        self.assertIn("[esp - 4] = eax;", result.text)
        self.assertIn("esp = esp - 4;", result.text)
        self.assertIn("eax = [esp];", result.text)
        self.assertIn("esp = esp + 4;", result.text)
        self.assertNotIn("rsp", result.text)
