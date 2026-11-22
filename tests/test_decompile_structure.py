"""Tests for S4 structuring: if/else, loops, switch, irreducibility.

Every fixture is hand-encoded x64 placed in a synthetic PE by
``tests/pe_builder.py``. Each assertion is about a shape the text must have
(keyword, nesting, condition), never about a whole golden paragraph: the point
of the pass is readable structure, and a byte-for-byte paragraph would break on
every harmless change without saying anything about control flow.

The invariants P5 established stay: every decoded instruction is still visible
through its address comment, ``// unhandled:`` lines still count the opaque
statements, and two calls produce identical bytes.
"""

import re
import struct
import time
import unittest

from pydbg.pe import PE
from tests.pe_builder import PEBuilder

IMAGE_BASE = 0x140000000
TEXT_RVA = 0x1000


def build(code, entry_rva=TEXT_RVA, magic=0x20B, image_base=IMAGE_BASE,
          extra_sections=()):
    """A PE whose .text is 'code' at RVA 0x1000, plus any extra sections."""
    builder = PEBuilder(magic=magic, image_base=image_base,
                        entry_rva=entry_rva)
    builder.add_section(".text", code, TEXT_RVA)
    for name, data, rva, characteristics in extra_sections:
        builder.add_section(name, data, rva, characteristics)
    return PE(builder.build())


def analyze(code, entry_rva=TEXT_RVA, magic=0x20B, image_base=IMAGE_BASE,
            extra_sections=()):
    from pydbg.analysis import analyze_pe
    return analyze_pe(build(code, entry_rva=entry_rva, magic=magic,
                            image_base=image_base,
                            extra_sections=extra_sections))


def decompile(code, rva=TEXT_RVA, image_base=IMAGE_BASE,
              extra_sections=(), **kwargs):
    from pydbg.analysis import decompile_function
    return decompile_function(
        analyze(code, image_base=image_base, extra_sections=extra_sections),
        rva, **kwargs)


def cfg_instructions(result, rva=TEXT_RVA):
    """The instruction RVAs of the CFG the decompiler was handed.

    Blocks overlap by construction (`build_function_cfg` re-decodes the bytes a
    branch target also starts), so this is a union rather than a sum. It is
    still the right set for the no-silent-drop check: every decoded instruction
    must be somewhere in the text.
    """
    from pydbg.analysis import build_function_cfg
    cfg = build_function_cfg(result.decoder, result.image,
                             result.functions, rva)
    return {addr for block in cfg.blocks.values()
            for addr in block.instructions}


def text_addresses(text):
    """Every address annotation in the text (`// @0x...`)."""
    return {int(value, 16)
            for value in re.findall(r"@0x([0-9a-f]+)", text)}


def text_labels(text):
    return {int(value, 16)
            for value in re.findall(r"L_([0-9a-f]+)", text)}


# ── fixtures ───────────────────────────────────────────────────
#
# The bytes are written with their addresses in comments so an assertion that
# moves says which encoding moved with it.

# cmp eax, 1 / jne else / mov eax, 2 / jmp end / else: mov eax, 3 / end: ret
IF_ELSE = bytes.fromhex(
    "83f801"        # 0x1000 cmp eax, 1
    "7507"          # 0x1003 jne 0x100c
    "b802000000"    # 0x1005 mov eax, 2
    "eb05"          # 0x100a jmp 0x1011
    "b803000000"    # 0x100c mov eax, 3
    "c3"            # 0x1011 ret
)

# eax = 0; while (eax < 5) { eax += 1; } return;
WHILE = bytes.fromhex(
    "b800000000"    # 0x1000 mov eax, 0
    "83f805"        # 0x1005 cmp eax, 5
    "7d05"          # 0x1008 jge 0x100f
    "83c001"        # 0x100a add eax, 1
    "ebf6"          # 0x100d jmp 0x1005
    "c3"            # 0x100f ret
)

# eax = 3; do { eax -= 1; } while (eax != 0); return;
DO_WHILE = bytes.fromhex(
    "b803000000"    # 0x1000 mov eax, 3
    "83e801"        # 0x1005 sub eax, 1
    "83f800"        # 0x1008 cmp eax, 0
    "75f8"          # 0x100b jne 0x1005
    "c3"            # 0x100d ret
)

# Two nested counter loops; the inner body breaks on j == 2 and continues on
# j == 1, so the text must say both words.
NESTED = bytes.fromhex(
    "b900000000"    # 0x1000 mov ecx, 0
    "83f903"        # 0x1005 cmp ecx, 3
    "7d1e"          # 0x1008 jge 0x1028
    "ba00000000"    # 0x100a mov edx, 0
    "83fa03"        # 0x100f cmp edx, 3
    "7d0f"          # 0x1012 jge 0x1023
    "83fa02"        # 0x1014 cmp edx, 2
    "740a"          # 0x1017 je 0x1023
    "83fa01"        # 0x1019 cmp edx, 1
    "74f1"          # 0x101c je 0x100f
    "83c201"        # 0x101e add edx, 1
    "ebec"          # 0x1021 jmp 0x100f
    "83c101"        # 0x1023 add ecx, 1
    "ebdd"          # 0x1026 jmp 0x1005
    "c3"            # 0x1028 ret
)

# Two entries into one cycle: 0x1004 and 0x100a jump at each other, and both
# are reached from the entry block. No single header dominates the cycle, so it
# is irreducible and must come out as labels and gotos.
IRREDUCIBLE = bytes.fromhex(
    "85c0"          # 0x1000 test eax, eax
    "7506"          # 0x1002 jne 0x100a
    "83f801"        # 0x1004 cmp eax, 1
    "7501"          # 0x1007 jne 0x100a
    "c3"            # 0x1009 ret
    "83f802"        # 0x100a cmp eax, 2
    "74f5"          # 0x100d je 0x1004
    "c3"            # 0x100f ret
)

# switch (eax) with four cases and a default, dispatched through a jump table:
#   cmp eax, 3 / ja default / jmp [rax*8 + table]
SWITCH_BASE = 0x400000
SWITCH_TABLE_RVA = 0x2000
SWITCH_CASE_RVAS = (0x1010, 0x1018, 0x1020, 0x1028)
SWITCH = bytes.fromhex(
    "83f803"                  # 0x1000 cmp eax, 3
    "772b"                    # 0x1003 ja 0x1030
    "ff24c500204000"          # 0x1005 jmp [rax*8 + 0x402000]
    "90909090"                # 0x100c padding (never decoded)
    "b800000000" "eb21" "90"  # 0x1010 case 0: eax = 0; jmp 0x1038
    "b801000000" "eb19" "90"  # 0x1018 case 1: eax = 1; jmp 0x1038
    "b802000000" "eb11" "90"  # 0x1020 case 2: eax = 2; jmp 0x1038
    "b803000000" "eb09" "90"  # 0x1028 case 3: eax = 3; jmp 0x1038
    "b863000000" "eb01" "90"  # 0x1030 default: eax = 99; jmp 0x1038
    "c3"                      # 0x1038 ret
)


# The same four-way dispatch written as a pure compare chain, with no table:
# structurable as nested ifs, never as a switch.
SWITCH_CHAIN = bytes.fromhex(
    "83f800" "741b"            # 0x1000 cmp eax, 0; je 0x1020
    "83f801" "741e"            # 0x1005 cmp eax, 1; je 0x1028
    "83f802" "7421"            # 0x100a cmp eax, 2; je 0x1030
    "83f803" "7424"            # 0x100f cmp eax, 3; je 0x1038
    "b863000000" "eb25"        # 0x1014 default: eax = 99; jmp 0x1040
    "9090909090"               # 0x101b padding
    "b800000000" "eb19" "90"   # 0x1020 case 0
    "b801000000" "eb11" "90"   # 0x1028 case 1
    "b802000000" "eb09" "90"   # 0x1030 case 2
    "b803000000" "eb01" "90"   # 0x1038 case 3
    "c3"                       # 0x1040 ret
)


# A loop whose body has one exit to the block after the loop and one jump
# straight past it: the second edge crosses the loop's region and cannot be a
# structured break.
CROSS_EDGE = bytes.fromhex(
    "b900000000"    # 0x1000 mov ecx, 0
    "83f903"        # 0x1005 cmp ecx, 3
    "7d0a"          # 0x1008 jge 0x1014 (the loop exit)
    "83f901"        # 0x100a cmp ecx, 1
    "7406"          # 0x100d je 0x1015  (past the exit: a cross edge)
    "83c101"        # 0x100f add ecx, 1
    "ebf1"          # 0x1012 jmp 0x1005
    "90"            # 0x1014 nop (loop exit)
    "c3"            # 0x1015 ret
)


# A switch whose last case ends exactly where `.pdata` says its function ends.
# Function A is [0x1000, 0x101D); 0x101D..0x102F is 0x90 padding and function B
# starts at 0x1030. Case 1's body has no terminator, so a block that is not
# bounded by A's end follows its fall-through into the padding and then B.
def _bounded_switch_code():
    code = bytearray(b"\x90" * 0x40)
    code[0x00:0x03] = bytes.fromhex("83f801")            # cmp eax, 1
    code[0x03:0x05] = bytes.fromhex("7707")              # ja 0x100c
    code[0x05:0x0c] = bytes.fromhex("ff24c500204000")    # jmp [rax*8+table]
    code[0x0c:0x0e] = bytes.fromhex("31c0")              # default: xor eax,eax
    code[0x0e] = 0xC3                                    # ret
    code[0x10:0x15] = bytes.fromhex("b807000000")        # case 0: eax = 7
    code[0x18:0x1d] = bytes.fromhex("b808000000")        # case 1: eax = 8
    code[0x30:0x35] = bytes.fromhex("b809000000")        # B: eax = 9
    code[0x35] = 0xC3                                    # B: ret
    return bytes(code)


BOUNDED_SWITCH = _bounded_switch_code()
BOUNDED_FUNCTION_END = 0x101D
BOUNDED_NEXT_FUNCTION = 0x1030
BOUNDED_CASE_RVAS = (0x1010, 0x1018)


def bounded_switch_image():
    """A PE whose `.pdata` ends A before the padding and function B."""
    builder = PEBuilder(magic=0x20B, image_base=SWITCH_BASE,
                        entry_rva=TEXT_RVA)
    builder.add_section(".text", BOUNDED_SWITCH, TEXT_RVA)
    builder.add_section(
        ".rdata",
        struct.pack("<QQ", *[SWITCH_BASE + rva for rva in BOUNDED_CASE_RVAS]),
        SWITCH_TABLE_RVA, 0x40000040)
    pdata = (struct.pack("<III", TEXT_RVA, BOUNDED_FUNCTION_END, 0)
             + struct.pack("<III", BOUNDED_NEXT_FUNCTION,
                           BOUNDED_NEXT_FUNCTION + 7, 0))
    builder.add_section(".pdata", pdata, 0x3000, 0x40000040)
    builder.add_dir(3, 0x3000, len(pdata))
    return builder.build()


def switch_table(base=SWITCH_BASE, rvas=SWITCH_CASE_RVAS):
    """The jump table's slots, as VAs the image base makes absolute."""
    return struct.pack("<" + "Q" * len(rvas),
                       *[base + rva for rva in rvas])


def switch_extra(base=SWITCH_BASE, rvas=SWITCH_CASE_RVAS):
    return ((".rdata", switch_table(base, rvas), SWITCH_TABLE_RVA,
             0x40000040),)


# Full-text goldens for the two smallest canonical shapes. They are the spec's
# "golden" acceptance written down: keyword assertions keep the other shapes
# readable, but these two pin the exact bytes a caller receives.
IF_ELSE_TEXT = """\
sub_1000:
  if (eax == 1) {  // @0x1000, @0x1003, @0x100a
    eax = 2;  // @0x1005
  } else {
    eax = 3;  // @0x100c
  }
  return rax;  // @0x1011
"""

WHILE_TEXT = """\
sub_1000:
  eax = 0;  // @0x1000
  while (eax < 5) {  // @0x1005, @0x1008, @0x100d
    eax = eax + 1;  // @0x100a
  }
  return rax;  // @0x100f
"""


class TestIfElse(unittest.TestCase):
    """A branch with two merge arms becomes an if/else, not two gotos."""

    def test_the_whole_text_is_the_golden(self):
        """Byte-for-byte: the construct, its indentation and its comments."""
        self.assertEqual(decompile(IF_ELSE).text, IF_ELSE_TEXT)

    def test_both_arms_appear_inside_one_if(self):
        """`jne` + two assignments + a join is the canonical if/else.

        The comparison is folded into the condition (`eax == 1`, not
        `eflags.zf`) because the `cmp` is immediately before the branch and its
        operands are registers. The branch taken at 0x1003 goes to the *else*
        arm, so the printed condition is the fall-through's: `eax == 1`.
        """
        result = decompile(IF_ELSE)

        self.assertIsNotNone(result)
        self.assertIn("if (eax == 1) {", result.text)
        self.assertIn("} else {", result.text)
        self.assertIn("eax = 2;", result.text)
        self.assertIn("eax = 3;", result.text)

    def test_arms_are_indented_below_the_if(self):
        """Nesting is real, not just keywords: body lines are four spaces in."""
        lines = decompile(IF_ELSE).text.splitlines()

        then_lines = [line for line in lines if "eax = 2;" in line]
        else_lines = [line for line in lines if "eax = 3;" in line]
        self.assertEqual(len(then_lines), 1, lines)
        self.assertEqual(len(else_lines), 1, lines)
        self.assertTrue(then_lines[0].startswith("    "), then_lines[0])
        self.assertTrue(else_lines[0].startswith("    "), else_lines[0])

    def test_the_join_is_rendered_once_after_the_if(self):
        """The merge block's `ret` is outside the if and appears once."""
        text = decompile(IF_ELSE).text

        returns = [line for line in text.splitlines()
                   if line.strip().startswith("return")]
        self.assertEqual(len(returns), 1, text)
        self.assertNotIn("goto", text)


class TestWhile(unittest.TestCase):
    """A natural loop whose latch jumps back to its test is a `while`."""

    def test_the_whole_text_is_the_golden(self):
        """Byte-for-byte: the test at the top, no goto, one return."""
        self.assertEqual(decompile(WHILE).text, WHILE_TEXT)

    def test_the_test_becomes_the_loop_condition(self):
        """`jge exit` becomes `while (eax < 5)`: the exit edge is negated."""
        result = decompile(WHILE)

        self.assertIn("while (eax < 5) {", result.text)
        self.assertIn("eax = eax + 1;", result.text)

    def test_the_body_is_nested_and_the_back_edge_is_implicit(self):
        """No `goto` is needed: the loop node states the repetition."""
        lines = decompile(WHILE).text.splitlines()

        body = [line for line in lines if "eax = eax + 1;" in line]
        self.assertEqual(len(body), 1, lines)
        self.assertTrue(body[0].startswith("    "), body[0])
        self.assertNotIn("goto", "\n".join(lines))


class TestDoWhile(unittest.TestCase):
    """A conditional latch is a bottom-tested loop, not a while."""

    def test_the_latch_test_closes_the_do_block(self):
        result = decompile(DO_WHILE)

        self.assertIn("do {", result.text)
        self.assertIn("} while (eax != 0);", result.text)
        self.assertIn("eax = eax - 1;", result.text)
        self.assertNotIn("goto", result.text)

    def test_the_body_is_indented_between_do_and_while(self):
        lines = decompile(DO_WHILE).text.splitlines()

        body = [line for line in lines if "eax = eax - 1;" in line]
        self.assertEqual(len(body), 1, lines)
        self.assertTrue(body[0].startswith("    "), body[0])


class TestNestedLoops(unittest.TestCase):
    """Two loops and an early exit: break and continue, not gotos."""

    def test_both_loops_are_structured(self):
        text = decompile(NESTED).text

        self.assertEqual(text.count("while ("), 2, text)
        self.assertNotIn("goto", text)

    def test_early_exit_and_back_edge_use_break_and_continue(self):
        text = decompile(NESTED).text

        self.assertEqual(text.count("break;"), 1, text)
        self.assertEqual(text.count("continue;"), 1, text)
        self.assertIn("if (edx == 2) {", text)
        self.assertIn("if (edx == 1) {", text)

    def test_the_nesting_is_two_levels_deep(self):
        """The inner if sits six spaces in; its body eight."""
        lines = decompile(NESTED).text.splitlines()

        inner_if = [line for line in lines if "if (edx == 2) {" in line]
        inner_break = [line for line in lines if "break;" in line]
        self.assertEqual(len(inner_if), 1, lines)
        self.assertEqual(len(inner_break), 1, lines)
        self.assertTrue(inner_if[0].startswith("      "), inner_if[0])
        self.assertTrue(inner_break[0].startswith("        "), inner_break[0])


class TestSwitch(unittest.TestCase):
    """A SlotTable that pairs with a bounds check is a switch."""

    def test_the_table_becomes_a_switch_with_every_case(self):
        result = decompile(SWITCH, image_base=SWITCH_BASE,
                           extra_sections=switch_extra())

        self.assertIn("switch (eax) {", result.text)
        for index in range(4):
            self.assertIn(f"case {index}:", result.text)
        self.assertIn("default:", result.text)
        self.assertEqual(result.text.count("case "), 4, result.text)

    def test_case_bodies_come_from_the_table_targets(self):
        """The CFG cannot follow the indirect edge; the table supplies them.

        Each slot names a block the analysis decoded. Adding them to the
        function is what makes the cases visible, and each body is rendered
        under its own `case`.
        """
        result = decompile(SWITCH, image_base=SWITCH_BASE,
                           extra_sections=switch_extra())

        addresses = text_addresses(result.text)
        for case_rva in SWITCH_CASE_RVAS:
            self.assertIn(case_rva, addresses, result.text)
        self.assertIn("eax = 99;", result.text)          # the default body
        self.assertIn(0x1038, result.blocks)             # the merge

    def test_blocks_are_cfg_starts_and_extra_blocks_hold_case_starts(self):
        """The CFG never built the case blocks; they are reported separately.

        `blocks` is the CFG's block set and nothing else, so a caller comparing
        the decompiler against `build_function_cfg` is comparing like with
        like. The jump-table targets live in `extra_blocks`, and the warning
        says the block set grew.
        """
        from pydbg.analysis import build_function_cfg, decompile_function
        result = analyze(SWITCH, image_base=SWITCH_BASE,
                         extra_sections=switch_extra())
        cfg = build_function_cfg(result.decoder, result.image,
                                 result.functions, TEXT_RVA)

        decompiled = decompile_function(result, TEXT_RVA)

        self.assertEqual(decompiled.blocks, tuple(sorted(cfg.blocks)))
        self.assertEqual(tuple(sorted(decompiled.extra_blocks)),
                         SWITCH_CASE_RVAS)
        self.assertIn("jump-table blocks", decompiled.warnings)
        for case_rva in SWITCH_CASE_RVAS:
            self.assertNotIn(case_rva, decompiled.blocks)

    def test_the_unresolved_dispatch_edge_is_still_reported(self):
        """Structuring a switch does not make the CFG's window dressing true.

        The edge itself was unresolved when the CFG was built, so `complete`
        stays False even though the text shows every case. That is the P5 rule
        and the switch is a presentation of it, not a claim that the analysis
        resolved the branch.
        """
        result = decompile(SWITCH, image_base=SWITCH_BASE,
                           extra_sections=switch_extra())

        self.assertFalse(result.complete)
        self.assertIn("unresolved edges", result.warnings)


class TestSwitchFallback(unittest.TestCase):
    """No pairing, no switch: the flat form stays and says why."""

    def test_a_table_shaped_jump_without_a_table_stays_a_goto(self):
        result = decompile(SWITCH, image_base=SWITCH_BASE,
                           extra_sections=((".rdata", b"\x00" * 0x40,
                                            SWITCH_TABLE_RVA, 0x40000040),))

        self.assertNotIn("switch (", result.text)
        self.assertIn("goto *", result.text)
        self.assertIn("unmatched jump table", result.warnings)

    def test_a_compare_chain_without_a_table_is_an_if_chain(self):
        result = decompile(SWITCH_CHAIN)

        self.assertNotIn("switch (", result.text)
        self.assertEqual(result.text.count("if ("), 4, result.text)
        for rva in (0x1020, 0x1028, 0x1030, 0x1038):
            self.assertIn(rva, text_addresses(result.text), result.text)


class TestJumpTableBound(unittest.TestCase):
    """A jump-table case block still belongs to the function that owns it."""

    def test_a_case_body_stops_at_the_function_end(self):
        """Without a bound, the last case swallows padding and the next function.

        The case at 0x1018 has no terminator; its bytes run into 0x90 padding
        at 0x101D and into function B at 0x1030. `.pdata` says A ends at
        0x101D, and that is where the case block must stop -- B is a different
        function and the padding is not code.
        """
        from pydbg.analysis import analyze_pe, decompile_function
        result = analyze_pe(PE(bounded_switch_image()))

        decompiled = decompile_function(result, TEXT_RVA)

        self.assertIsNotNone(decompiled)
        addresses = text_addresses(decompiled.text)
        self.assertIn(0x1018, addresses, decompiled.text)
        self.assertNotIn(BOUNDED_FUNCTION_END, addresses, decompiled.text)
        self.assertNotIn(BOUNDED_NEXT_FUNCTION, addresses, decompiled.text)
        self.assertFalse(addresses & set(range(BOUNDED_FUNCTION_END,
                                               BOUNDED_NEXT_FUNCTION + 7)),
                         decompiled.text)


class TestUnmodeledCondition(unittest.TestCase):
    """A terminator with no modelled condition is not invented into an `if`."""

    # test eax,eax / loop 0x100a / nop / jmp 0x100b / nops / ret.
    # `loop` is a conditional jump to capstone, but it is outside the condition
    # table, so the lift keeps it as an Opaque statement.
    LOOP_TERMINATED = bytes.fromhex("85c0e20690eb04" "90909090" "c3")

    def test_a_loop_terminator_stays_flat_and_says_why(self):
        """`complete=True` with `if (!?)` was a claim the analysis could not back.

        The block's condition was never lowered, so there is no truth value to
        test. The flat form states the edge and its reason; the warning says
        the same thing to a caller that reads the result instead of the text.
        """
        result = decompile(self.LOOP_TERMINATED)

        self.assertIsNotNone(result)
        self.assertNotIn("if (", result.text)
        self.assertNotIn("!?", result.text)
        self.assertIn("condition not modeled", result.text)
        self.assertIn("condition not modeled", result.warnings)
        self.assertEqual(result.text.count("// unhandled:"),
                         len(result.unhandled))


class TestIrreducible(unittest.TestCase):
    """A cycle with two entries cannot be a loop; labels and gotos are honest."""

    def test_the_cycle_is_reported_and_uses_goto(self):
        result = decompile(IRREDUCIBLE)

        self.assertIn("goto", result.text)
        self.assertIn("irreducible", result.warnings)

    def test_every_instruction_survives_the_fallback(self):
        """The fallback is still a rendering of the whole function."""
        result = decompile(IRREDUCIBLE)

        covered = text_addresses(result.text) | text_labels(result.text)
        self.assertEqual(covered, cfg_instructions(analyze(IRREDUCIBLE)),
                         result.text)


class TestCrossEdge(unittest.TestCase):
    """An edge out of a loop that is not its exit stays a goto, and is named."""

    def test_cross_edge_is_a_goto_with_an_irreducible_warning(self):
        result = decompile(CROSS_EDGE)

        self.assertIn("while (ecx < 3) {", result.text)
        self.assertIn("goto L_1015;", result.text)
        self.assertIn("irreducible", result.warnings)


class TestNoSilentDrop(unittest.TestCase):
    """The P5 set equality survives every structuring decision."""

    def test_every_cfg_instruction_is_still_addressable(self):
        """Acceptance 2, switch included: the CFG's set plus the extra blocks.

        A switch is the one shape whose case blocks the CFG never built, so its
        expected set is the CFG instructions *union* the instructions of the
        jump-table blocks the result names. Including it here keeps the
        equality from being true only for the shapes that need no help.
        """
        from pydbg.analysis import build_function_cfg, decompile_function
        cases = (
            ("if/else", IF_ELSE, {}),
            ("while", WHILE, {}),
            ("do-while", DO_WHILE, {}),
            ("nested", NESTED, {}),
            ("irreducible", IRREDUCIBLE, {}),
            ("cross edge", CROSS_EDGE, {}),
            ("switch", SWITCH, {"image_base": SWITCH_BASE,
                                "extra_sections": switch_extra()}),
        )
        for name, code, kwargs in cases:
            with self.subTest(shape=name):
                result = analyze(code, **kwargs)
                decompiled = decompile_function(result, TEXT_RVA)
                expected = cfg_instructions(result)
                for extra in decompiled.extra_blocks:
                    extra_cfg = build_function_cfg(
                        result.decoder, result.image, result.functions, extra)
                    expected |= {addr for block in extra_cfg.blocks.values()
                                 for addr in block.instructions}
                covered = (text_addresses(decompiled.text)
                           | text_labels(decompiled.text))
                self.assertEqual(covered, expected, decompiled.text)

    def test_unhandled_lines_still_equal_the_opaque_count(self):
        result = decompile(bytes.fromhex("0fa2" "0f05" "c3"))

        self.assertEqual(len(result.unhandled), 2)
        self.assertEqual(result.text.count("// unhandled:"),
                         len(result.unhandled))


class TestDeterminism(unittest.TestCase):
    """No set iteration order reaches the text."""

    def test_structured_shapes_render_identically_twice(self):
        for name, code in (("switch", SWITCH), ("nested", NESTED)):
            with self.subTest(shape=name):
                result = analyze(code, image_base=(
                    SWITCH_BASE if name == "switch" else IMAGE_BASE),
                    extra_sections=(switch_extra()
                                    if name == "switch" else ()))
                from pydbg.analysis import decompile_function
                first = decompile_function(result, TEXT_RVA)
                second = decompile_function(result, TEXT_RVA)
                self.assertEqual(first.text.encode("utf-8"),
                                 second.text.encode("utf-8"))


class TestPerformance(unittest.TestCase):
    """A 500-instruction function stays well inside the budget."""

    def test_500_instructions_and_20_branches_under_100ms(self):
        code = large_function()
        result = analyze(code)
        from pydbg.analysis import build_function_cfg, decompile_function

        cfg = build_function_cfg(result.decoder, result.image,
                                 result.functions, TEXT_RVA)
        instructions = sum(len(block.instructions)
                           for block in cfg.blocks.values())
        self.assertGreaterEqual(instructions, 500)

        times = []
        for _ in range(3):
            start = time.perf_counter()
            decompiled = decompile_function(result, TEXT_RVA)
            times.append(time.perf_counter() - start)
        self.assertIsNotNone(decompiled)
        self.assertLess(min(times), 0.100,
                        f"min {min(times) * 1000:.1f} ms of {times}")


def large_function():
    """~530 instructions: 20 compare/branch groups over a bed of nops."""
    parts = [b"\x90" * 90]
    branch_count = 20
    group_body = b"\x90" * 20
    cursor = 90
    for index in range(branch_count):
        parts.append(bytes.fromhex("83f8") + bytes([index]))   # cmp eax, imm8
        je_at = cursor + 3
        # The target is the final `ret`; its offset is computed after all
        # groups are laid out, so this pass only reserves the field.
        parts.append(b"\x0f\x84\x00\x00\x00\x00")
        parts.append(group_body)
        cursor = je_at + 6 + len(group_body)
    tail_rva = TEXT_RVA + cursor
    data = bytearray(b"".join(parts))
    # Rewrite each `je rel32` with the distance to the shared tail.
    position = 90
    for _ in range(branch_count):
        je_at = position + 3
        relative = tail_rva - (TEXT_RVA + je_at + 6)
        struct.pack_into("<i", data, je_at + 2, relative)
        position = je_at + 6 + len(group_body)
    data.extend(b"\xc3")
    return bytes(data)


if __name__ == "__main__":
    unittest.main()
