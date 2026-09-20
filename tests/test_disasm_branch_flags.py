"""Which instructions count as a branch, a call, or a return.

These flags are not decoration. `branch_target()` returns None for anything
that is not is_call or is_jmp, and `is_indirect_branch()` returns False for it
too — so an instruction wrongly left out of is_jmp has its edge dropped
silently, without even appearing in the list of unresolved edges. A sweep
likewise only stops at is_ret.

capstone does not classify all of these the way the names suggest: the loop
family carries only the 'branch_relative' group, and `iret` is grouped with
'privilege' rather than 'ret'. So the families are enumerated here with the
counts measured on real images, and every case is a decode rather than a
mnemonic comparison.
"""

import unittest

from pydbg.disasm.engine import DisasmEngine

# One encoding per case, with the mnemonic it is expected to produce.
CONDITIONAL_BRANCHES = {
    b"\x74\x02": "je",
    b"\x75\x02": "jne",
    b"\x72\x02": "jb",
    b"\x77\x02": "ja",
    b"\x7f\x02": "jg",
    b"\x7c\x02": "jl",
    b"\x70\x02": "jo",
    b"\x7b\x02": "jnp",
    b"\xe3\x02": "jecxz",
}

LOOPS = {
    b"\xe2\x02": "loop",
    b"\xe1\x02": "loope",
    b"\xe0\x02": "loopne",
}

UNCONDITIONAL_BRANCHES = {
    b"\xeb\x02": "jmp",
}

RETURNS = {
    b"\xc3": "ret",
    b"\xcb": "retf",
    b"\xcf": "iretd",
}

CALLS = {
    b"\xe8\x00\x00\x00\x00": "call",
}


def decode(data):
    engine = DisasmEngine(mode="x86")
    insns = engine.disasm(0x1000, data)
    assert insns, f"test fixture does not decode: {data!r}"
    return insns[0]


class TestBranchFamilies(unittest.TestCase):

    def test_every_conditional_branch_is_a_jump(self):
        for data, mnemonic in CONDITIONAL_BRANCHES.items():
            with self.subTest(mnemonic=mnemonic):
                insn = decode(data)
                self.assertEqual(insn.mnemonic, mnemonic)
                self.assertTrue(insn.is_jmp)
                self.assertTrue(insn.is_cond)

    def test_the_loop_family_is_a_branch(self):
        """capstone groups these only as 'branch_relative', not 'jump'."""
        for data, mnemonic in LOOPS.items():
            with self.subTest(mnemonic=mnemonic):
                insn = decode(data)
                self.assertEqual(insn.mnemonic, mnemonic)
                self.assertTrue(insn.is_jmp,
                                f"{mnemonic} is a branch and must not be "
                                f"dropped from the call graph")
                self.assertEqual(insn.groups, ("branch_relative",),
                                 "if capstone starts reporting a jump group "
                                 "here, the special case can go")

    def test_a_loop_keeps_its_fallthrough(self):
        """It branches on a counter, so the next instruction still runs."""
        for data, mnemonic in LOOPS.items():
            with self.subTest(mnemonic=mnemonic):
                insn = decode(data)
                self.assertTrue(insn.is_cond,
                                f"{mnemonic} must not be treated as terminal")
                self.assertFalse(insn.is_ret)

    def test_an_unconditional_jump_is_not_conditional(self):
        for data, mnemonic in UNCONDITIONAL_BRANCHES.items():
            with self.subTest(mnemonic=mnemonic):
                insn = decode(data)
                self.assertTrue(insn.is_jmp)
                self.assertFalse(insn.is_cond)

    def test_every_return_family_stops_a_sweep(self):
        for data, mnemonic in RETURNS.items():
            with self.subTest(mnemonic=mnemonic):
                insn = decode(data)
                self.assertEqual(insn.mnemonic, mnemonic)
                self.assertTrue(insn.is_ret,
                                f"{mnemonic} ends a path and must be is_ret")

    def test_iret_is_its_own_group(self):
        """The reason it needs a special case, pinned so it can be noticed."""
        insn = decode(b"\xcf")
        self.assertIn("iret", insn.groups)
        self.assertNotIn("ret", insn.groups)

    def test_calls_are_calls_and_not_branches(self):
        for data, mnemonic in CALLS.items():
            with self.subTest(mnemonic=mnemonic):
                insn = decode(data)
                self.assertTrue(insn.is_call)
                self.assertFalse(insn.is_jmp)

    def test_no_family_is_both_a_branch_and_a_return(self):
        """The flags are read independently, so a double classification would
        let one consumer stop a path another still expects to continue."""
        for data, mnemonic in {**CONDITIONAL_BRANCHES, **LOOPS,
                               **UNCONDITIONAL_BRANCHES, **RETURNS}.items():
            with self.subTest(mnemonic=mnemonic):
                insn = decode(data)
                self.assertFalse(insn.is_jmp and insn.is_ret)


class TestTheConsequences(unittest.TestCase):
    """The flags matter through what reads them, so test through that."""

    def make_image(self, code):
        from tests.pe_builder import PEBuilder
        builder = PEBuilder(magic=0x10B, image_base=0x400000,
                            entry_rva=0x1000)
        builder.add_section(".text", code, 0x1000)
        return builder.build()

    def analyze(self, code):
        from pydbg.analysis import analyze_bytes
        return analyze_bytes(self.make_image(code))

    def test_a_loop_back_edge_is_recorded_as_a_branch_not_an_immediate(self):
        """The edge survives either way — it is the *kind* that is lost.

        Without is_jmp, `classify_refs` still records the target, but as an
        IMM: "an immediate that lands in code", the same kind a bare constant
        gets. Nothing downstream can tell a loop back edge from a number, and
        the site never appears among the unresolved branches either, because
        `is_indirect_branch` is false for it too.
        """
        from pydbg.analysis import RefKind

        # 0x1000: nop; 0x1001: loop -3 (back to 0x1000); 0x1003: ret
        code = b"\x90" + b"\xe2\xfd" + b"\xc3"
        result = self.analyze(code)

        self.assertTrue(result.decoder.is_decoded(0x1000))

        branches = [ref for ref in result.xrefs_of(0x1000, RefKind.BRANCH)
                    if ref.source == 0x1001]
        self.assertEqual(len(branches), 1,
                         "the loop back edge is not a BRANCH reference; "
                         f"all refs at 0x1000: {result.xrefs_of(0x1000)}")

    def test_a_loop_is_not_left_out_of_the_call_graph_as_unresolved(self):
        """It is neither a resolved edge nor a reported gap — it is absent.

        A site that showed up among the unresolved branches would at least be
        countable. This one is invisible to `call_graph_is_complete()`, which
        is what makes the omission silent.
        """
        code = b"\x90" + b"\xe2\xfd" + b"\xc3"
        result = self.analyze(code)

        self.assertTrue(result.call_graph_is_complete())
        self.assertEqual([s.rva for s in result.indirect_call_sites()], [])

    def test_a_sweep_stops_at_iret(self):
        """Without is_ret the sweep decodes straight past the handler.

        The bytes after the iret are a valid instruction, so a sweep that
        keeps going produces a plausible decode of code that is not part of
        this path — which is the failure mode, not a crash.
        """
        # 0x1000: iretd; 0x1001..: nops the sweep should not reach by falling
        # through the return.
        code = b"\xcf" + b"\x90" * 8 + b"\xc3"
        result = self.analyze(code)

        self.assertEqual(result.decoder.size_of(0x1000), 1)
        self.assertFalse(
            result.decoder.is_decoded(0x1001),
            "the sweep ran past the iret into the bytes after it")


class TestTheEnumerationsAreCurrent(unittest.TestCase):
    """Guards against a capstone upgrade silently changing the answer."""

    def test_every_named_family_still_decodes_to_itself(self):
        for table in (CONDITIONAL_BRANCHES, LOOPS, UNCONDITIONAL_BRANCHES,
                      RETURNS, CALLS):
            for data, mnemonic in table.items():
                with self.subTest(mnemonic=mnemonic):
                    self.assertEqual(decode(data).mnemonic, mnemonic)

    def test_the_loop_ids_are_the_ones_capstone_still_reports(self):
        from pydbg.disasm.engine import _LOOP_INSNS
        import capstone

        self.assertTrue(_LOOP_INSNS)
        for data, mnemonic in LOOPS.items():
            self.assertIn(decode(data).insn_id, _LOOP_INSNS,
                          f"{mnemonic} is no longer matched by _LOOP_INSNS")

    def test_no_loop_mnemonic_is_missing_from_the_table(self):
        """The table above is the denominator; a new spelling must not be
        silently absent from it."""
        import capstone
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        names = {cs.insn_name(i) for i in range(1, capstone.x86.X86_INS_ENDING)
                 if cs.insn_name(i)}
        loops_in_capstone = {n for n in names
                             if n and n.startswith("loop") and n != "loop"}
        covered = set(LOOPS.values())
        # loopd/loopde/loopdne only appear in 16-bit encodings capstone names
        # differently; anything else missing is a real gap.
        missing = {n for n in loops_in_capstone if n not in covered
                   and not n.startswith("loopd") and not n.startswith("loopw")}
        self.assertEqual(missing, set(),
                         f"loop family members not covered: {missing}")


if __name__ == "__main__":
    unittest.main()
