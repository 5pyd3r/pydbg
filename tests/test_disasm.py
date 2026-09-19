import unittest
from tests import HOST_ARCH
from pydbg.disasm.engine import DisasmEngine, Instruction


# Simple x64 code: mov rax, 1; ret
X64_RET = bytes([
    0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,  # mov rax, 1
    0xC3,                                          # ret
])

# x64 conditional: xor eax, eax; test eax, eax; jne target; inc eax; ret
X64_COND = bytes([
    0x31, 0xC0,                   # xor eax, eax
    0x85, 0xC0,                   # test eax, eax
    0x75, 0x02,                   # jne +2 (skip inc)
    0xFF, 0xC0,                   # inc eax
    0xC3,                         # ret
])


class TestDisasmEngine(unittest.TestCase):

    def test_mode_default(self):
        engine = DisasmEngine()
        expected = "x64" if HOST_ARCH == 64 else "x86"
        self.assertEqual(engine.mode(), expected)

    def test_mode_explicit_x86(self):
        engine = DisasmEngine(mode="x86")
        self.assertEqual(engine.mode(), "x86")

    def test_mode_explicit_x64(self):
        engine = DisasmEngine(mode="x64")
        self.assertEqual(engine.mode(), "x64")

    def test_disasm_basic(self):
        engine = DisasmEngine(mode="x64")
        insns = engine.disasm(0x1000, X64_RET)
        self.assertEqual(len(insns), 2)
        self.assertEqual(insns[0].mnemonic, "mov")
        self.assertEqual(insns[0].address, 0x1000)
        self.assertEqual(insns[0].size, 7)
        self.assertFalse(insns[0].is_ret)
        self.assertEqual(insns[1].mnemonic, "ret")
        self.assertTrue(insns[1].is_ret)

    def test_disasm_instruction_properties(self):
        engine = DisasmEngine(mode="x64")
        insns = engine.disasm(0x1000, X64_RET)
        ret = insns[1]
        self.assertEqual(ret.mnemonic, "ret")
        self.assertTrue(ret.is_ret)
        self.assertFalse(ret.is_call)
        self.assertFalse(ret.is_jmp)
        self.assertFalse(ret.is_cond)

    def test_iter_disasm(self):
        engine = DisasmEngine(mode="x64")
        results = list(engine.iter_disasm(0x0, X64_RET))
        self.assertEqual(len(results), 2)

    def test_disasm_x86_mode(self):
        # x86: xor eax, eax; ret
        x86_code = bytes([0x33, 0xC0, 0xC3])
        engine = DisasmEngine(mode="x86")
        insns = engine.disasm(0x0, x86_code)
        self.assertEqual(len(insns), 2)
        self.assertEqual(insns[0].mnemonic, "xor")

    def test_disasm_raw_bytes_field(self):
        engine = DisasmEngine(mode="x64")
        insns = engine.disasm(0x0, b'\xc3')
        self.assertEqual(insns[0].raw_bytes, b'\xc3')

    def test_disasm_groups(self):
        engine = DisasmEngine(mode="x64")
        insns = engine.disasm(0x0, X64_RET)
        ret = insns[1]
        self.assertIn('ret', ret.groups)

    def test_conditional_jump_detection(self):
        engine = DisasmEngine(mode="x64")
        insns = engine.disasm(0x1000, X64_COND)
        jne = [i for i in insns if i.mnemonic == 'jne']
        self.assertEqual(len(jne), 1)
        self.assertTrue(jne[0].is_cond)
        self.assertTrue(jne[0].is_jmp)
        self.assertFalse(jne[0].is_ret)
        self.assertFalse(jne[0].is_call)

    def test_group_names_are_named_once_per_distinct_set(self):
        """The cache is the whole point: 670k instructions, a handful of sets.

        Asserting on `is` rather than `==` on purpose. Equality would pass
        whether or not anything is shared, and sharing is the change — an
        implementation that rebuilds an equal tuple per instruction is exactly
        the cost this removes.
        """
        engine = DisasmEngine(mode="x64")
        # Two rets, and two nops that have no groups at all.
        insns = engine.disasm(0x0, b"\xc3" + b"\x90\x90" + b"\xc3")
        first_ret, second_ret = insns[0], insns[-1]
        self.assertIn('ret', first_ret.groups)
        self.assertIs(first_ret.groups, second_ret.groups)
        self.assertIs(insns[1].groups, insns[2].groups)
        self.assertEqual(insns[1].groups, ())

    def test_a_second_engine_does_not_inherit_the_first_ones_cache(self):
        """Per-engine, not global: the cache lives with the capstone handle
        that produced it, so a torn-down engine leaves nothing behind."""
        first = DisasmEngine(mode="x64").disasm(0x0, b"\xc3")[0]
        second = DisasmEngine(mode="x64").disasm(0x0, b"\xc3")[0]
        self.assertEqual(first.groups, second.groups)
        self.assertIsNot(first.groups, second.groups)


class TestInstructionDataclass(unittest.TestCase):

    def test_instruction_fields(self):
        insn = Instruction(
            address=0x1000,
            size=3,
            mnemonic="xor",
            op_str="eax, eax",
            raw_bytes=b'\x31\xc0',
            is_call=False,
            is_jmp=False,
            is_ret=False,
            is_cond=False,
        )
        self.assertEqual(insn.address, 0x1000)
        self.assertEqual(insn.mnemonic, "xor")

    def test_defaults(self):
        insn = Instruction(address=0, size=0, mnemonic="", op_str="", raw_bytes=b"")
        self.assertFalse(insn.is_call)
        self.assertFalse(insn.is_jmp)
        self.assertFalse(insn.is_ret)
        self.assertFalse(insn.is_cond)
        self.assertEqual(insn.groups, ())
        # Additive fields: an Instruction built the old way still works, and
        # reads as "operands not materialized" rather than as a missing field.
        self.assertEqual(insn.operands, ())
        self.assertEqual(insn.insn_id, 0)


class TestOperandDetail(unittest.TestCase):
    """Operand-level detail, which the engine used to decode and discard.

    `cs.detail` was already True, so the data was always there; it just never
    reached the caller, which is why no cross-referencing or structure
    recovery was possible on top of this engine.
    """

    def decode(self, code, mode="x64", addr=0x140001000):
        from pydbg.disasm.engine import DisasmEngine
        return DisasmEngine(mode=mode).disasm(addr, code)[0]

    def test_absolute_memory_operand(self):
        from pydbg.disasm.engine import OP_MEM
        # movabs rax, qword ptr [0x140001000]
        insn = self.decode(b"\x48\xa1\x00\x10\x00\x40\x01\x00\x00\x00")
        dest, src = insn.operands
        self.assertEqual(src.kind, OP_MEM)
        self.assertTrue(src.is_absolute_mem)
        self.assertFalse(src.is_table_mem)
        self.assertEqual(src.mem_disp, 0x140001000)
        self.assertEqual(src.size, 8)

    def test_base_relative_memory_is_not_an_address(self):
        # mov rax, [rbx+8] — a displacement of 8 is an offset, not an address,
        # and must not be mistaken for one.
        insn = self.decode(b"\x48\x8b\x43\x08")
        src = insn.operands[1]
        self.assertFalse(src.is_absolute_mem)
        self.assertFalse(src.is_table_mem)
        self.assertNotEqual(src.mem_base, 0)
        self.assertEqual(src.mem_disp, 8)

    def test_indexed_memory_is_a_table_reference(self):
        # jmp qword ptr [rcx*8 + 0x40002000] — switch-table shape.
        insn = self.decode(b"\xff\x24\xcd\x00\x20\x00\x40")
        src = insn.operands[0]
        self.assertTrue(src.is_table_mem)
        self.assertFalse(src.is_absolute_mem)
        self.assertEqual(src.mem_scale, 8)
        self.assertEqual(src.mem_disp, 0x40002000)

    def test_segment_relative_memory_is_not_an_address(self):
        """gs:[0x60] reads a TEB field; 0x60 is an offset, not an address.

        This looked like absolute addressing by every other test — no base, no
        index — and a cross-reference pass built on that would have recorded
        references to address 0x60. Found by decoding real code: every
        "absolute" operand in the first 128KB of kernel32.dll's .text was one
        of these TEB accesses.
        """
        insn = self.decode(b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00")
        src = insn.operands[1]
        self.assertNotEqual(src.mem_segment, 0, "expected the gs prefix")
        self.assertEqual(src.mem_base, 0)
        self.assertEqual(src.mem_index, 0)
        self.assertFalse(src.is_absolute_mem)
        self.assertFalse(src.is_table_mem)

    def test_immediate_keeps_full_width(self):
        """The port this comes from masked immediates to 32 bits.

        On an x64 image that turns 0x140001000 into 0x40001000 — and every
        such address then fails an image-window test, silently, so the seed
        classes that depend on immediates just come back empty.
        """
        from pydbg.disasm.engine import OP_IMM
        insn = self.decode(b"\x48\xb8\x00\x10\x00\x40\x01\x00\x00\x00")
        src = insn.operands[1]
        self.assertEqual(src.kind, OP_IMM)
        self.assertEqual(src.imm, 0x140001000)
        self.assertEqual(src.imm & 0xFFFFFFFF, 0x40001000,
                         "sanity: masking really would have changed this")

    def test_negative_displacement_is_not_masked(self):
        """[rbx-8] must stay -8, not become 0xFFFFFFF8."""
        insn = self.decode(b"\x48\x8b\x43\xf8")
        src = insn.operands[1]
        self.assertEqual(src.mem_disp, -8)

    def test_indirect_call_has_a_register_operand(self):
        """A call through a register is how indirect calls appear; the old
        Instruction could only say is_call, not what it called."""
        from pydbg.disasm.engine import OP_REG
        insn = self.decode(b"\x48\xff\xd0")
        self.assertTrue(insn.is_call)
        self.assertEqual(len(insn.operands), 1)
        self.assertEqual(insn.operands[0].kind, OP_REG)

    def test_ret_has_no_operands(self):
        insn = self.decode(b"\xc3")
        self.assertTrue(insn.is_ret)
        self.assertEqual(insn.operands, ())

    def test_jump_target_is_an_immediate(self):
        insn = self.decode(b"\x75\x05")
        self.assertTrue(insn.is_cond)
        self.assertEqual(insn.operands[0].imm, 0x140001007)

    def test_operand_widths_follow_the_operand_size_prefix(self):
        # mov rax, [rbx] is 8 bytes wide; mov eax, [rbx] is 4. Width matters to
        # anything reconstructing a structure layout.
        self.assertEqual(self.decode(b"\x48\x8b\x03").operands[1].size, 8)
        self.assertEqual(self.decode(b"\x8b\x03").operands[1].size, 4)

    def test_operands_are_detached_and_small(self):
        """Capstone operand objects keep their CsInsn alive (~1KB each).

        Holding those for a 670k-instruction image is ~1GB, so Operand is a
        frozen slotted dataclass. Both properties are load-bearing and both
        would be lost by a casual edit.
        """
        import sys

        from pydbg.disasm.engine import Operand

        operand = self.decode(b"\x48\x8b\x43\x08").operands[1]
        self.assertIsInstance(operand, Operand)
        self.assertFalse(hasattr(operand, "__dict__"), "slots=True was lost")
        self.assertLess(sys.getsizeof(operand), 200)
        with self.assertRaises(Exception):      # frozen=True was lost
            operand.mem_disp = 1


if __name__ == '__main__':
    unittest.main()
