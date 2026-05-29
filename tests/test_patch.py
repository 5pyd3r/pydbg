import unittest


from pydbg.patch.assembler import Assembler
from pydbg.exceptions import PydbgError


class TestAssembler(unittest.TestCase):

    def test_mode_default(self):
        asm = Assembler()
        self.assertEqual(asm.mode(), "x64")

    def test_mode_x86(self):
        asm = Assembler(mode="x86")
        self.assertEqual(asm.mode(), "x86")

    def test_bad_mode(self):
        with self.assertRaises(PydbgError):
            Assembler(mode="arm")

    def test_assemble_single(self):
        asm = Assembler()
        code = asm.assemble("ret")
        self.assertEqual(code, b'\xc3')

    def test_assemble_multi_newline(self):
        asm = Assembler()
        code = asm.assemble("push rbp\nmov rbp, rsp")
        self.assertEqual(code, b'\x55\x48\x89\xE5')

    def test_assemble_multi_semicolon(self):
        asm = Assembler()
        code = asm.assemble("xor eax, eax; ret")
        self.assertEqual(code, b'\x31\xC0\xC3')

    def test_assemble_with_addr(self):
        asm = Assembler()
        code1 = asm.assemble("nop", 0x1000)
        code2 = asm.assemble("nop", 0x2000)
        self.assertEqual(code1, code2)

    def test_bad_syntax(self):
        asm = Assembler()
        with self.assertRaises(PydbgError):
            asm.assemble("invalid_instruction_xyz")

    def test_verify_ok(self):
        asm = Assembler()
        self.assertTrue(asm.verify("ret"))

    def test_verify_nop(self):
        asm = Assembler()
        self.assertTrue(asm.verify("nop"))

    def test_empty_code(self):
        asm = Assembler()
        code = asm.assemble("")
        self.assertEqual(code, b'')
