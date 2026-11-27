import unittest

from tests import HOST_ARCH
from pydbg.patch.assembler import Assembler
from pydbg.exceptions import PydbgError


class _FakeSession:
    """The one attribute the assembler reads — and it can be changed."""

    def __init__(self, arch):
        self.target_arch = arch


class TestAssembler(unittest.TestCase):

    def test_mode_default(self):
        asm = Assembler()
        expected = "x64" if HOST_ARCH == 64 else "x86"
        self.assertEqual(asm.mode(), expected)

    def test_mode_x86(self):
        asm = Assembler(mode="x86")
        self.assertEqual(asm.mode(), "x86")

    def test_bad_mode(self):
        with self.assertRaises(PydbgError):
            Assembler(mode="arm")

    def test_no_args_resolves_the_host_mode_and_assembles(self):
        """Assembler() with no arguments is the documented host default.

        'inc eax' discriminates the modes: x86 encodes it as 0x40, x64 as the
        REX-prefixed 0xFF 0xC0 (verified against keystone 0.9.2).
        """
        asm = Assembler()
        expected = b'\xFF\xC0' if HOST_ARCH == 64 else b'\x40'
        self.assertEqual(asm.mode(), "x64" if HOST_ARCH == 64 else "x86")
        self.assertEqual(asm.assemble("inc eax"), expected)

    def test_explicit_mode_discriminates(self):
        self.assertEqual(Assembler(mode="x86").assemble("inc eax"), b'\x40')
        self.assertEqual(Assembler(mode="x64").assemble("inc eax"), b'\xFF\xC0')

    def test_explicit_mode_wins_over_the_session(self):
        asm = Assembler(mode="x86", session=_FakeSession(64))
        self.assertEqual(asm.mode(), "x86")
        self.assertEqual(asm.assemble("inc eax"), b'\x40')

    def test_session_mode_is_resolved_per_call(self):
        """A Debugger builds its assembler before any target exists.

        It used to take the host's pointer width in __init__ and keep it, so a
        WOW64 target reached later was encoded as x64 for the rest of the
        session. Mutating the session between calls must move both mode() and
        the encoded bytes, which also proves the mode-specific keystone engine
        was rebuilt rather than reused.
        """
        session = _FakeSession(32)
        asm = Assembler(session=session)
        self.assertEqual(asm.mode(), "x86")
        self.assertEqual(asm.assemble("inc eax"), b'\x40')

        session.target_arch = 64
        self.assertEqual(asm.mode(), "x64")
        self.assertEqual(asm.assemble("inc eax"), b'\xFF\xC0')

    def test_session_without_target_arch_fails_loudly(self):
        asm = Assembler(session=object())
        with self.assertRaises(PydbgError):
            asm.mode()
        with self.assertRaises(PydbgError):
            asm.assemble("inc eax")

    def test_assemble_single(self):
        asm = Assembler()
        code = asm.assemble("ret")
        self.assertEqual(code, b'\xc3')

    def test_assemble_multi_newline(self):
        if HOST_ARCH == 64:
            asm = Assembler(mode="x64")
            code = asm.assemble("push rbp\nmov rbp, rsp")
            self.assertEqual(code, b'\x55\x48\x89\xE5')
        else:
            asm = Assembler(mode="x86")
            code = asm.assemble("push ebp\nmov ebp, esp")
            self.assertEqual(code, b'\x55\x89\xE5')

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

    def test_verify_with_operands(self):
        """The regression: a statement with operands used to never verify.

        verify() compared 'mov eax, ebx' against the disassembler's 'mov', so
        it answered False for every real instruction and the suite only ever
        exercised zero-operand lines.
        """
        asm = Assembler()
        self.assertTrue(asm.verify("mov eax, ebx"))
        self.assertTrue(asm.verify("xor eax, eax; ret"))

    def test_verify_multi_statement_counts_instructions(self):
        asm = Assembler()
        self.assertTrue(asm.verify("push rbp\nmov rbp, rsp\npop rbp\nret"))

    def test_empty_code(self):
        asm = Assembler()
        code = asm.assemble("")
        self.assertEqual(code, b'')
