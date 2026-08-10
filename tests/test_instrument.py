import struct
import unittest

from pydbg.instrument.templates import build_abs_jmp, build_stub, build_trampoline
from pydbg.exceptions import PydbgError


class TestTemplates(unittest.TestCase):

    def test_build_abs_jmp_5_bytes_e9(self):
        code = build_abs_jmp(0x1000, 0x2000)
        self.assertEqual(len(code), 5)
        self.assertEqual(code[0], 0xE9)
        rel = struct.unpack('<i', code[1:])[0]
        self.assertEqual(rel, 0x2000 - (0x1000 + 5))

    def test_build_abs_jmp_backward(self):
        code = build_abs_jmp(0x2000, 0x1000)
        rel = struct.unpack('<i', code[1:])[0]
        self.assertEqual(rel, 0x1000 - (0x2000 + 5))

    def test_build_abs_jmp_out_of_range(self):
        with self.assertRaises(PydbgError):
            build_abs_jmp(0, 1 << 40)

    def test_build_stub_is_jmp(self):
        self.assertEqual(build_stub(0x1000, 0x9000), build_abs_jmp(0x1000, 0x9000))

    def test_build_trampoline_appends_jmp_back(self):
        original = b'\x90\x90\x90\x90\x90'
        tramp = build_trampoline(original, trampoline_addr=0x5000, target_addr=0x1000)
        self.assertEqual(len(tramp), len(original) + 5)
        self.assertEqual(tramp[:5], original)
        self.assertEqual(tramp[0], 0x90)
        self.assertEqual(tramp[5], 0xE9)
        rel = struct.unpack('<i', tramp[6:])[0]
        self.assertEqual(rel, 0x1005 - (0x5005 + 5))
