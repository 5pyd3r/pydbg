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


from pydbg.instrument.codegen import _scan_externs
from pydbg.exceptions import PydbgError


class TestCodegen(unittest.TestCase):

    def test_scan_externs_collects_names(self):
        src = ('extern void Foo(int x);'
               'extern int  Bar(void);'
               'int on_call(int x) { Foo(x); return Bar(); }')
        self.assertEqual(_scan_externs(src), {'Foo', 'Bar'})

    def test_scan_externs_reserves_original_func(self):
        src = ('extern int original_func(int a, int b);'
               'extern void Game_Log(int x);'
               'int on_call(int a, int b) { Game_Log(a); return original_func(a, b); }')
        self.assertEqual(_scan_externs(src), {'Game_Log'})

    def test_scan_externs_no_externs(self):
        self.assertEqual(_scan_externs('int on_call(int x) { return x * 2; }'), set())

    def test_compile_payload_missing_backend_raises(self):
        # 确定性验证后端缺失时的降级错误（mock 掉 _backend，不依赖导入状态）
        from unittest import mock
        from pydbg.instrument import codegen
        with mock.patch.object(codegen, '_backend',
                               side_effect=PydbgError("LLVM backend not available.")):
            with self.assertRaises(PydbgError):
                codegen.compile_payload('int on_call(int x){return x;}', 'x64', {})

    def test_compile_payload_unresolved_extern_raises(self):
        # 后端存在时：extern 未解析应抛 PydbgError（缺失符号名单）
        from pydbg.instrument import codegen
        try:
            codegen._backend()
        except PydbgError:
            self.skipTest("LLVM backend not built")
        with self.assertRaises(PydbgError) as ctx:
            codegen.compile_payload(
                'extern void Missing_Func(int x);'
                'int on_call(int x){ Missing_Func(x); return x; }', 'x64', {})
        self.assertIn('Missing_Func', str(ctx.exception))


from pydbg.instrument.templates import InstrumentTemplates


class TestInstrumentTemplates(unittest.TestCase):

    def _entry(self, src):
        self.assertIn('int on_call', src)
        self.assertIn('original_func(', src)

    def test_log_args_generates_c(self):
        src, syms = InstrumentTemplates.log_args(
            'on_call', 'int a, int b', 'Game_Log', {'Game_Log': 0x601000})
        self._entry(src)
        self.assertIn('Game_Log(a)', src)
        self.assertIn('Game_Log(b)', src)
        self.assertEqual(syms['Game_Log'], 0x601000)
        self.assertNotIn('original_func', syms)

    def test_call_counter_generates_c(self):
        src, syms = InstrumentTemplates.call_counter(
            'on_call', 'int a', 'MyTick', {'MyTick': 0x700000})
        self._entry(src)
        self.assertIn('MyTick()', src)
        self.assertIn('original_func(a)', src)
        self.assertEqual(syms['MyTick'], 0x700000)

    def test_modify_return_generates_c(self):
        src, syms = InstrumentTemplates.modify_return(
            'on_call', 'int a, int b', 'r + 1', {})
        self._entry(src)
        self.assertIn('int r = original_func(a, b);', src)
        self.assertIn('return (r + 1);', src)
        self.assertEqual(syms, {})

    def test_params_names_parsed(self):
        src, _ = InstrumentTemplates.log_args('on_call', 'int a, int b', 'L', {})
        self.assertIn('L(a)', src)
        self.assertIn('L(b)', src)
