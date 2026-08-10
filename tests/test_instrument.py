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
        self.assertIn('extern void Game_Log(int value);', src)
        self.assertIn('extern int original_func(int a, int b);', src)
        self.assertIn('return original_func(a, b);', src)
        self.assertEqual(syms['Game_Log'], 0x601000)
        self.assertNotIn('original_func', syms)

    def test_call_counter_generates_c(self):
        src, syms = InstrumentTemplates.call_counter(
            'on_call', 'int a', 'MyTick', {'MyTick': 0x700000})
        self._entry(src)
        self.assertIn('MyTick()', src)
        self.assertIn('original_func(a)', src)
        self.assertIn('extern void MyTick(void);', src)
        self.assertIn('extern int original_func(int a);', src)
        self.assertIn('return original_func(a);', src)
        self.assertEqual(syms['MyTick'], 0x700000)

    def test_modify_return_generates_c(self):
        src, syms = InstrumentTemplates.modify_return(
            'on_call', 'int a, int b', 'r + 1', {})
        self._entry(src)
        self.assertIn('extern int original_func(int a, int b);', src)
        self.assertIn('int r = original_func(a, b);', src)
        self.assertIn('return (r + 1);', src)
        self.assertEqual(syms, {})

    def test_params_names_parsed(self):
        src, _ = InstrumentTemplates.log_args('on_call', 'int a, int b', 'L', {})
        self.assertIn('L(a)', src)
        self.assertIn('L(b)', src)


from pydbg.instrument import Instrumenter
from pydbg.exceptions import PydbgError


class TestInstrumenter(unittest.TestCase):

    def setUp(self):
        from pydbg.core.session import DebugSession
        self.session = DebugSession()
        self.inst = Instrumenter(self.session)

    def test_init_empty_active(self):
        self.assertEqual(self.inst.active, {})

    def test_install_requires_exactly_one_source(self):
        with self.assertRaises(PydbgError):
            self.inst.install(0x1000)  # 两者都没有
        with self.assertRaises(PydbgError):
            self.inst.install(0x1000, c_source='int on_call(int x){return x;}',
                              template=('x', {}))  # 两者都给

    def test_install_backend_missing_raises(self):
        # 确定性：mock 掉 codegen.compile_payload 的 PydbgError 路径。
        # fresh DebugSession 的 process_handle 为 None，未 mock 时 mem.read/write
        # 会先在 Cython 绑定处抛 TypeError（到不了 codegen）；故同时 mock 掉原始
        # 字节读取、内存分配与 MemoryManager 读写，让 install 稳定走到 codegen
        # 调用处，并验证分配失败后的双段回滚（trampoline + stub 都释放）。
        from unittest import mock
        from pydbg.instrument import codegen
        with mock.patch.object(self.inst, '_read_min_5_bytes',
                               return_value=b'\x90' * 5), \
             mock.patch.object(self.inst, '_alloc_rwx',
                               side_effect=[0x5000, 0x7000]), \
             mock.patch.object(self.inst, '_free_rwx') as free_mock, \
             mock.patch('pydbg.memory.manager.MemoryManager'), \
             mock.patch.object(codegen, 'compile_payload',
                               side_effect=PydbgError("LLVM backend not available.")) as compile_mock:
            with self.assertRaises(PydbgError):
                self.inst.install(0x1000, c_source='int on_call(int x){return x;}')
        # 接线：tramp 先分配（0x5000），stub 后分配（0x7000）；
        # compile(c_source, mode, symbols, base_addr=...) — symbols 是位置参数（下标 2）
        args, kwargs = compile_mock.call_args
        self.assertEqual(kwargs['base_addr'], 0x7000)
        self.assertEqual(args[2]['original_func'], 0x5000)
        # 回滚路径：trampoline 与 stub 两个分配都被释放
        self.assertEqual(free_mock.call_count, 2)
