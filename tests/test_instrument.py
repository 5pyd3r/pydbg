import os
import struct
import sys
import time
import unittest

from pydbg.exceptions import PydbgError
from pydbg.instrument import Instrumenter
from pydbg.instrument.codegen import _scan_externs
from pydbg.instrument.templates import (
    InstrumentTemplates,
    build_abs_jmp,
    build_stub,
    build_trampoline,
)


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
        # 调用处，并验证编译失败后整块区域一次性回滚释放。
        from unittest import mock
        from pydbg.instrument import codegen
        with mock.patch.object(self.inst, '_read_min_5_bytes',
                               return_value=b'\x90' * 5), \
             mock.patch.object(self.inst, '_alloc_rwx',
                               return_value=0x5000), \
             mock.patch.object(self.inst, '_free_rwx') as free_mock, \
             mock.patch('pydbg.memory.manager.MemoryManager'), \
             mock.patch.object(codegen, 'compile_payload',
                               side_effect=PydbgError("LLVM backend not available.")) as compile_mock:
            with self.assertRaises(PydbgError):
                self.inst.install(0x1000, c_source='int on_call(int x){return x;}')
        # 单次分配（返回区域基址 0x5000）：stub 紧随 trampoline 之后
        tramp_size = len(b'\x90' * 5) + 5   # 10
        stub_addr = 0x5000 + tramp_size     # 0x500A
        region_size = tramp_size + 0x2000   # 0x200A
        # 接线：compile(c_source, mode, symbols, base_addr=...) — symbols 是位置参数（下标 2）
        args, kwargs = compile_mock.call_args
        self.assertEqual(kwargs['base_addr'], stub_addr)
        self.assertEqual(args[2]['original_func'], 0x5000)
        # 回滚路径：整块连续区域（trampoline + stub 缓冲）一次释放。
        # _free_rwx(mem, addr, size) 的首参是 mem 实例，断言后两个参数。
        self.assertEqual(free_mock.call_count, 1)
        self.assertEqual(free_mock.call_args[0][1:], (0x5000, region_size))

    def test_install_success_contiguous_region(self):
        # 确定性：mock 分配/编译/内存读写，验证成功安装时 trampoline 与 stub 落在
        # 同一连续区域（stub_addr == trampoline_addr + trampoline_size），restore
        # 对整块区域只调用一次 _free_rwx。
        from unittest import mock
        from pydbg.instrument import codegen
        with mock.patch.object(self.inst, '_read_min_5_bytes',
                               return_value=b'\x90' * 5), \
             mock.patch.object(self.inst, '_alloc_rwx',
                               return_value=0x5000), \
             mock.patch.object(self.inst, '_free_rwx') as free_mock, \
             mock.patch('pydbg.memory.manager.MemoryManager'), \
             mock.patch.object(codegen, 'compile_payload',
                               return_value=b'\x00' * 64) as compile_mock:
            info = self.inst.install(
                0x1000, c_source='int on_call(int x){return x;}')
            # 单次分配返回区域基址；stub 紧跟 trampoline，天然满足 ±2GB 邻接
            self.assertEqual(info.trampoline_addr, 0x5000)
            self.assertEqual(info.stub_addr,
                             info.trampoline_addr + info.trampoline_size)
            # 接线：compile 以 stub 地址为 base_addr；original_func 映射到 trampoline
            args, kwargs = compile_mock.call_args
            self.assertEqual(kwargs['base_addr'], info.stub_addr)
            self.assertEqual(args[2]['original_func'], info.trampoline_addr)
            # install 期间没有任何释放；restore 一次性释放整块区域
            self.assertEqual(free_mock.call_count, 0)
            self.inst.restore(0x1000)
            # _free_rwx(mem, addr, size) 的首参是 mem 实例，断言后两个参数
            self.assertEqual(free_mock.call_count, 1)
            self.assertEqual(
                free_mock.call_args[0][1:],
                (info.trampoline_addr,
                 info.trampoline_size + info.stub_alloc_size))


_TEST_TARGET = os.environ.get(
    'TEST_INSTRUMENT_TARGET_PATH',
    r'C:\Users\Spyder\Desktop\ai_eden\Output\instrument-module\build-instrument\tests\instrument_target.exe',
)


def _module_by_name(dbg, basename):
    for m in dbg.enum_modules():
        if m.get("name", "").split("\\")[-1].lower() == basename.lower():
            return m
    return None


def _export_address(dbg, exe_path, base, name):
    from pydbg.pe import PE
    pe = PE.from_file(exe_path)
    for exp in pe.exports:
        if exp.name == name:
            return base + exp.rva
    raise AssertionError(f"export {name} not found in {exe_path}")


def _backend_available():
    """LLVM 后端可用性探测。_llvm_backend 扩展未构建时返回 False，使 live
    测试 skip 而非失败（CI 默认构建 instrument_target.exe 但不构建后端）。"""
    try:
        from pydbg.instrument import codegen
        codegen._backend()
        return True
    except Exception:
        return False


@unittest.skipUnless(
    os.path.isfile(_TEST_TARGET) and _backend_available(),
    "requires instrument_target.exe and LLVM backend")
class TestInstrumentLive(unittest.TestCase):

    @property
    def target_path(self):
        return _TEST_TARGET

    def _launch(self):
        from pydbg import Debugger
        dbg = Debugger()
        dbg.create_process(self.target_path)
        return dbg

    def _run_until_started(self, dbg, seconds=3):
        """继续调试事件，让目标跑起来并度过启动期。"""
        deadline = time.time() + seconds
        while time.time() < deadline:
            ev = dbg.wait_event(100)
            if ev is None:
                continue
            dbg.continue_event(ev.pid, ev.tid)

    def _sum_rate(self, dbg, g_sum_addr, seconds=0.4):
        """测量 g_sum 增长速率（每秒增量）。目标每轮 +3，插桩后每轮 +103。"""
        a = int.from_bytes(dbg.read_memory(g_sum_addr, 4), 'little')
        t0 = time.time()
        time.sleep(seconds)
        b = int.from_bytes(dbg.read_memory(g_sum_addr, 4), 'little')
        return (b - a) / max(time.time() - t0, 1e-6)

    def test_install_restore_roundtrip(self):
        from pydbg.instrument import Instrumenter
        from tests.helpers import teardown

        dbg = self._launch()
        inst = Instrumenter(dbg._session)
        try:
            self._run_until_started(dbg)

            base = _module_by_name(dbg, os.path.basename(self.target_path))["base_address"]
            addr = _export_address(dbg, self.target_path, base, "add_numbers")
            orig = dbg.read_memory(addr, 5)

            g_sum_addr = _export_address(dbg, self.target_path, base, "g_sum")
            base_rate = self._sum_rate(dbg, g_sum_addr, 0.4)
            self.assertGreater(base_rate, 0, "目标未运行：g_sum 无增长")

            info = inst.install(
                addr,
                c_source=('extern int original_func(int a, int b);'
                          'int on_call(int a, int b) {'
                          '    return original_func(a, b) + 100;'
                          '}'),
            )
            self.assertGreater(info.trampoline_addr, 0)
            self.assertGreater(info.stub_addr, 0)
            # detour stub 已写入：target 首字节为 E9
            self.assertEqual(dbg.read_memory(addr, 1), b"\xe9")

            # 插桩后每轮 +103（原 +3 再加 +100）：速率应远超基线
            hooked_rate = self._sum_rate(dbg, g_sum_addr, 0.4)
            self.assertGreater(
                hooked_rate, 10 * base_rate,
                "hook 未生效：g_sum 速率未变为 +103/轮")

            inst.restore(addr)
            self.assertNotIn(addr, inst.active)
            self.assertEqual(dbg.read_memory(addr, 5), orig)

            # 恢复后每轮回到 +3：速率应回落到基线水平
            restored_rate = self._sum_rate(dbg, g_sum_addr, 0.4)
            self.assertGreater(restored_rate, 0, "目标未运行：g_sum 无增长")
            self.assertLess(
                restored_rate, 3 * base_rate,
                "restore 未生效：g_sum 速率未回到 +3/轮")
        finally:
            teardown(dbg)


_TEST_TARGET32 = os.environ.get(
    'TEST_INSTRUMENT_TARGET32_PATH',
    r'C:\Users\Spyder\Desktop\ai_eden\Output\instrument-module\tests\target\instrument_target32.exe',
)


def _wow64_available():
    # 64 位宿主才能调试 WOW64（32 位进程）——同 test_wow64 的检测。
    # _pydbg.wow64_available 绑定不存在时按宿主架构判断；import 放进 try 内，
    # 32 位宿主收集时若无绑定应返回 False 而非抛 ImportError。
    if struct.calcsize("P") == 8 and sys.platform == "win32":
        return True
    try:
        from pydbg import _pydbg
        return bool(getattr(_pydbg, 'wow64_available', lambda: False)())
    except Exception:
        return False


@unittest.skipUnless(
    os.path.isfile(_TEST_TARGET32) and _wow64_available() and _backend_available(),
    "requires 32-bit instrument target, WOW64 host, and LLVM backend")
class TestInstrumentLive32(TestInstrumentLive):
    """32 位 WOW64 live 往返；复用 TestInstrumentLive 的断言逻辑。"""

    @property
    def target_path(self):
        return _TEST_TARGET32

    def _launch(self):
        from pydbg import Debugger
        dbg = Debugger()
        dbg.create_process(_TEST_TARGET32)
        return dbg
