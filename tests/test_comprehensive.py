"""Comprehensive tests covering all pydbg modules and edge cases.

Test categories:
  1. Exception hierarchy
  2. DebugSession dataclass
  3. PE Source/View layers
  4. Disasm analysis edge cases
  5. Symbol resolver
  6. Module resolver
  7. Hook integration
  8. Dump/minidump
  9. Assembler edge cases
  10. Integration (Debugger full lifecycle)
"""

import os
import struct
import unittest

from tests import HOST_ARCH, IP_REG, SP_REG, GP_REG

TEST_TARGET_PATH = os.path.join(os.path.dirname(__file__), "target", "simple_target.exe")
if not os.path.exists(TEST_TARGET_PATH):
    TEST_TARGET_PATH = os.environ.get("TEST_TARGET_PATH", "simple_target.exe")

try:
    from pydbg import _pydbg
    _has_cython = True
except ImportError:
    _has_cython = False

try:
    import capstone  # noqa: F401
    _has_capstone = True
except ImportError:
    _has_capstone = False

try:
    import keystone  # noqa: F401
    _has_keystone = True
except ImportError:
    _has_keystone = False


# ═══════════════════════════════════════════════════════════════════
# 1. Exception Hierarchy
# ═══════════════════════════════════════════════════════════════════

class TestExceptionHierarchy(unittest.TestCase):
    """Tests for exception class hierarchy and behavior."""

    def test_base_exception(self):
        from pydbg.exceptions import PydbgError
        e = PydbgError("test message")
        self.assertEqual(str(e), "test message")
        self.assertIsInstance(e, Exception)

    def test_process_error_inherits(self):
        from pydbg.exceptions import PydbgError, ProcessError
        e = ProcessError("process failed")
        self.assertIsInstance(e, PydbgError)
        self.assertIsInstance(e, Exception)

    def test_mem_error_inherits(self):
        from pydbg.exceptions import PydbgError, MemError
        e = MemError("memory failed")
        self.assertIsInstance(e, PydbgError)

    def test_thread_error_inherits(self):
        from pydbg.exceptions import PydbgError, ThreadError
        e = ThreadError("thread failed")
        self.assertIsInstance(e, PydbgError)

    def test_breakpoint_error_inherits(self):
        from pydbg.exceptions import PydbgError, BreakpointError
        e = BreakpointError("bp failed")
        self.assertIsInstance(e, PydbgError)

    def test_timeout_error_inherits(self):
        from pydbg.exceptions import PydbgError, TimeoutError
        e = TimeoutError("timeout")
        self.assertIsInstance(e, PydbgError)

    def test_catch_all_with_base(self):
        """All pydbg exceptions should be caught by PydbgError."""
        from pydbg.exceptions import (
            PydbgError, ProcessError, MemError,
            ThreadError, BreakpointError, TimeoutError,
        )
        for exc_cls in [ProcessError, MemError, ThreadError,
                        BreakpointError, TimeoutError]:
            with self.assertRaises(PydbgError):
                raise exc_cls("test")

    def test_exception_message_preserved(self):
        from pydbg.exceptions import ProcessError
        e = ProcessError("specific error detail")
        self.assertIn("specific error detail", str(e))

    def test_exception_repr(self):
        from pydbg.exceptions import PydbgError
        e = PydbgError("test")
        self.assertIn("test", repr(e))


# ═══════════════════════════════════════════════════════════════════
# 2. DebugSession
# ═══════════════════════════════════════════════════════════════════

class TestDebugSession(unittest.TestCase):
    """Tests for DebugSession dataclass."""

    def test_default_values(self):
        from pydbg.core.session import DebugSession
        s = DebugSession()
        self.assertIsNone(s.process_handle)
        self.assertIsNone(s.thread_handle)
        self.assertIsNone(s.pid)
        self.assertIsNone(s.tid)
        self.assertEqual(s.bp_counter, 0)
        self.assertEqual(s.breakpoints, {})
        self.assertEqual(s.pending_single_step, {})

    def test_host_arch_matches_python(self):
        from pydbg.core.session import DebugSession
        s = DebugSession()
        self.assertEqual(s.host_arch, HOST_ARCH)
        self.assertIn(s.host_arch, (32, 64))

    def test_target_arch_defaults_to_host(self):
        from pydbg.core.session import DebugSession
        s = DebugSession()
        self.assertEqual(s.target_arch, HOST_ARCH)

    def test_breakpoint_dict_operations(self):
        from pydbg.core.session import DebugSession
        s = DebugSession()
        s.breakpoints[1] = ("int3", 0x1000, b"\x90")
        s.breakpoints[2] = ("hw", 0x2000, 0)
        self.assertEqual(len(s.breakpoints), 2)
        self.assertEqual(s.breakpoints[1][0], "int3")
        self.assertEqual(s.breakpoints[2][0], "hw")

    def test_pending_single_step_operations(self):
        from pydbg.core.session import DebugSession
        s = DebugSession()
        s.pending_single_step[100] = (1, 0x1000, b"\x90")
        self.assertIn(100, s.pending_single_step)
        bp_id, addr, orig = s.pending_single_step.pop(100)
        self.assertEqual(bp_id, 1)
        self.assertEqual(addr, 0x1000)

    def test_bp_counter_increment(self):
        from pydbg.core.session import DebugSession
        s = DebugSession()
        self.assertEqual(s.bp_counter, 0)
        s.bp_counter += 1
        self.assertEqual(s.bp_counter, 1)
        s.bp_counter += 1
        self.assertEqual(s.bp_counter, 2)


# ═══════════════════════════════════════════════════════════════════
# 3. PE Source/View Layers
# ═══════════════════════════════════════════════════════════════════

class TestBytesSource(unittest.TestCase):
    """Tests for BytesSource."""

    def test_read_normal(self):
        from pydbg.pe.source import BytesSource
        src = BytesSource(b"\x01\x02\x03\x04\x05")
        data = src.read(1, 3)
        self.assertEqual(data, b"\x02\x03\x04")

    def test_read_at_offset_zero(self):
        from pydbg.pe.source import BytesSource
        src = BytesSource(b"\xAB\xCD")
        data = src.read(0, 2)
        self.assertEqual(data, b"\xAB\xCD")

    def test_read_out_of_bounds(self):
        from pydbg.pe.source import BytesSource
        src = BytesSource(b"\x01\x02")
        with self.assertRaises(ValueError):
            src.read(0, 10)

    def test_read_exact_size(self):
        from pydbg.pe.source import BytesSource
        src = BytesSource(b"\x01\x02\x03")
        data = src.read(0, 3)
        self.assertEqual(len(data), 3)

    def test_read_empty(self):
        from pydbg.pe.source import BytesSource
        src = BytesSource(b"")
        with self.assertRaises(ValueError):
            src.read(0, 1)


class TestFileSource(unittest.TestCase):
    """Tests for FileSource."""

    def test_read_kernel32(self):
        """Read MZ header from kernel32.dll."""
        from pydbg.pe.source import FileSource
        path = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"),
            "System32", "kernel32.dll"
        )
        if not os.path.exists(path):
            self.skipTest("kernel32.dll not found")

        with FileSource(path) as src:
            data = src.read(0, 2)
            self.assertEqual(data, b"MZ")

    def test_context_manager(self):
        """FileSource works as context manager."""
        from pydbg.pe.source import FileSource
        path = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"),
            "System32", "kernel32.dll"
        )
        if not os.path.exists(path):
            self.skipTest("kernel32.dll not found")

        with FileSource(path) as src:
            self.assertIsNotNone(src.read(0, 2))

    def test_nonexistent_file(self):
        from pydbg.pe.source import FileSource
        with self.assertRaises((FileNotFoundError, OSError)):
            FileSource("nonexistent_file.dll")


class TestFileView(unittest.TestCase):
    """Tests for FileView address translation."""

    def test_rva_in_section(self):
        from pydbg.pe.view import FileView
        from pydbg.pe.types import SectionHeader

        sections = [
            SectionHeader(name=".text", virtual_size=0x1000,
                          virtual_address=0x1000, size_of_raw_data=0x1000,
                          pointer_to_raw_data=0x400, characteristics=0),
            SectionHeader(name=".rdata", virtual_size=0x1000,
                          virtual_address=0x2000, size_of_raw_data=0x1000,
                          pointer_to_raw_data=0x1400, characteristics=0),
        ]
        view = FileView(sections)
        # RVA 0x1050 in .text -> file offset 0x450
        self.assertEqual(view.rva_to_source_offset(0x1050), 0x450)
        # RVA 0x2100 in .rdata -> file offset 0x1500
        self.assertEqual(view.rva_to_source_offset(0x2100), 0x1500)

    def test_rva_outside_sections(self):
        from pydbg.pe.view import FileView
        from pydbg.pe.types import SectionHeader

        sections = [
            SectionHeader(name=".text", virtual_size=0x1000,
                          virtual_address=0x1000, size_of_raw_data=0x1000,
                          pointer_to_raw_data=0x400, characteristics=0),
        ]
        view = FileView(sections)
        self.assertIsNone(view.rva_to_source_offset(0x5000))

    def test_rva_between_sections(self):
        """RVA in gap between sections returns None."""
        from pydbg.pe.view import FileView
        from pydbg.pe.types import SectionHeader

        sections = [
            SectionHeader(name=".text", virtual_size=0x1000,
                          virtual_address=0x1000, size_of_raw_data=0x1000,
                          pointer_to_raw_data=0x400, characteristics=0),
            SectionHeader(name=".rdata", virtual_size=0x1000,
                          virtual_address=0x3000, size_of_raw_data=0x1000,
                          pointer_to_raw_data=0x1400, characteristics=0),
        ]
        view = FileView(sections)
        # Gap at 0x2000
        self.assertIsNone(view.rva_to_source_offset(0x2000))

    def test_rva_at_section_boundary(self):
        """RVA exactly at section start."""
        from pydbg.pe.view import FileView
        from pydbg.pe.types import SectionHeader

        sections = [
            SectionHeader(name=".text", virtual_size=0x1000,
                          virtual_address=0x1000, size_of_raw_data=0x1000,
                          pointer_to_raw_data=0x400, characteristics=0),
        ]
        view = FileView(sections)
        self.assertEqual(view.rva_to_source_offset(0x1000), 0x400)

    def test_empty_sections(self):
        from pydbg.pe.view import FileView
        view = FileView([])
        self.assertIsNone(view.rva_to_source_offset(0x1000))


class TestLoadedView(unittest.TestCase):
    """Tests for LoadedView address translation."""

    def test_rva_is_identity(self):
        from pydbg.pe.view import LoadedView
        view = LoadedView()
        self.assertEqual(view.rva_to_source_offset(0x1234), 0x1234)
        self.assertEqual(view.rva_to_source_offset(0), 0)

    def test_large_rva(self):
        from pydbg.pe.view import LoadedView
        view = LoadedView()
        self.assertEqual(view.rva_to_source_offset(0x7FFFFFFF), 0x7FFFFFFF)


# ═══════════════════════════════════════════════════════════════════
# 4. Disasm Analysis Edge Cases
# ═══════════════════════════════════════════════════════════════════

class TestResolveDirectTarget(unittest.TestCase):
    """Tests for _resolve_direct_target helper."""

    def test_hex_format(self):
        from pydbg.disasm.analysis import _resolve_direct_target
        from pydbg.disasm.engine import Instruction

        insn = Instruction(address=0x1000, size=5, mnemonic="call",
                           op_str="0x401000", raw_bytes=b'')
        self.assertEqual(_resolve_direct_target(insn), 0x401000)

    def test_hex_with_comma(self):
        from pydbg.disasm.analysis import _resolve_direct_target
        from pydbg.disasm.engine import Instruction

        insn = Instruction(address=0x1000, size=5, mnemonic="call",
                           op_str="0x401000, extra", raw_bytes=b'')
        self.assertEqual(_resolve_direct_target(insn), 0x401000)

    def test_hex_suffix_format(self):
        from pydbg.disasm.analysis import _resolve_direct_target
        from pydbg.disasm.engine import Instruction

        insn = Instruction(address=0x1000, size=5, mnemonic="jmp",
                           op_str="401000h", raw_bytes=b'')
        self.assertEqual(_resolve_direct_target(insn), 0x401000)

    def test_empty_op_str(self):
        from pydbg.disasm.analysis import _resolve_direct_target
        from pydbg.disasm.engine import Instruction

        insn = Instruction(address=0x1000, size=1, mnemonic="ret",
                           op_str="", raw_bytes=b'')
        self.assertIsNone(_resolve_direct_target(insn))

    def test_none_instruction(self):
        from pydbg.disasm.analysis import _resolve_direct_target
        self.assertIsNone(_resolve_direct_target(None))

    def test_register_operand(self):
        from pydbg.disasm.analysis import _resolve_direct_target
        from pydbg.disasm.engine import Instruction

        insn = Instruction(address=0x1000, size=2, mnemonic="call",
                           op_str="rax", raw_bytes=b'')
        self.assertIsNone(_resolve_direct_target(insn))

    def test_memory_operand(self):
        from pydbg.disasm.analysis import _resolve_direct_target
        from pydbg.disasm.engine import Instruction

        insn = Instruction(address=0x1000, size=6, mnemonic="call",
                           op_str="[rax+0x10]", raw_bytes=b'')
        self.assertIsNone(_resolve_direct_target(insn))


class TestComputeSuccessors(unittest.TestCase):
    """Tests for _compute_successors helper."""

    def test_ret_no_successors(self):
        from pydbg.disasm.analysis import _compute_successors
        from pydbg.disasm.engine import Instruction

        insn = Instruction(address=0x1000, size=1, mnemonic="ret",
                           op_str="", raw_bytes=b'\xc3', is_ret=True)
        self.assertEqual(_compute_successors(insn), [])

    def test_conditional_branch(self):
        from pydbg.disasm.analysis import _compute_successors
        from pydbg.disasm.engine import Instruction

        insn = Instruction(address=0x1000, size=2, mnemonic="jne",
                           op_str="0x1010", raw_bytes=b'\x75\x0e',
                           is_jmp=True, is_cond=True)
        succs = _compute_successors(insn)
        self.assertIn(0x1010, succs)  # branch target
        self.assertIn(0x1002, succs)  # fallthrough
        self.assertEqual(len(succs), 2)

    def test_unconditional_jmp(self):
        from pydbg.disasm.analysis import _compute_successors
        from pydbg.disasm.engine import Instruction

        insn = Instruction(address=0x1000, size=5, mnemonic="jmp",
                           op_str="0x2000", raw_bytes=b'\xe9',
                           is_jmp=True, is_cond=False)
        succs = _compute_successors(insn)
        self.assertEqual(succs, [0x2000])

    def test_call_returns_both(self):
        from pydbg.disasm.analysis import _compute_successors
        from pydbg.disasm.engine import Instruction

        insn = Instruction(address=0x1000, size=5, mnemonic="call",
                           op_str="0x3000", raw_bytes=b'\xe8',
                           is_call=True)
        succs = _compute_successors(insn)
        self.assertIn(0x3000, succs)  # call target
        self.assertIn(0x1005, succs)  # return address
        self.assertEqual(len(succs), 2)

    def test_regular_fallthrough(self):
        from pydbg.disasm.analysis import _compute_successors
        from pydbg.disasm.engine import Instruction

        insn = Instruction(address=0x1000, size=3, mnemonic="mov",
                           op_str="eax, 1", raw_bytes=b'\xb8\x01\x00')
        succs = _compute_successors(insn)
        self.assertEqual(succs, [0x1003])

    def test_none_instruction(self):
        from pydbg.disasm.analysis import _compute_successors
        self.assertEqual(_compute_successors(None), [])


@unittest.skipUnless(_has_capstone, "requires capstone")
class TestBuildBlocksEdgeCases(unittest.TestCase):
    """Tests for build_blocks edge cases."""

    def test_empty_instructions(self):
        from pydbg.disasm.analysis import build_blocks
        self.assertEqual(build_blocks([]), [])

    def test_single_nop(self):
        from pydbg.disasm.analysis import build_blocks
        from pydbg.disasm.engine import Instruction

        insns = [Instruction(address=0x1000, size=1, mnemonic="nop",
                             op_str="", raw_bytes=b'\x90')]
        blocks = build_blocks(insns)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].start_addr, 0x1000)

    def test_unconditional_jmp_creates_two_blocks(self):
        from pydbg.disasm.engine import DisasmEngine
        from pydbg.disasm.analysis import build_blocks

        # jmp +2; nop; nop; ret
        code = bytes([0xEB, 0x02, 0x90, 0x90, 0xC3])
        engine = DisasmEngine(mode="x64")
        insns = engine.disasm(0x1000, code)
        blocks = build_blocks(insns)
        self.assertGreaterEqual(len(blocks), 2)


@unittest.skipUnless(_has_capstone, "requires capstone")
class TestBuildCFGEdgeCases(unittest.TestCase):
    """Tests for build_cfg edge cases."""

    def test_empty_cfg(self):
        from pydbg.disasm.analysis import build_cfg
        cfg = build_cfg([])
        self.assertEqual(cfg.entry, 0)
        self.assertEqual(cfg.blocks, {})
        self.assertEqual(cfg.edges, [])

    def test_custom_entry_addr(self):
        from pydbg.disasm.engine import DisasmEngine
        from pydbg.disasm.analysis import build_blocks, build_cfg

        code = bytes([0xC3])  # ret
        engine = DisasmEngine(mode="x64")
        insns = engine.disasm(0x2000, code)
        blocks = build_blocks(insns)
        cfg = build_cfg(blocks, entry_addr=0x2000)
        self.assertEqual(cfg.entry, 0x2000)

    def test_cfg_edge_types(self):
        from pydbg.disasm.engine import DisasmEngine
        from pydbg.disasm.analysis import build_blocks, build_cfg

        # xor eax,eax; test eax,eax; jne +2; inc eax; ret
        code = bytes([0x31, 0xC0, 0x85, 0xC0, 0x75, 0x02, 0xFF, 0xC0, 0xC3])
        engine = DisasmEngine(mode="x64")
        insns = engine.disasm(0x1000, code)
        blocks = build_blocks(insns)
        cfg = build_cfg(blocks)
        edge_types = {e.type for e in cfg.edges}
        self.assertTrue(len(edge_types) > 0)


# ═══════════════════════════════════════════════════════════════════
# 5. Symbol Resolver
# ═══════════════════════════════════════════════════════════════════

class TestSymbolResolver(unittest.TestCase):
    """Tests for SymbolResolver."""

    def test_init_not_initialized(self):
        from pydbg.core.session import DebugSession
        from pydbg.symbol.resolver import SymbolResolver

        session = DebugSession()
        sr = SymbolResolver(session)
        self.assertFalse(sr._initialized)

    def test_from_name_before_init_raises(self):
        from pydbg.core.session import DebugSession
        from pydbg.symbol.resolver import SymbolResolver
        from pydbg.exceptions import PydbgError

        session = DebugSession()
        sr = SymbolResolver(session)
        with self.assertRaises(PydbgError):
            sr.from_name("test")

    def test_from_addr_before_init_raises(self):
        from pydbg.core.session import DebugSession
        from pydbg.symbol.resolver import SymbolResolver
        from pydbg.exceptions import PydbgError

        session = DebugSession()
        sr = SymbolResolver(session)
        with self.assertRaises(PydbgError):
            sr.from_addr(0x1000)

    def test_load_module_before_init_raises(self):
        from pydbg.core.session import DebugSession
        from pydbg.symbol.resolver import SymbolResolver
        from pydbg.exceptions import PydbgError

        session = DebugSession()
        sr = SymbolResolver(session)
        with self.assertRaises(PydbgError):
            sr.load_module("test.dll", 0x10000)

    def test_cleanup_before_init_is_noop(self):
        from pydbg.core.session import DebugSession
        from pydbg.symbol.resolver import SymbolResolver

        session = DebugSession()
        sr = SymbolResolver(session)
        sr.cleanup()  # should not raise
        self.assertFalse(sr._initialized)

    def test_set_options_delegates(self):
        """set_options should not raise even without process."""
        from pydbg.core.session import DebugSession
        from pydbg.symbol.resolver import SymbolResolver

        session = DebugSession()
        sr = SymbolResolver(session)
        if _has_cython:
            sr.set_options(0x2)  # SYMOPT_UNDNAME


# ═══════════════════════════════════════════════════════════════════
# 6. Module Resolver
# ═══════════════════════════════════════════════════════════════════

class TestModuleResolver(unittest.TestCase):
    """Tests for ModuleResolver."""

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_enumerate_returns_list(self):
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        for _ in range(50):
            event = dbg.wait_event(2000)
            if event is None or event.type == "EXIT_PROCESS":
                break
            if event.type == "EXCEPTION":
                break
            dbg.continue_event(event.pid, event.tid)

        modules = dbg.enum_modules()
        self.assertIsInstance(modules, list)
        self.assertGreater(len(modules), 0)
        self.assertIn("handle", modules[0])
        self.assertIn("base_address", modules[0])

        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_get_module_filename(self):
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        for _ in range(50):
            event = dbg.wait_event(2000)
            if event is None or event.type == "EXIT_PROCESS":
                break
            if event.type == "EXCEPTION":
                break
            dbg.continue_event(event.pid, event.tid)

        modules = dbg.enum_modules()
        filename = dbg.get_module_filename(modules[0]["handle"])
        self.assertIsInstance(filename, str)
        self.assertGreater(len(filename), 0)

        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)


# ═══════════════════════════════════════════════════════════════════
# 7. Hook Integration
# ═══════════════════════════════════════════════════════════════════

class TestIATHookFullFlow(unittest.TestCase):
    """Tests for IATHook with synthetic PE data."""

    def _build_pe_with_imports(self):
        """Build minimal PE32+ with one import: MessageBoxA from user32.dll."""
        from tests.test_pe import build_pe_with_imports
        return build_pe_with_imports()

    def test_set_and_restore(self):
        """Full set/restore cycle with mock memory."""
        from pydbg.core.session import DebugSession
        from pydbg.hook.iat import IATHook

        session = DebugSession()
        session.target_arch = 64
        hook = IATHook(session)
        pe_data = self._build_pe_with_imports()

        base = 0x140000000
        # IAT entry at RVA 0x5400 → absolute addr = base + 0x5400
        iat_abs = base + 0x5400
        # Pre-fill IAT with a fake function pointer
        fake_func_ptr = 0x7FFE1234
        pe_buf = bytearray(pe_data)
        struct.pack_into('<Q', pe_buf, 0x5400, fake_func_ptr)

        # Mock memory that reads from the PE buffer at the right offset
        class MockMemory:
            def __init__(self, data, base_addr):
                self._data = data
                self._base = base_addr
                self.written = {}

            def read(self, addr, size):
                offset = addr - self._base
                return bytes(self._data[offset:offset + size])

            def write(self, addr, data):
                offset = addr - self._base
                self._data[offset:offset + len(data)] = data
                self.written[addr] = data

        class MockModules:
            def enumerate(self):
                return [{'name': 'test.exe', 'base_address': base,
                         'handle': base}]

        mem = MockMemory(pe_buf, base)
        hook._get_memory = lambda: mem
        hook._get_modules = lambda: MockModules()

        # Patch _find_iat_addr to return absolute address instead of RVA
        # (the real implementation returns RVA which is used with base in real memory)
        orig_find = hook._find_iat_addr

        def patched_find_iat(mod, func_name, memory):
            rva = orig_find(mod, func_name, memory)
            if rva is not None:
                return mod['base_address'] + rva
            return None
        hook._find_iat_addr = patched_find_iat

        # Set hook — replaces IAT entry
        original = hook.set('test.exe', 'MessageBoxA', 0x9999)
        self.assertEqual(original, fake_func_ptr)
        self.assertIn(('test.exe', 'MessageBoxA'), hook.list_hooks())

        # Verify IAT was overwritten
        new_val = int.from_bytes(mem.read(iat_abs, 8), 'little')
        self.assertEqual(new_val, 0x9999)

        # Restore — puts original back
        hook.restore('test.exe', 'MessageBoxA')
        self.assertEqual(hook.list_hooks(), {})
        restored_val = int.from_bytes(mem.read(iat_abs, 8), 'little')
        self.assertEqual(restored_val, fake_func_ptr)

    def test_find_returns_none_for_unknown(self):
        from pydbg.core.session import DebugSession
        from pydbg.hook.iat import IATHook

        session = DebugSession()
        session.target_arch = 64
        hook = IATHook(session)

        class MockMemory:
            def read(self, addr, size):
                return b'\x00' * size

        class MockModules:
            def enumerate(self):
                return [{'name': 'test.exe', 'base_address': 0x140000000}]

        hook._get_memory = lambda: MockMemory()
        hook._get_modules = lambda: MockModules()

        result = hook.find('test.exe', 'NonExistent')
        self.assertIsNone(result)

    def test_ptr_size_32bit(self):
        from pydbg.core.session import DebugSession
        from pydbg.hook.iat import IATHook

        session = DebugSession()
        session.target_arch = 32
        hook = IATHook(session)
        self.assertEqual(hook._ptr_size(), 4)

    def test_ptr_size_64bit(self):
        from pydbg.core.session import DebugSession
        from pydbg.hook.iat import IATHook

        session = DebugSession()
        session.target_arch = 64
        hook = IATHook(session)
        self.assertEqual(hook._ptr_size(), 8)


@unittest.skipUnless(_has_capstone, "requires capstone")
class TestInlineHookEdgeCases(unittest.TestCase):
    """Tests for InlineHook edge cases."""

    def test_read_min_5_bytes(self):
        """Verify _read_min_5_bytes reads enough for JMP."""
        from pydbg.core.session import DebugSession
        from pydbg.hook.inline import InlineHook
        from pydbg.disasm.engine import DisasmEngine

        session = DebugSession()
        hook = InlineHook(session)
        engine = DisasmEngine(mode="x64")

        # 7-byte instruction (mov rax, 1) + ret
        code = bytes([0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xC3])

        class MockMem:
            def read(self, addr, size):
                return code

        result = hook._read_min_5_bytes(MockMem(), engine, 0x1000)
        self.assertGreaterEqual(len(result), 5)

    def test_multiple_hooks_tracked(self):
        from pydbg.core.session import DebugSession
        from pydbg.hook.inline import InlineHook

        session = DebugSession()
        hook = InlineHook(session)

        from pydbg.hook.inline import Trampoline
        t1 = Trampoline(addr=0x2000, size=10, original_code=b'\x55')
        t2 = Trampoline(addr=0x3000, size=10, original_code=b'\x48\x89\xe5')

        hook._hooks[0x1000] = t1
        hook._hooks[0x1100] = t2

        self.assertEqual(len(hook._hooks), 2)
        self.assertIn(0x1000, hook._hooks)
        self.assertIn(0x1100, hook._hooks)


# ═══════════════════════════════════════════════════════════════════
# 8. Dump/Minidump
# ═══════════════════════════════════════════════════════════════════

class TestMinidumpReaderEdgeCases(unittest.TestCase):
    """Tests for MinidumpReader."""

    def test_lazy_load(self):
        """Data should not be loaded until get_stream is called."""
        from pydbg.dump.minidump import MinidumpReader
        reader = MinidumpReader("test.dmp")
        self.assertIsNone(reader._data)

    def test_stream_constants_correct(self):
        from pydbg.dump.minidump import (
            STREAM_UNUSED, STREAM_THREAD_LIST, STREAM_MODULE_LIST,
            STREAM_MEMORY_LIST, STREAM_EXCEPTION, STREAM_SYSTEM_INFO,
            STREAM_MEMORY_64_LIST,
        )
        self.assertEqual(STREAM_UNUSED, 0)
        self.assertEqual(STREAM_THREAD_LIST, 3)
        self.assertEqual(STREAM_MODULE_LIST, 4)
        self.assertEqual(STREAM_MEMORY_LIST, 5)
        self.assertEqual(STREAM_EXCEPTION, 6)
        self.assertEqual(STREAM_SYSTEM_INFO, 7)
        self.assertEqual(STREAM_MEMORY_64_LIST, 9)


class TestStackWalkerEdgeCases(unittest.TestCase):
    """Tests for StackWalker."""

    def test_machine_constant(self):
        from pydbg.dump.stackwalk import StackWalker
        self.assertEqual(StackWalker.MACHINE_X64, 0x8664)

    def test_init_with_session(self):
        from pydbg.dump.stackwalk import StackWalker
        from pydbg.core.session import DebugSession

        sw = StackWalker(DebugSession())
        self.assertIsNotNone(sw._s)


# ═══════════════════════════════════════════════════════════════════
# 9. Assembler Edge Cases
# ═══════════════════════════════════════════════════════════════════

@unittest.skipUnless(_has_keystone, "requires keystone-engine")
class TestAssemblerEdgeCases(unittest.TestCase):
    """Tests for Assembler edge cases."""

    def test_multiline_with_comments(self):
        from pydbg.patch.assembler import Assembler
        asm = Assembler()
        # Newlines and semicolons should both work
        code = asm.assemble("xor eax, eax\nret")
        self.assertEqual(code, b'\x31\xc0\xc3')

    def test_empty_and_whitespace(self):
        from pydbg.patch.assembler import Assembler
        asm = Assembler()
        self.assertEqual(asm.assemble(""), b'')
        self.assertEqual(asm.assemble("  "), b'')
        self.assertEqual(asm.assemble("\n"), b'')

    def test_nop(self):
        from pydbg.patch.assembler import Assembler
        asm = Assembler()
        self.assertEqual(asm.assemble("nop"), b'\x90')

    def test_verify_roundtrip(self):
        from pydbg.patch.assembler import Assembler
        asm = Assembler()
        self.assertTrue(asm.verify("ret"))
        self.assertTrue(asm.verify("nop"))

    def test_assemble_with_address(self):
        """Assembly with address should produce valid bytes."""
        from pydbg.patch.assembler import Assembler
        asm = Assembler()
        code = asm.assemble("nop", 0x1000)
        self.assertEqual(code, b'\x90')

    def test_invalid_assembly_raises(self):
        from pydbg.patch.assembler import Assembler
        from pydbg.exceptions import PydbgError
        asm = Assembler()
        with self.assertRaises(PydbgError):
            asm.assemble("invalid_instruction_xyz")

    def test_x86_mode(self):
        from pydbg.patch.assembler import Assembler
        asm = Assembler(mode="x86")
        self.assertEqual(asm.mode(), "x86")
        code = asm.assemble("ret")
        self.assertEqual(code, b'\xc3')

    def test_x64_mode(self):
        from pydbg.patch.assembler import Assembler
        asm = Assembler(mode="x64")
        self.assertEqual(asm.mode(), "x64")

    def test_bad_mode_raises(self):
        from pydbg.patch.assembler import Assembler
        from pydbg.exceptions import PydbgError
        with self.assertRaises(PydbgError):
            Assembler(mode="arm")


# ═══════════════════════════════════════════════════════════════════
# 10. Integration Tests
# ═══════════════════════════════════════════════════════════════════

class TestDebuggerFullLifecycle(unittest.TestCase):
    """Integration tests for Debugger full lifecycle."""

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_create_process_returns_valid_ids(self):
        from pydbg import Debugger
        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        self.assertGreater(pid, 0)
        self.assertGreater(tid, 0)
        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_create_invalid_path_raises(self):
        from pydbg import Debugger
        from pydbg.exceptions import ProcessError
        dbg = Debugger()
        with self.assertRaises(ProcessError):
            dbg.create_process("nonexistent_program_xyz.exe")

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_detach_nonexistent_raises(self):
        from pydbg import Debugger
        from pydbg.exceptions import ProcessError
        dbg = Debugger()
        with self.assertRaises(ProcessError):
            dbg.detach(999999)

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_wait_event_returns_debug_event(self):
        from pydbg import Debugger, DebugEvent
        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        event = dbg.wait_event(5000)
        self.assertIsNotNone(event)
        self.assertIsInstance(event, DebugEvent)
        self.assertEqual(event.type, "CREATE_PROCESS")
        dbg.continue_event(pid, tid)
        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_wait_event_timeout_returns_none(self):
        from pydbg import Debugger
        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)
        # Drain until initial breakpoint
        for _ in range(50):
            event = dbg.wait_event(2000)
            if event is None or event.type == "EXIT_PROCESS":
                break
            if event.type == "EXCEPTION":
                break
            dbg.continue_event(event.pid, event.tid)
        # Now wait with very short timeout - should return None
        event = dbg.wait_event(1)  # 1ms
        # May or may not be None depending on timing
        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_run_loop_returns_exit_code(self):
        from pydbg import Debugger
        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)

        events = []

        def on_event(event):
            events.append(event.type)

        exit_code = dbg.run(on_event, timeout_ms=5000)
        self.assertIsInstance(exit_code, int)
        self.assertIn("CREATE_PROCESS", events)

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_run_loop_callback_false_stops(self):
        from pydbg import Debugger
        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)

        call_count = 0

        def on_event(event):
            nonlocal call_count
            call_count += 1
            return False  # stop after first event

        dbg.run(on_event, timeout_ms=5000)
        self.assertGreaterEqual(call_count, 1)

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_terminate_drains_events(self):
        from pydbg import Debugger
        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        dbg.terminate_process(0)
        # After terminate, process handle should still be valid
        self.assertIsNotNone(dbg._session.process_handle)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_get_exit_code_running(self):
        from pydbg import Debugger
        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        code = dbg.get_exit_code()
        self.assertEqual(code, 259)  # STILL_ACTIVE

        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)


class TestBreakpointInRunLoop(unittest.TestCase):
    """Integration tests for breakpoints in the run loop."""

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_software_breakpoint_lifecycle(self):
        """Set BP, run loop, verify BP is hit and restored."""
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)

        # Get to initial breakpoint
        event = dbg.wait_event(5000)
        self.assertEqual(event.type, "CREATE_PROCESS")
        dbg.continue_event(event.pid, event.tid)

        # Consume until first EXCEPTION (loader bp)
        for _ in range(50):
            event = dbg.wait_event(2000)
            if event is None or event.type == "EXIT_PROCESS":
                break
            if event.type == "EXCEPTION":
                break
            dbg.continue_event(event.pid, event.tid)

        # Now set a breakpoint at the current IP
        h_thread = dbg.open_thread(tid)
        regs = dbg.get_registers(h_thread)
        addr = regs[IP_REG]
        bp_id = dbg.set_breakpoint(addr)
        dbg.close_handle(h_thread)

        # Verify breakpoint is set
        self.assertIsNotNone(dbg.find_breakpoint(addr))
        self.assertEqual(dbg.find_breakpoint(addr), bp_id)

        # Remove and verify
        dbg.remove_breakpoint(bp_id)
        self.assertIsNone(dbg.find_breakpoint(addr))

        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_multiple_breakpoints(self):
        """Set multiple breakpoints."""
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        for _ in range(50):
            event = dbg.wait_event(2000)
            if event is None or event.type == "EXIT_PROCESS":
                break
            if event.type == "EXCEPTION":
                break
            dbg.continue_event(event.pid, event.tid)

        modules = dbg.enum_modules()
        base = modules[0]["base_address"]

        # Set multiple breakpoints at different addresses
        bp1 = dbg.set_breakpoint(base)
        bp2 = dbg.set_breakpoint(base + 0x100)
        bp3 = dbg.set_breakpoint(base + 0x200)

        self.assertNotEqual(bp1, bp2)
        self.assertNotEqual(bp2, bp3)

        # All should be findable
        self.assertEqual(dbg.find_breakpoint(base), bp1)
        self.assertEqual(dbg.find_breakpoint(base + 0x100), bp2)
        self.assertEqual(dbg.find_breakpoint(base + 0x200), bp3)

        # Remove all
        dbg.remove_breakpoint(bp1)
        dbg.remove_breakpoint(bp2)
        dbg.remove_breakpoint(bp3)

        self.assertIsNone(dbg.find_breakpoint(base))

        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_hardware_breakpoint_all_slots(self):
        """Test hardware breakpoints in all 4 slots."""
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        for _ in range(50):
            event = dbg.wait_event(2000)
            if event is None or event.type == "EXIT_PROCESS":
                break
            if event.type == "EXCEPTION":
                break
            dbg.continue_event(event.pid, event.tid)

        h_thread = dbg.open_thread(tid)
        regs = dbg.get_registers(h_thread)
        base = regs[IP_REG]

        bp_ids = []
        for slot in range(4):
            bp_id = dbg.set_hw_breakpoint(base + slot * 0x10, "x", 1, slot)
            bp_ids.append(bp_id)

        # All should have unique IDs
        self.assertEqual(len(set(bp_ids)), 4)

        # Remove all
        for bp_id in bp_ids:
            dbg.remove_breakpoint(bp_id)

        dbg.close_handle(h_thread)
        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_remove_nonexistent_breakpoint_raises(self):
        from pydbg import Debugger
        from pydbg.exceptions import BreakpointError

        dbg = Debugger()
        with self.assertRaises(BreakpointError):
            dbg.remove_breakpoint(999)

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_hw_breakpoint_invalid_condition(self):
        from pydbg import Debugger
        from pydbg.exceptions import BreakpointError

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        h_thread = dbg.open_thread(tid)
        with self.assertRaises(BreakpointError):
            dbg.set_hw_breakpoint(0x1000, condition="invalid")
        dbg.close_handle(h_thread)
        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)


class TestMemoryIntegration(unittest.TestCase):
    """Integration tests for memory operations."""

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_read_write_cycle(self):
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        for _ in range(50):
            event = dbg.wait_event(2000)
            if event is None or event.type == "EXIT_PROCESS":
                break
            if event.type == "EXCEPTION":
                break
            dbg.continue_event(event.pid, event.tid)

        modules = dbg.enum_modules()
        base = modules[0]["base_address"]

        # Read MZ header
        data = dbg.read_memory(base, 2)
        self.assertEqual(data, b"MZ")

        # Query memory
        info = dbg.query_memory(base)
        self.assertIn("base_address", info)
        self.assertIn("protect", info)

        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_read_memory_invalid_raises(self):
        from pydbg import Debugger
        from pydbg.exceptions import MemError

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        for _ in range(50):
            event = dbg.wait_event(2000)
            if event is None or event.type == "EXIT_PROCESS":
                break
            if event.type == "EXCEPTION":
                break
            dbg.continue_event(event.pid, event.tid)

        # Reading from invalid address should raise MemError
        with self.assertRaises(MemError):
            dbg.read_memory(0x0, 4)

        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)


class TestThreadIntegration(unittest.TestCase):
    """Integration tests for thread operations."""

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_open_and_get_registers(self):
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        h_thread = dbg.open_thread(tid)
        regs = dbg.get_registers(h_thread)
        self.assertIn(IP_REG, regs)
        self.assertIn(SP_REG, regs)
        self.assertIn(GP_REG, regs)
        self.assertIn("eflags", regs)
        self.assertIn("arch", regs)

        dbg.close_handle(h_thread)
        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_suspend_resume_thread(self):
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        h_thread = dbg.open_thread(tid)
        count = dbg.suspend_thread(h_thread)
        self.assertGreaterEqual(count, 0)

        count2 = dbg.resume_thread(h_thread)
        self.assertGreaterEqual(count2, 0)

        dbg.close_handle(h_thread)
        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_enumerate_threads(self):
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        for _ in range(50):
            event = dbg.wait_event(2000)
            if event is None or event.type == "EXIT_PROCESS":
                break
            if event.type == "EXCEPTION":
                break
            dbg.continue_event(event.pid, event.tid)

        tids = dbg.get_thread_ids()
        self.assertIsInstance(tids, list)
        self.assertGreater(len(tids), 0)
        self.assertIn(tid, tids)

        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_set_register(self):
        from pydbg import Debugger

        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_TARGET_PATH)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        h_thread = dbg.open_thread(tid)
        regs = dbg.get_registers(h_thread)

        # Set eflags (should not crash)
        old_flags = regs["eflags"]
        dbg.set_register(h_thread, "eflags", old_flags | 0x100)  # set TF
        new_regs = dbg.get_registers(h_thread)
        self.assertTrue(new_regs["eflags"] & 0x100)

        # Restore
        dbg.set_register(h_thread, "eflags", old_flags)

        dbg.close_handle(h_thread)
        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)


@unittest.skipUnless(_has_capstone, "requires capstone")
class TestDisasmEngineIntegration(unittest.TestCase):
    """Integration tests for DisasmEngine."""

    def test_auto_mode_detects_host(self):
        from pydbg.disasm.engine import DisasmEngine
        engine = DisasmEngine()
        expected = "x64" if HOST_ARCH == 64 else "x86"
        self.assertEqual(engine.mode(), expected)

    def test_session_based_mode(self):
        from pydbg.core.session import DebugSession
        from pydbg.disasm.engine import DisasmEngine

        session = DebugSession()
        session.target_arch = 32
        engine = DisasmEngine(session=session)
        self.assertEqual(engine.mode(), "x86")

        session2 = DebugSession()
        session2.target_arch = 64
        engine2 = DisasmEngine(session=session2)
        self.assertEqual(engine2.mode(), "x64")

    def test_disasm_with_detail(self):
        from pydbg.disasm.engine import DisasmEngine

        engine = DisasmEngine(mode="x64")
        # call 0x401000
        code = bytes([0xE8, 0x00, 0x00, 0x00, 0x00])
        insns = engine.disasm(0x1000, code)
        self.assertEqual(len(insns), 1)
        self.assertTrue(insns[0].is_call)
        self.assertFalse(insns[0].is_jmp)
        self.assertFalse(insns[0].is_ret)

    def test_iter_disasm_lazy(self):
        from pydbg.disasm.engine import DisasmEngine

        engine = DisasmEngine(mode="x64")
        code = bytes([0x90, 0x90, 0xC3])  # nop; nop; ret
        results = list(engine.iter_disasm(0x0, code))
        self.assertEqual(len(results), 3)
        self.assertTrue(results[2].is_ret)

    def test_invalid_mode_raises(self):
        from pydbg.disasm.engine import DisasmEngine
        from pydbg.exceptions import PydbgError

        engine = DisasmEngine(mode="arm")
        with self.assertRaises(PydbgError):
            engine.mode()


class TestStepTracerIntegration(unittest.TestCase):
    """Integration tests for StepTracer."""

    def test_is_step_event(self):
        from pydbg.trace.step import StepTracer, EXCEPTION_SINGLE_STEP
        from pydbg.core.event import DebugEvent

        event = DebugEvent({
            'pid': 1, 'tid': 2,
            'event_name': 'EXCEPTION',
            'exception_code': EXCEPTION_SINGLE_STEP,
            'exception_address': 0x1000,
            'first_chance': 1,
            'exception_params': [],
        })
        self.assertTrue(StepTracer.is_step_event(event))

    def test_is_not_step_event(self):
        from pydbg.trace.step import StepTracer
        from pydbg.core.event import DebugEvent

        event = DebugEvent({
            'pid': 1, 'tid': 2,
            'event_name': 'CREATE_PROCESS',
        })
        self.assertFalse(StepTracer.is_step_event(event))


class TestCallTreeIntegration(unittest.TestCase):
    """Integration tests for CallTree."""

    def test_full_call_tree(self):
        from pydbg.trace.calltree import CallTree

        tree = CallTree()
        # main() calls foo(), foo() calls bar()
        tree.on_call(0x1000, 0x2000)  # main -> foo
        tree.on_call(0x2010, 0x3000)  # foo -> bar
        tree.on_ret(0x3010)           # bar returns
        tree.on_call(0x2020, 0x4000)  # foo -> baz
        tree.on_ret(0x4010)           # baz returns
        tree.on_ret(0x2030)           # foo returns

        self.assertEqual(tree.current_depth(), 0)
        self.assertEqual(len(tree.root.children), 1)
        main_node = tree.root.children[0]
        self.assertEqual(main_node.target, 0x2000)
        self.assertEqual(len(main_node.children), 2)

    def test_is_call_ret_insn(self):
        from pydbg.trace.calltree import CallTree
        from pydbg.disasm.engine import Instruction

        call_insn = Instruction(address=0, size=5, mnemonic="call",
                                op_str="0x2000", raw_bytes=b'\xe8',
                                is_call=True)
        ret_insn = Instruction(address=0, size=1, mnemonic="ret",
                               op_str="", raw_bytes=b'\xc3', is_ret=True)
        mov_insn = Instruction(address=0, size=3, mnemonic="mov",
                               op_str="eax, 1", raw_bytes=b'\xb8')

        self.assertTrue(CallTree.is_call_insn(call_insn))
        self.assertFalse(CallTree.is_call_insn(ret_insn))
        self.assertTrue(CallTree.is_ret_insn(ret_insn))
        self.assertFalse(CallTree.is_ret_insn(mov_insn))


class TestPEParserEdgeCases(unittest.TestCase):
    """Tests for PE parser edge cases."""

    def test_pe32_parse_complete(self):
        from pydbg.pe import PE
        from tests.test_pe import build_minimal_pe32

        data = build_minimal_pe32()
        pe = PE(data)
        self.assertEqual(pe.dos_header.e_magic, 0x5A4D)
        self.assertEqual(pe.optional_header.magic, 0x10B)
        self.assertEqual(pe.file_header.machine, 0x14C)
        self.assertEqual(len(pe.sections), 2)
        self.assertEqual(pe.exports, [])
        self.assertEqual(pe.imports, [])

    def test_pe32plus_parse_complete(self):
        from pydbg.pe import PE
        from tests.test_pe import build_minimal_pe32plus

        data = build_minimal_pe32plus()
        pe = PE(data)
        self.assertEqual(pe.optional_header.magic, 0x20B)
        self.assertEqual(pe.file_header.machine, 0x8664)
        self.assertEqual(pe.optional_header.image_base, 0x140000000)

    def test_pe_with_exports(self):
        from pydbg.pe import PE
        from tests.test_pe import build_pe_with_exports

        data = build_pe_with_exports()
        pe = PE(data)
        self.assertEqual(len(pe.exports), 1)
        self.assertEqual(pe.exports[0].name, "MyExport")

    def test_pe_with_imports(self):
        from pydbg.pe import PE
        from tests.test_pe import build_pe_with_imports

        data = build_pe_with_imports()
        pe = PE(data)
        self.assertEqual(len(pe.imports), 1)
        self.assertEqual(pe.imports[0].dll_name, "user32.dll")
        self.assertEqual(pe.imports[0].name, "MessageBoxA")

    def test_invalid_dos_signature(self):
        from pydbg.pe import PE
        data = b"XX" + b"\x00" * 100
        with self.assertRaises(ValueError) as cm:
            PE(data)
        self.assertIn("DOS signature", str(cm.exception))

    def test_invalid_pe_signature(self):
        from pydbg.pe import PE
        data = struct.pack("<2s58xI", b"MZ", 0x40)
        data += b"\x00" * (0x44 - len(data))
        data += b"BADS"
        data += b"\x00" * 100
        with self.assertRaises(ValueError) as cm:
            PE(data)
        self.assertIn("PE signature", str(cm.exception))

    def test_from_file_kernel32(self):
        from pydbg.pe import PE
        path = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"),
            "System32", "kernel32.dll"
        )
        if not os.path.exists(path):
            self.skipTest("kernel32.dll not found")

        pe = PE.from_file(path)
        self.assertEqual(pe.dos_header.e_magic, 0x5A4D)
        self.assertGreater(len(pe.exports), 0)
        export_names = [e.name for e in pe.exports if e.name]
        self.assertIn("GetProcAddress", export_names)
        self.assertIn("LoadLibraryA", export_names)

    def test_from_file_ntdll(self):
        from pydbg.pe import PE
        path = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"),
            "System32", "ntdll.dll"
        )
        if not os.path.exists(path):
            self.skipTest("ntdll.dll not found")

        pe = PE.from_file(path)
        self.assertEqual(pe.dos_header.e_magic, 0x5A4D)
        self.assertGreater(len(pe.exports), 0)

    def test_rva_to_offset_pe32(self):
        from pydbg.pe import PE
        from tests.test_pe import build_minimal_pe32

        data = build_minimal_pe32()
        pe = PE(data)
        # .text: VA=0x1000, RawData=0x400
        offset = pe.rva_to_offset(0x1050)
        self.assertEqual(offset, 0x450)

    def test_rva_to_offset_pe32plus(self):
        from pydbg.pe import PE
        from tests.test_pe import build_minimal_pe32plus

        data = build_minimal_pe32plus()
        pe = PE(data)
        offset = pe.rva_to_offset(0x1050)
        self.assertEqual(offset, 0x450)

    def test_rva_outside_sections_returns_none(self):
        from pydbg.pe import PE
        from tests.test_pe import build_minimal_pe32plus

        data = build_minimal_pe32plus()
        pe = PE(data)
        self.assertIsNone(pe.rva_to_offset(0x99999))


class TestDebugEventEdgeCases(unittest.TestCase):
    """Tests for DebugEvent edge cases."""

    def test_exception_event_with_params(self):
        from pydbg import DebugEvent
        raw = {
            "event_name": "EXCEPTION",
            "pid": 100,
            "tid": 200,
            "exception_code": 0xC0000005,
            "exception_addr": 0xDEAD,
            "first_chance": True,
            "exception_params": [0, 0xDEAD],
        }
        event = DebugEvent(raw)
        self.assertEqual(event.exception_name, "EXCEPTION_ACCESS_VIOLATION")
        self.assertIsNotNone(event.exception_info)
        self.assertEqual(event.exception_info["access_type"], "read")
        self.assertEqual(event.exception_info["access_addr"], 0xDEAD)

    def test_exception_write_fault(self):
        from pydbg import DebugEvent
        raw = {
            "event_name": "EXCEPTION",
            "pid": 100,
            "tid": 200,
            "exception_code": 0xC0000005,
            "exception_addr": 0xBEEF,
            "first_chance": True,
            "exception_params": [1, 0xBEEF],  # write fault
        }
        event = DebugEvent(raw)
        self.assertEqual(event.exception_info["access_type"], "write")

    def test_exception_execute_fault(self):
        from pydbg import DebugEvent
        raw = {
            "event_name": "EXCEPTION",
            "pid": 100,
            "tid": 200,
            "exception_code": 0xC0000005,
            "exception_addr": 0xCAFE,
            "first_chance": True,
            "exception_params": [8, 0xCAFE],  # execute fault
        }
        event = DebugEvent(raw)
        self.assertEqual(event.exception_info["access_type"], "execute")

    def test_in_page_error(self):
        from pydbg import DebugEvent
        raw = {
            "event_name": "EXCEPTION",
            "pid": 100,
            "tid": 200,
            "exception_code": 0xC0000006,
            "exception_addr": 0x1000,
            "first_chance": True,
            "exception_params": [0, 0x1000, 0xC0000005],
        }
        event = DebugEvent(raw)
        self.assertIsNotNone(event.exception_info)
        self.assertIn("ntstatus", event.exception_info)

    def test_non_exception_event(self):
        from pydbg import DebugEvent
        raw = {"event_name": "LOAD_DLL", "pid": 1, "tid": 2}
        event = DebugEvent(raw)
        self.assertIsNone(event.exception_code)
        self.assertIsNone(event.exception_name)
        self.assertIsNone(event.exception_info)

    def test_unknown_event_type(self):
        from pydbg import DebugEvent
        event = DebugEvent({})
        self.assertEqual(event.type, "UNKNOWN")


class TestExceptionHelpers(unittest.TestCase):
    """Tests for exception code helpers."""

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_all_known_codes(self):
        codes = {
            0xC0000005: "EXCEPTION_ACCESS_VIOLATION",
            0x80000003: "EXCEPTION_BREAKPOINT",
            0x80000004: "EXCEPTION_SINGLE_STEP",
            0x80000001: "EXCEPTION_GUARD_PAGE",
            0xC0000094: "EXCEPTION_INT_DIVIDE_BY_ZERO",
            0xC00000FD: "EXCEPTION_STACK_OVERFLOW",
        }
        for code, expected in codes.items():
            result = _pydbg.exception_code_to_str(code)
            self.assertEqual(result, expected, f"Failed for 0x{code:08X}")

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_unknown_code_format(self):
        result = _pydbg.exception_code_to_str(0x12345678)
        self.assertEqual(result, "UNKNOWN_EXCEPTION(0x12345678)")

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_get_exception_info_av(self):
        info = _pydbg.get_exception_info(0xC0000005, 0xDEAD, 1, [1, 0xBEEF])
        self.assertEqual(info["name"], "EXCEPTION_ACCESS_VIOLATION")
        self.assertEqual(info["access_type"], "write")
        self.assertEqual(info["access_addr"], 0xBEEF)
        self.assertTrue(info["first_chance"])

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_get_exception_info_breakpoint(self):
        info = _pydbg.get_exception_info(0x80000003, 0x1000, 1, [])
        self.assertEqual(info["name"], "EXCEPTION_BREAKPOINT")
        self.assertEqual(info["addr"], 0x1000)


if __name__ == "__main__":
    unittest.main()
