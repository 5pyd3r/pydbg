import unittest

from pydbg.hook.iat import IATHook
from pydbg.hook.inline import InlineHook, Trampoline

try:
    from pydbg import _pydbg  # noqa: F401

    _has_cython = True
except ImportError:
    _has_cython = False


class TestTrampoline(unittest.TestCase):

    def test_dataclass_fields(self):
        t = Trampoline(addr=0x1000, size=10, original_code=b'\x90\x90')
        self.assertEqual(t.addr, 0x1000)
        self.assertEqual(t.size, 10)
        self.assertEqual(t.original_code, b'\x90\x90')

    def test_dataclass_equality(self):
        t1 = Trampoline(addr=0x1000, size=5, original_code=b'\xc3')
        t2 = Trampoline(addr=0x1000, size=5, original_code=b'\xc3')
        self.assertEqual(t1, t2)


class TestIATHook(unittest.TestCase):

    def test_init_empty_hooks(self):
        from pydbg.core.session import DebugSession
        session = DebugSession()
        hook = IATHook(session)
        self.assertEqual(hook.list_hooks(), {})

    def test_list_hooks_tracks_entries(self):
        from pydbg.core.session import DebugSession
        session = DebugSession()
        hook = IATHook(session)
        hook._hooks[('kernel32.dll', 'CreateFileW')] = (0x1000, 0x7ffe0000)
        hooks = hook.list_hooks()
        self.assertIn(('kernel32.dll', 'CreateFileW'), hooks)

    def test_find_module_case_insensitive(self):
        from pydbg.core.session import DebugSession
        session = DebugSession()
        hook = IATHook(session)
        modules = [{'name': 'KERNEL32.DLL', 'base_address': 0x7ffe0000}]
        result = hook._find_module(
            type('MockModules', (), {'enumerate': lambda self: modules})(),
            'kernel32.dll'
        )
        self.assertIsNotNone(result)

    def test_find_module_not_found(self):
        from pydbg.core.session import DebugSession
        session = DebugSession()
        hook = IATHook(session)
        modules = [{'name': 'ntdll.dll', 'base_address': 0x7ffe0000}]
        result = hook._find_module(
            type('MockModules', (), {'enumerate': lambda self: modules})(),
            'kernel32.dll'
        )
        self.assertIsNone(result)


class TestIATFindAddr(unittest.TestCase):
    """Test _find_iat_addr with synthetic PE data."""

    def _build_pe_with_imports(self):
        """A PE32+ image in *loaded* layout, with one import.

        Loaded layout (pointer_to_raw_data == RVA) is what a debugger reads
        from a live process, and it is what LoadedView expects. The previous
        fixture was a file image, so the old 64 KiB slurp happened to work
        only because it was parsed as a file — nothing about a live module.
        """
        from tests.pe_builder import build_loaded_image_with_one_import

        data, _ = build_loaded_image_with_one_import()
        return data

    def test_find_existing_import(self):
        """_find_iat_addr returns IAT RVA for known import."""
        from pydbg.core.session import DebugSession
        session = DebugSession()
        hook = IATHook(session)
        pe_data = self._build_pe_with_imports()

        # Mock memory that returns full PE data (simulates mapped image)
        class MockMemory:
            def read(self, addr, size):
                offset = addr - 0x140000000
                return pe_data[offset:offset + size]

        mod = {'base_address': 0x140000000, 'name': 'test.exe'}
        result = hook._find_iat_addr(mod, 'MessageBoxA', MockMemory())
        self.assertEqual(result, 0x2400)  # IAT RVA

    def test_find_case_insensitive(self):
        """_find_iat_addr is case-insensitive."""
        from pydbg.core.session import DebugSession
        session = DebugSession()
        hook = IATHook(session)
        pe_data = self._build_pe_with_imports()

        class MockMemory:
            def read(self, addr, size):
                offset = addr - 0x140000000
                return pe_data[offset:offset + size]

        mod = {'base_address': 0x140000000, 'name': 'test.exe'}
        result = hook._find_iat_addr(mod, 'messageboxa', MockMemory())
        self.assertEqual(result, 0x2400)

    def test_find_nonexistent_import(self):
        """_find_iat_addr returns None for unknown function."""
        from pydbg.core.session import DebugSession
        session = DebugSession()
        hook = IATHook(session)
        pe_data = self._build_pe_with_imports()

        class MockMemory:
            def read(self, addr, size):
                offset = addr - 0x140000000
                return pe_data[offset:offset + size]

        mod = {'base_address': 0x140000000, 'name': 'test.exe'}
        result = hook._find_iat_addr(mod, 'NonExistentFunc', MockMemory())
        self.assertIsNone(result)

    def test_find_zero_base(self):
        """_find_iat_addr returns None when base_address is 0."""
        from pydbg.core.session import DebugSession
        hook = IATHook(DebugSession())

        class MockMemory:
            def read(self, addr, size):
                return b'\x00' * size

        mod = {'base_address': 0, 'name': 'test.exe'}
        result = hook._find_iat_addr(mod, 'MessageBoxA', MockMemory())
        self.assertIsNone(result)


class TestInlineHook(unittest.TestCase):

    def test_init(self):
        from pydbg.core.session import DebugSession
        session = DebugSession()
        hook = InlineHook(session)
        self.assertIsNotNone(hook)
        self.assertEqual(hook._hooks, {})

    def test_trampoline_stored_on_set(self):
        from pydbg.core.session import DebugSession
        session = DebugSession()
        hook = InlineHook(session)
        t = Trampoline(addr=0x2000, size=10, original_code=b'\x55\x48\x89\xE5')
        hook._hooks[0x1000] = t
        self.assertIn(0x1000, hook._hooks)
        self.assertEqual(hook._hooks[0x1000].original_code, b'\x55\x48\x89\xE5')


class TestInlineHookLive(unittest.TestCase):
    """Live inline hook on a safe allocated stub (never executed)."""

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_set_and_restore_live(self):
        from pydbg.hook.inline import Trampoline
        from pydbg.exceptions import PydbgError
        from tests.helpers import create_debugger, teardown, alloc_writable

        dbg, pid, tid = create_debugger()
        try:
            target = alloc_writable(dbg, 0x40)
            stub = alloc_writable(dbg, 0x10)
            self.assertNotEqual(target, 0)
            self.assertNotEqual(stub, 0)
            dbg.write_memory(target, b"\x90" * 0x40)  # nops
            dbg.write_memory(stub, b"\xc3" * 0x10)    # rets (never executed)

            try:
                tramp = dbg.hook_inline.set(target, stub)
            except PydbgError as exc:
                # Relocation-range failure if VirtualAllocEx placed regions
                # >2GB apart (JMP rel32). This is environment-dependent.
                self.skipTest(f"inline hook relocation failed: {exc}")

            self.assertIsInstance(tramp, Trampoline)
            self.assertNotEqual(tramp.addr, 0)
            self.assertEqual(tramp.original_code, b"\x90" * 5)
            # target first byte is now a relative JMP (0xE9)
            self.assertEqual(dbg.read_memory(target, 1), b"\xe9")

            dbg.hook_inline.restore(tramp)
            self.assertEqual(dbg.read_memory(target, 5), b"\x90" * 5)
            self.assertEqual(dbg.hook_inline._hooks, {})
        finally:
            teardown(dbg)

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_set_close_range_hook(self):
        from tests.helpers import create_debugger, teardown, alloc_writable

        dbg, pid, tid = create_debugger()
        try:
            region = alloc_writable(dbg, 0x1000)
            self.assertNotEqual(region, 0)
            target = region + 0x10
            stub = region + 0x30  # 0x20 apart -> within rel8 (128-byte) range
            dbg.write_memory(target, b"\x90" * 0x40)
            dbg.write_memory(stub, b"\xc3" * 0x10)
            tramp = dbg.hook_inline.set(target, stub)
            self.assertEqual(dbg.read_memory(target, 1), b"\xe9")
            dbg.hook_inline.restore(tramp)
            self.assertEqual(dbg.read_memory(target, 5), b"\x90" * 5)
        finally:
            teardown(dbg)


class TestInlineHookErrors(unittest.TestCase):
    """Deterministic error paths for InlineHook.set/restore."""

    def test_set_short_code_raises(self):
        from unittest import mock
        from pydbg.core.session import DebugSession
        from pydbg.hook.inline import InlineHook
        from pydbg.exceptions import PydbgError

        hook = InlineHook(DebugSession())
        with mock.patch.object(hook, "_read_min_5_bytes", return_value=b"\x90\x90"):
            with mock.patch.object(hook, "_alloc", return_value=0x1000):
                with self.assertRaises(PydbgError):
                    hook.set(0x400000, 0x500000)

    def test_set_alloc_failure_raises(self):
        from unittest import mock
        from pydbg.core.session import DebugSession
        from pydbg.hook.inline import InlineHook
        from pydbg.exceptions import PydbgError

        hook = InlineHook(DebugSession())
        with mock.patch.object(hook, "_read_min_5_bytes",
                               return_value=b"\x90" * 8):
            with mock.patch.object(hook, "_alloc", return_value=0):
                with self.assertRaises(PydbgError):
                    hook.set(0x400000, 0x500000)

    def test_restore_unknown_trampoline_raises(self):
        """Silently returning left the E9 detour in place.

        The caller believed the target had its original bytes back; it did
        not. Refusing is the only honest answer.
        """
        from pydbg.core.session import DebugSession
        from pydbg.exceptions import PydbgError

        hook = InlineHook(DebugSession())
        tramp = Trampoline(addr=0x2000, size=10, original_code=b"\x90" * 5)
        with self.assertRaises(PydbgError):
            hook.restore(tramp)
        self.assertEqual(hook._hooks, {})


if __name__ == '__main__':
    unittest.main()
