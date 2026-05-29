import unittest

from pydbg.hook.iat import IATHook
from pydbg.hook.inline import InlineHook, Trampoline


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


if __name__ == '__main__':
    unittest.main()
