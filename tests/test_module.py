"""Live-process tests for ModuleResolver coverage."""

import unittest

try:
    from pydbg import _pydbg  # noqa: F401

    _has_cython = True
except ImportError:
    _has_cython = False


class TestModuleResolverCoverage(unittest.TestCase):

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def setUp(self):
        from tests.helpers import create_debugger
        self.dbg, self.pid, self.tid = create_debugger()

    def tearDown(self):
        from tests.helpers import teardown
        teardown(self.dbg)

    def test_find_module_by_basename(self):
        mod = self.dbg.find_module("simple_target.exe")
        self.assertIsNotNone(mod)
        self.assertIn("base_address", mod)
        self.assertIn("handle", mod)

    def test_find_module_case_insensitive(self):
        mod = self.dbg.find_module("SIMPLE_TARGET.EXE")
        self.assertIsNotNone(mod)

    def test_find_module_missing_returns_none(self):
        self.assertIsNone(self.dbg.find_module("nonexistent_module_xyz.dll"))

    def test_get_filename_invalid_handle_raises(self):
        # Note: hModule=0 is a *legal* value for GetModuleFileNameExA (it means
        # "the process's main executable"), so it would not raise. A non-NULL
        # handle that is not a loaded module base is what actually fails.
        from pydbg.exceptions import MemError
        with self.assertRaises(MemError):
            self.dbg.modules.get_filename(0x12345678)

    def test_enumerate_handle_invalid_raises(self):
        from pydbg.exceptions import MemError
        with self.assertRaises(MemError):
            self.dbg.modules.enumerate_handle(0)

    def test_enumerate_handle_with_names(self):
        h = self.dbg._session.process_handle
        modules = self.dbg.modules.enumerate_handle(h)
        self.assertGreater(len(modules), 0)
        self.assertTrue(all("name" in m for m in modules))
        self.assertTrue(modules[0]["name"].lower().endswith(".exe"))

    def test_name_resolve_failure_yields_empty_string(self):
        """GetModuleFileNameExA failure should yield '' per module (not crash)."""
        from unittest import mock
        from pydbg.core.session import DebugSession
        from pydbg.module.resolver import ModuleResolver

        session = DebugSession()
        resolver = ModuleResolver(session)
        with mock.patch("pydbg.module.resolver._pydbg.enum_process_modules",
                        return_value=[{"handle": 0x111, "base_address": 0x1000}]):
            with mock.patch("pydbg.module.resolver._pydbg.get_module_file_name_ex",
                            side_effect=OSError(5, "mock")):
                modules = resolver.enumerate()
        self.assertEqual(modules[0]["name"], "")


if __name__ == "__main__":
    unittest.main()
