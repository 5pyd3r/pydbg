"""Live-process + mock tests for SymbolResolver coverage and error wrapping."""

import unittest

try:
    from pydbg import _pydbg  # noqa: F401

    _has_cython = True
except ImportError:
    _has_cython = False


class TestSymbolResolverCoverage(unittest.TestCase):
    """Live happy paths + best-effort dbghelp calls."""

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def setUp(self):
        from tests.helpers import create_debugger
        self.dbg, self.pid, self.tid = create_debugger()

    def tearDown(self):
        # Always release dbghelp state before the process handle is closed.
        # dbghelp keys symbol state by the handle VALUE; if we initialize a
        # process and skip SymCleanup, a later test whose process reuses the
        # same handle value gets SymInitializeW ERROR_INVALID_PARAMETER (87).
        try:
            self.dbg.symbol_cleanup()
        except Exception:
            pass
        from tests.helpers import teardown
        teardown(self.dbg)

    def test_initialize_cleanup_live(self):
        self.dbg.symbol_initialize()
        self.assertTrue(self.dbg.symbols._initialized)
        self.dbg.symbol_cleanup()
        self.assertFalse(self.dbg.symbols._initialized)

    def test_cleanup_twice_noop(self):
        self.dbg.symbol_initialize()
        self.dbg.symbol_cleanup()
        self.dbg.symbol_cleanup()  # second cleanup must be a no-op
        self.assertFalse(self.dbg.symbols._initialized)

    def test_set_options_live(self):
        self.dbg.symbol_initialize()
        self.dbg.symbols.set_options(0x2)  # SYMOPT_UNDNAME
        self.dbg.symbol_cleanup()

    def test_from_name_best_effort(self):
        from pydbg.exceptions import PydbgError
        self.dbg.symbol_initialize()
        try:
            info = self.dbg.symbol_from_name("ntdll.dll!NtCurrentTeb")
        except PydbgError:
            self.skipTest("dbghelp could not resolve export (env-dependent)")
        else:
            self.assertIsInstance(info, dict)
            self.assertIn("address", info)

    def test_from_addr_best_effort(self):
        from pydbg.exceptions import PydbgError
        from tests.helpers import module_base
        self.dbg.symbol_initialize()
        try:
            info = self.dbg.symbol_from_addr(module_base(self.dbg))
        except PydbgError:
            self.skipTest("dbghelp could not resolve address (env-dependent)")
        else:
            self.assertIsInstance(info, dict)
            self.assertIn("name", info)


class TestSymbolResolverErrorWrapping(unittest.TestCase):
    """Mock-based: raw OSError from _pydbg must wrap into PydbgError."""

    def _resolver(self):
        from pydbg.core.session import DebugSession
        from pydbg.symbol.resolver import SymbolResolver
        session = DebugSession()
        session.process_handle = 0x1234
        return SymbolResolver(session)

    def test_initialize_oserror_wrapped(self):
        from unittest import mock
        from pydbg.exceptions import PydbgError
        sr = self._resolver()
        with mock.patch("pydbg._pydbg.sym_initialize",
                        side_effect=OSError(5, "mock")):
            with self.assertRaises(PydbgError):
                sr.initialize()

    def test_cleanup_oserror_wrapped(self):
        from unittest import mock
        from pydbg.exceptions import PydbgError
        sr = self._resolver()
        sr._initialized = True
        with mock.patch("pydbg._pydbg.sym_cleanup",
                        side_effect=OSError(5, "mock")):
            with self.assertRaises(PydbgError):
                sr.cleanup()

    def test_from_name_oserror_wrapped(self):
        from unittest import mock
        from pydbg.exceptions import PydbgError
        sr = self._resolver()
        sr._initialized = True
        with mock.patch("pydbg._pydbg.sym_from_name",
                        side_effect=OSError(5, "mock")):
            with self.assertRaises(PydbgError):
                sr.from_name("foo")

    def test_from_addr_oserror_wrapped(self):
        from unittest import mock
        from pydbg.exceptions import PydbgError
        sr = self._resolver()
        sr._initialized = True
        with mock.patch("pydbg._pydbg.sym_from_addr",
                        side_effect=OSError(5, "mock")):
            with self.assertRaises(PydbgError):
                sr.from_addr(0x1000)

    def test_load_module_oserror_wrapped(self):
        from unittest import mock
        from pydbg.exceptions import PydbgError
        sr = self._resolver()
        sr._initialized = True
        with mock.patch("pydbg._pydbg.sym_load_module_ex",
                        side_effect=OSError(5, "mock")):
            with self.assertRaises(PydbgError):
                sr.load_module("test.dll", 0x10000)


if __name__ == "__main__":
    unittest.main()
