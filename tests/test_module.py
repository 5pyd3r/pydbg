"""Live-process tests for ModuleResolver coverage."""

import os
import struct
import subprocess
import sys
import unittest

try:
    from pydbg import _pydbg  # noqa: F401

    _has_cython = True
except ImportError:
    _has_cython = False

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))

# Same path tests/meson.build defines as target32_dir: `meson test` sets
# TEST_WOW64_TARGET_PATH, plain pytest falls back to the out-of-band target.
TEST_WOW64_TARGET = os.environ.get(
    "TEST_WOW64_TARGET_PATH",
    os.path.join(_TEST_DIR, "target", "simple_target32.exe"),
)
_HAS_WOW64_TARGET = os.path.exists(TEST_WOW64_TARGET)


def _wow64_available():
    """True only on a 64-bit Windows host (WOW64 debugging needs one)."""
    return struct.calcsize("P") == 8 and sys.platform == "win32"


# The filter/refusal path must not need the compiled extension. This script is
# run in a subprocess because resolver.py binds `_pydbg` at import time; a
# stub installed in-process (the way tests/test_import_boundary.py blocks the
# extension) would replace the real one for the rest of the suite.
_VIEW_CHECK_WITHOUT_EXTENSION = '''
import sys
import types

import pydbg

calls = []


class FakeExtension(types.ModuleType):
    """Stand-in for _pydbg: records which table each view asks for."""

    def enum_process_modules(self, h_process):
        calls.append(("all", h_process, None))
        return []

    def enum_process_modules_ex(self, h_process, filter_flag):
        calls.append(("filtered", h_process, filter_flag))
        return []


fake = FakeExtension("pydbg._pydbg")
sys.modules["pydbg._pydbg"] = fake
pydbg._pydbg = fake

from pydbg.constants import LIST_MODULES_32BIT, LIST_MODULES_64BIT
from pydbg.exceptions import PydbgError
from pydbg.module.resolver import ModuleResolver


class FakeSession:
    process_handle = 0x1234
    pid = 42

    def __init__(self, arch):
        self.pid_arch = {42: arch}

    def arch_for_pid(self, pid):
        target = self.pid if pid is None else pid
        return self.pid_arch.get(target, self.pid_arch[self.pid])

    def modules_for(self, pid):
        return []


resolver = ModuleResolver(FakeSession(32))

# The historical answer still goes through enum_process_modules().
assert resolver.enumerate() == []
assert calls[-1][0] == "all", calls

# 32-bit view: the 32BIT filter, chosen because the TARGET is 32-bit.
assert resolver.enumerate(arch="32") == []
assert calls[-1] == ("filtered", 0x1234, LIST_MODULES_32BIT), calls

# A 32-bit target has no 64-bit table: refused before the Win32 call.
before = len(calls)
for bad in ("64", 64, "x64"):
    try:
        resolver.enumerate(arch=bad)
    except PydbgError as exc:
        assert "64-bit module view" in str(exc), exc
        assert "32-bit target" in str(exc), exc
    else:
        raise AssertionError("64-bit view accepted on a 32-bit target")
assert len(calls) == before, calls

# ...and a native 64-bit target refuses the 32-bit view the same way.
resolver = ModuleResolver(FakeSession(64))
before = len(calls)
try:
    resolver.enumerate(arch="32")
except PydbgError as exc:
    assert "32-bit module view" in str(exc), exc
    assert "64-bit target" in str(exc), exc
else:
    raise AssertionError("32-bit view accepted on a 64-bit target")
assert len(calls) == before, calls

assert resolver.enumerate(arch="64") == []
assert calls[-1] == ("filtered", 0x1234, LIST_MODULES_64BIT), calls

# A spelling that names no table is a PydbgError like every other refusal, and
# costs no Win32 call.
before = len(calls)
try:
    resolver.enumerate(arch="arm")
except PydbgError as exc:
    assert "must be None, 32 or 64" in str(exc), exc
else:
    raise AssertionError("an unknown module-view architecture was accepted")
assert len(calls) == before, calls

print("32-bit module view plumbing works without the extension")
'''


class TestModuleViewWithoutExtension(unittest.TestCase):
    """The view selection and its refusal path need no compiled extension."""

    def test_view_selection_and_refusal_need_no_extension(self):
        done = subprocess.run(
            [sys.executable, "-c", _VIEW_CHECK_WITHOUT_EXTENSION],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("without the extension", done.stdout)


class TestModuleViewArchitecture(unittest.TestCase):
    """Which Win32 call an arch-filtered view makes (real extension present)."""

    @unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
    def setUp(self):
        from pydbg.core.session import DebugSession
        from pydbg.module.resolver import ModuleResolver

        self.session = DebugSession()
        self.session.pid = 4321
        self.session.register_pid_arch(4321, 32)
        self.resolver = ModuleResolver(self.session)

    def test_32bit_view_uses_the_32bit_filter(self):
        from unittest import mock

        from pydbg.constants import LIST_MODULES_32BIT

        with mock.patch("pydbg.module.resolver._pydbg.enum_process_modules_ex",
                        return_value=[{"handle": 0x1000,
                                       "base_address": 0x1000}]) as called:
            with mock.patch("pydbg.module.resolver._pydbg.get_module_file_name_ex",
                            return_value="C:\\Windows\\SysWOW64\\kernel32.dll"):
                modules = self.resolver.enumerate(arch="32")

        called.assert_called_once_with(
            self.session.process_handle, LIST_MODULES_32BIT)
        self.assertEqual(modules[0]["name"],
                         "C:\\Windows\\SysWOW64\\kernel32.dll")

    def test_64bit_view_on_a_32bit_target_never_reaches_win32(self):
        from unittest import mock

        from pydbg.exceptions import PydbgError

        with mock.patch(
                "pydbg.module.resolver._pydbg.enum_process_modules_ex") as called:
            with self.assertRaises(PydbgError):
                self.resolver.enumerate(arch="64")
        called.assert_not_called()

    def test_default_view_still_uses_the_unfiltered_call(self):
        from unittest import mock

        with mock.patch("pydbg.module.resolver._pydbg.enum_process_modules",
                        return_value=[]) as unfiltered:
            with mock.patch(
                    "pydbg.module.resolver._pydbg.enum_process_modules_ex") as filtered:
                self.resolver.enumerate()
        unfiltered.assert_called_once_with(self.session.process_handle)
        filtered.assert_not_called()


class TestModuleResolverCoverage(unittest.TestCase):

    @unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
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


class TestWow64ModuleView(unittest.TestCase):
    """The 32-bit module table on a real WOW64 target.

    Skips name their family: 'environment:' on a 32-bit host, and
    'target not built:' when simple_target32.exe is absent (the conftest rule).
    """

    @unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
    def setUp(self):
        if not _wow64_available():
            self.skipTest("environment: 64-bit Windows host")
        if not _HAS_WOW64_TARGET:
            self.skipTest(
                "target not built: tests/target/simple_target32.exe "
                "(scripts/build-target32.ps1)")

    def test_the_32bit_table_appears_once_the_image_is_mapped(self):
        from pydbg import Debugger
        from pydbg.exceptions import MemError, PydbgError
        from tests.helpers import teardown

        basename = os.path.basename(TEST_WOW64_TARGET).lower()
        dbg = Debugger()
        try:
            dbg.create_process(TEST_WOW64_TARGET)
            modules = []
            for _ in range(100):
                event = dbg.wait_event(2000)
                if event is None or event.type == "EXIT_PROCESS":
                    break
                dbg.continue_event(event.pid, event.tid)
                try:
                    modules = dbg.enum_modules(arch="32")
                except MemError:
                    # ERROR_PARTIAL_COPY: the 32-bit image is not mapped yet,
                    # which is the boundary the resolver docstring documents.
                    continue
                if any(
                    m["name"].split("\\")[-1].lower() == basename
                    for m in modules
                ):
                    break

            exe = next(
                (m for m in modules
                 if m["name"].split("\\")[-1].lower() == basename), None)
            self.assertIsNotNone(
                exe, "32-bit exe never appeared in the 32-bit module view")
            self.assertEqual(exe["arch"], "x86")
            self.assertTrue(all(m["arch"] == "x86" for m in modules),
                            "a non-x86 module leaked into the 32-bit view")

            # The positive half above proves the table was selected by the
            # target (32), not this x64 host; this proves the reverse too.
            with self.assertRaises(PydbgError):
                dbg.enum_modules(arch="64")
        finally:
            teardown(dbg)


if __name__ == "__main__":
    unittest.main()
