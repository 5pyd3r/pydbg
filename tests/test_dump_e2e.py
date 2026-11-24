"""End to end: a live DLL, dumped and rebuilt, becomes a file Windows loads.

The other dump tests check one half each — `dump_module` on live bytes,
`rebuild_pe` on a synthetic image, the loader on a synthetic file. This test
joins them with the one sample that removes every "the fixture was designed
for the writer" caveat: the DLL built by meson from `tests/target/dump_target.c`
and loaded by `tests/target/dump_host.c`. Its export and its import of a real
Win32 function are what the rebuilt header, export directory and import table
have to keep, and `LoadLibraryExW` is the second oracle: a file `PE(data)`
parses can still be one Windows refuses.

The copy is written under a random name because a file called
`dump_target.dll` would collide with the module the host still has mapped — the
loader could find that one and never touch the rebuilt bytes.

Every skip names its family, so a missing target does not silently look green.
"""

import ctypes
import os
import shutil
import tempfile
import time
import unittest
import uuid

from pydbg.dump import dump_module, rebuild_pe
from pydbg.exceptions import PydbgError
from pydbg.pe import PE

try:
    from pydbg import _pydbg  # noqa: F401

    _has_cython = True
except ImportError:
    _has_cython = False

_DLL_ENV = 'TEST_DUMP_DLL_PATH'
_HOST_ENV = 'TEST_DUMP_HOST_PATH'
_DLL_BASENAME = 'dump_target.dll'
_EXPORT_NAME = 'dump_target_answer'
_IMPORT_DLL = 'kernel32.dll'
_IMPORT_NAME = 'GetTickCount'
_BUILD_COMMAND = 'meson compile -C build dump_target dump_host'

# LoadLibraryExW flag: map the image but do not load dependencies, resolve
# imports, or run DllMain. That is exactly the claim the rebuild makes — the
# file layout is loadable — and not the one it explicitly declines (relocation
# rewriting for a module loaded away from its preferred base, spec §11.7).
_DONT_RESOLVE_DLL_REFERENCES = 0x1
# GetExitCodeProcess's pseudo-code for a process that has not exited.
_STILL_ACTIVE = 259
_LOAD_TIMEOUT = 30.0
_POLL_MS = 100


def _require_paths(test):
    """Return (dll, host), or skip naming the meson command that builds them."""
    paths = {}
    for env in (_DLL_ENV, _HOST_ENV):
        value = os.environ.get(env)
        if not value:
            test.skipTest(
                f"target not built: {env} unset; run: {_BUILD_COMMAND}")
        paths[env] = value
    for env in (_DLL_ENV, _HOST_ENV):
        if not os.path.isfile(paths[env]):
            test.skipTest(
                f"target not built: {paths[env]} missing (from {env}); "
                f"run: {_BUILD_COMMAND}")
    return paths[_DLL_ENV], paths[_HOST_ENV]


def _basename(name):
    """The file name of a module path, lower-cased for comparison."""
    return (name or '').replace('/', '\\').rsplit('\\', 1)[-1].lower()


def _find_module(dbg, basename):
    """The enum_modules() entry for 'basename', or None."""
    for module in dbg.enum_modules():
        if _basename(module.get('name')) == basename.lower():
            return module
    return None


def _wait_for_module(test, dbg, pid, tid):
    """Release the loader breakpoint and run until dump_target.dll is mapped.

    Module enumeration can fail while the loader is still working
    (ERROR_PARTIAL_COPY), which is transient: keep consuming debug events and
    retry. Every event has to be continued, or the debuggee stays frozen on it
    and the DLL never finishes loading.
    """
    # create_debugger leaves the initial breakpoint delivered but uncontinued.
    dbg.continue_event(pid, tid)
    deadline = time.monotonic() + _LOAD_TIMEOUT
    while time.monotonic() < deadline:
        try:
            module = _find_module(dbg, _DLL_BASENAME)
        except PydbgError:
            module = None
        if module is not None:
            return module
        event = dbg.wait_event(_POLL_MS)
        if event is not None:
            if event.type == 'EXIT_PROCESS':
                test.fail(
                    f"{_HOST_ENV} exited before loading {_DLL_BASENAME} "
                    f"(exit code {event.raw.get('exit_code')})")
            dbg.continue_event(event.pid, event.tid)
        elif dbg.get_exit_code() != _STILL_ACTIVE:
            test.fail(
                f"{_HOST_ENV} exited with {dbg.get_exit_code()} before "
                f"loading {_DLL_BASENAME}")
    test.fail(
        f"{_DLL_BASENAME} did not appear in enum_modules() within "
        f"{_LOAD_TIMEOUT:.0f} s; is it next to the host exe?")


def _load_without_resolving(path):
    """Map 'path' with the Windows loader; returns the HMODULE or 0."""
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    load = kernel32.LoadLibraryExW
    load.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint32]
    load.restype = ctypes.c_void_p
    return load(path, None, _DONT_RESOLVE_DLL_REFERENCES)


def _free(handle):
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    free = kernel32.FreeLibrary
    free.argtypes = [ctypes.c_void_p]
    free.restype = ctypes.c_int
    free(handle)


def _export_from_loaded_module(handle, name):
    """Address of 'name' in the mapped image, or 0; no imports are resolved."""
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    get = kernel32.GetProcAddress
    get.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    get.restype = ctypes.c_void_p
    return get(handle, name.encode('ascii'))


class TestDumpEndToEnd(unittest.TestCase):
    """The acceptance the synthetic fixtures cannot make."""

    @unittest.skipUnless(_has_cython, 'optional dependency: Cython extension')
    def test_a_dumped_dll_rebuilds_into_a_file_the_loader_accepts(self):
        dll_path, host_path = _require_paths(self)
        from tests.helpers import create_debugger, teardown

        # The on-disk DLL is the independent source of truth for the image:
        # every expected section, entry point and export comes from it, never
        # from the writer that produced the bytes under test.
        source = PE.from_file(dll_path)
        dbg, pid, tid = create_debugger(host_path)
        directory = tempfile.mkdtemp(prefix='pydbg-dump-e2e-')
        try:
            module = _wait_for_module(self, dbg, pid, tid)

            dumped = dump_module(dbg, module)
            rebuilt = rebuild_pe(dumped)
            parsed = PE(rebuilt.data)

            self.assertEqual([s.name for s in parsed.sections],
                             [s.name for s in source.sections])
            self.assertEqual([s.characteristics for s in parsed.sections],
                             [s.characteristics for s in source.sections])
            self.assertEqual(parsed.optional_header.entry_point_rva,
                             source.optional_header.entry_point_rva)
            self.assertEqual(dumped.entry_point_rva,
                             source.optional_header.entry_point_rva)
            self.assertEqual(rebuilt.report.entry_point,
                             source.optional_header.entry_point_rva)
            self.assertIn(_EXPORT_NAME,
                          [entry.name for entry in parsed.exports])
            imports = [(imp.dll_name.lower(), imp.name)
                       for imp in parsed.imports]
            self.assertIn(
                (_IMPORT_DLL, _IMPORT_NAME), imports,
                f"rebuilt import table lost {_IMPORT_DLL}!{_IMPORT_NAME}")

            # A random name keeps the loader away from the still-mapped module
            # and from the original file: the bytes under test are the only
            # candidate.
            copy_path = os.path.join(
                directory, f'dump_target_{uuid.uuid4().hex}.dll')
            with open(copy_path, 'wb') as handle:
                handle.write(rebuilt.data)

            module_handle = _load_without_resolving(copy_path)
            self.assertTrue(
                module_handle,
                f"LoadLibraryExW(DONT_RESOLVE_DLL_REFERENCES) rejected "
                f"{copy_path}: win32 error {ctypes.get_last_error()}")
            try:
                self.assertTrue(
                    _export_from_loaded_module(module_handle, _EXPORT_NAME),
                    f"the loader mapped {copy_path} but its export "
                    f"{_EXPORT_NAME} is not reachable")
            finally:
                _free(module_handle)
        finally:
            # The host sleeps forever; killing it is how the dump stops holding
            # the module. teardown also copes with a launch that failed.
            teardown(dbg)
            shutil.rmtree(directory, ignore_errors=True)
