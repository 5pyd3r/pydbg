"""Injection primitives acceptance (spec §13.2, ticket P38/D9).

What this file proves, in the order the ticket lists it:

1. `inject_dll` maps `dump_target.dll` into `dump_host.exe`'s module list and
   the target's own export directory answers `dump_target_answer` — checked by
   walking the *target's* PE headers, not by loading the DLL here;
2. `inject_shellcode` runs `xor eax,eax; ret` to a zero thread exit code and
   the target keeps running;
3. `queue_apc` executes on a thread parked in an alertable wait;
4. `suspend_process`/`resume_process` count every thread and leave the target
   alive;
5. invalid path / empty code / invalid thread each raise `InjectionError`
   naming the stage and the Win32 code;
6. the extension is not needed to import `pydbg` or `pydbg.inject`, and the
   live checks declare `optional dependency: Cython extension` /
   `target not built:` when their preconditions are missing.

The live targets are started as ordinary (non-debugged) processes and opened
with `_pydbg.open_process`: injection is a library operation on any process,
not only a debuggee, and avoiding debug events keeps the checks focused on the
primitives rather than on the debug loop. `dbg` is a real `Debugger` whose
session is pointed at that handle, which is the same surface a debuggee gives
the API.
"""

import os
import struct
import subprocess
import sys
import time
import unittest

from pydbg import PydbgError
from pydbg.inject import InjectionError, InjectionReport

try:
    from pydbg import _pydbg
    from pydbg.inject import (
        inject_dll,
        inject_shellcode,
        queue_apc,
        resume_process,
        suspend_process,
    )

    _has_cython = True
except ImportError:                     # pragma: no cover - environment
    _has_cython = False

_HERE = os.path.dirname(os.path.abspath(__file__))
# meson's test_env already exports TEST_INSTRUMENT_TARGET_PATH; accepting it
# here means a CI run exercises the primitives without a second knob.
_TARGET = os.environ.get(
    "TEST_INJECT_TARGET_PATH",
    os.environ.get(
        "TEST_INSTRUMENT_TARGET_PATH",
        os.path.join(_HERE, "target", "instrument_target.exe")))
_DUMP_DLL = os.environ.get(
    "TEST_DUMP_DLL_PATH", os.path.join(_HERE, "target", "dump_target.dll"))
_DUMP_HOST = os.environ.get(
    "TEST_DUMP_HOST_PATH", os.path.join(_HERE, "target", "dump_host.exe"))

needs_cython = unittest.skipUnless(
    _has_cython, "optional dependency: Cython extension")
needs_target = unittest.skipUnless(
    os.path.isfile(_TARGET), "target not built: " + _TARGET)
needs_dump_targets = unittest.skipUnless(
    os.path.isfile(_DUMP_DLL) and os.path.isfile(_DUMP_HOST),
    "target not built: " + _DUMP_DLL + " and " + _DUMP_HOST)

# GetExitCodeProcess answers this while the process is still running.
_STILL_ACTIVE = 259


class TestInjectionTypes(unittest.TestCase):
    """The extension-free half: types, error hierarchy, and the ADR-0001 seam."""

    def test_report_carries_thread_handle_and_remote_base(self):
        report = InjectionReport(thread_id=7, handle=0x88, remote_base=0x9000)
        self.assertEqual(
            (report.thread_id, report.handle, report.remote_base),
            (7, 0x88, 0x9000))

    def test_error_is_a_pydbg_error(self):
        self.assertTrue(issubclass(InjectionError, PydbgError))
        with self.assertRaises(PydbgError):
            raise InjectionError("injection alloc failed (win32=5)")

    def test_importing_the_package_does_not_load_the_extension(self):
        """`import pydbg` and `import pydbg.inject` stay extension-free."""
        code = (
            "import sys\n"
            "import pydbg\n"
            "import pydbg.inject\n"
            "assert '_pydbg' not in sys.modules, sorted(sys.modules)\n"
            "assert pydbg.inject.InjectionReport is not None\n"
            "assert pydbg.inject.InjectionError is not None\n"
            "assert 'inject_dll' in dir(pydbg.inject)\n"
            "print('ok')\n")
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ok", result.stdout)


@needs_cython
class TestInjectionValidation(unittest.TestCase):
    """Every invalid input is an InjectionError naming stage + Win32 code."""

    def _message(self, fn, *args, **kwargs):
        with self.assertRaises(InjectionError) as ctx:
            fn(*args, **kwargs)
        return str(ctx.exception)

    def test_empty_shellcode_names_the_code_stage_and_invalid_parameter(self):
        message = self._message(inject_shellcode, None, b"")
        self.assertIn("code", message)
        self.assertIn("87", message)

    def test_non_bytes_shellcode_is_refused(self):
        message = self._message(inject_shellcode, None, "not bytes")
        self.assertIn("code", message)
        self.assertIn("87", message)

    def test_missing_dll_path_names_the_path_stage_and_file_not_found(self):
        missing = os.path.join(_HERE, "target", "no-such-dll-38.dll")
        message = self._message(inject_dll, None, missing)
        self.assertIn("path", message)
        self.assertIn("2", message)

    def test_empty_dll_path_is_refused(self):
        message = self._message(inject_dll, None, "")
        self.assertIn("path", message)
        self.assertIn("87", message)

    def test_zero_thread_id_is_refused_before_any_syscall(self):
        message = self._message(queue_apc, None, 0, 0x1000)
        self.assertIn("apc", message)
        self.assertIn("87", message)

    def test_zero_apc_address_is_refused(self):
        message = self._message(queue_apc, None, 1234, 0)
        self.assertIn("apc", message)
        self.assertIn("87", message)

    def test_suspend_process_without_a_target_is_refused(self):
        message = self._message(suspend_process, None)
        self.assertIn("target", message)

    def test_queue_apc_docstring_requires_an_alertable_wait(self):
        self.assertIn("alertable", queue_apc.__doc__.lower())


def _remote_export(h_process, module_base, name):
    """Resolve 'name' in the target's export directory, the way GetProcAddress does.

    Returns the export's VA, or 0. Reads only target memory, so it proves the
    module the *target* loaded actually carries the export instead of proving
    that this test process can load the same file.
    """
    dos = _pydbg.read_process_memory(h_process, module_base, 0x40)
    if dos[:2] != b"MZ":
        return 0
    e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
    nt = _pydbg.read_process_memory(h_process, module_base + e_lfanew, 0x108)
    if nt[:4] != b"PE\x00\x00":
        return 0
    magic = struct.unpack_from("<H", nt, 0x18)[0]
    dir_off = 0x70 if magic == 0x20B else 0x60      # OptionalHeader.DataDirectory
    export_rva = struct.unpack_from("<I", nt, 0x18 + dir_off)[0]
    if not export_rva:
        return 0
    header = _pydbg.read_process_memory(h_process, module_base + export_rva, 40)
    name_count = struct.unpack_from("<I", header, 24)[0]
    funcs = struct.unpack_from("<I", header, 28)[0]
    names = struct.unpack_from("<I", header, 32)[0]
    ordinals = struct.unpack_from("<I", header, 36)[0]
    for index in range(min(name_count, 4096)):
        name_rva = struct.unpack_from(
            "<I",
            _pydbg.read_process_memory(
                h_process, module_base + names + 4 * index, 4))[0]
        raw = _pydbg.read_process_memory(h_process, module_base + name_rva, 128)
        end = raw.find(b"\x00")
        if end != -1:
            raw = raw[:end]
        if raw == name.encode("ascii", errors="replace"):
            ordinal = struct.unpack_from(
                "<H",
                _pydbg.read_process_memory(
                    h_process, module_base + ordinals + 2 * index, 2))[0]
            func_rva = struct.unpack_from(
                "<I",
                _pydbg.read_process_memory(
                    h_process, module_base + funcs + 4 * ordinal, 4))[0]
            return module_base + func_rva
    return 0


def _module_by_name(modules, basename):
    wanted = basename.lower()
    for module in modules:
        if os.path.basename(module.get("name", "")).lower() == wanted:
            return module
    return None


class _LiveTarget:
    """An ordinary process opened with PROCESS_ALL_ACCESS and a Debugger facade.

    Injection does not need a debugging relationship — only a process handle
    and its pid. Starting the target outside the debug API also means a
    CreateRemoteThread from here is not held at a CREATE_THREAD debug event.
    """

    def __init__(self, path):
        self.process = subprocess.Popen(
            [path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd=os.path.dirname(os.path.abspath(path)))
        self.handle = None
        for _ in range(200):
            try:
                self.handle = _pydbg.open_process(self.process.pid)
                break
            except OSError:
                time.sleep(0.01)
        if self.handle is None:
            self.process.kill()
            raise RuntimeError(f"could not open target {path!r}")

        from pydbg import Debugger

        self.dbg = Debugger()
        session = self.dbg._session
        session.pid = self.process.pid
        session.process_handle = self.handle
        session.target_arch = 64

    def close(self):
        try:
            _pydbg.terminate_process(self.handle, 0)
        except OSError:
            pass
        try:
            _pydbg.close_handle(self.handle)
        except OSError:
            pass
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:       # pragma: no cover - cleanup
            self.process.kill()
            self.process.wait(timeout=5)

    def alive(self):
        return _pydbg.get_exit_code(self.handle) == _STILL_ACTIVE


@needs_cython
@needs_target
class TestShellcodeInjectionLive(unittest.TestCase):

    def setUp(self):
        self.target = _LiveTarget(_TARGET)
        self.addCleanup(self.target.close)

    def test_xor_eax_ret_thread_exits_zero_and_target_survives(self):
        code = b"\x31\xC0\xC3"                  # xor eax,eax; ret
        report = inject_shellcode(self.target.dbg, code)

        self.assertIsInstance(report, InjectionReport)
        self.assertNotEqual(report.thread_id, 0)
        self.assertNotEqual(report.handle, 0)
        self.assertNotEqual(report.remote_base, 0)
        self.assertEqual(
            _pydbg.read_process_memory(
                self.target.handle, report.remote_base, len(code)), code)
        self.assertEqual(
            self.target.dbg.memory.query(report.remote_base)["protect"],
            0x40)                           # PAGE_EXECUTE_READWRITE

        self.assertEqual(
            _pydbg.wait_for_single_object(report.handle, 10000), 0)
        self.assertEqual(_pydbg.get_exit_code_thread(report.handle), 0)
        _pydbg.close_handle(report.handle)
        self.assertTrue(self.target.alive())


@needs_cython
@needs_target
class TestDllInjectionLive(unittest.TestCase):

    def setUp(self):
        self.target = _LiveTarget(_TARGET)
        self.addCleanup(self.target.close)

    def _wait_and_check_thread(self, report):
        self.assertEqual(
            _pydbg.wait_for_single_object(report.handle, 10000), 0)
        loaded_base = _pydbg.get_exit_code_thread(report.handle)
        _pydbg.close_handle(report.handle)
        self.assertNotEqual(loaded_base, 0, "LoadLibraryW returned NULL")
        # GetExitCodeThread is a DWORD: only the low 32 bits of the HMODULE
        # come back, so compare them against the module list's full base.
        return loaded_base & 0xFFFFFFFF

    def test_inject_dll_adds_a_module_the_target_did_not_have(self):
        """The instrument target never loads the DLL, so its appearance is ours."""
        before = _module_by_name(self.target.dbg.modules.enumerate(),
                                 "dump_target.dll")
        self.assertIsNone(before)

        report = inject_dll(self.target.dbg, _DUMP_DLL)
        loaded_base = self._wait_and_check_thread(report)
        self.assertNotEqual(report.remote_base, 0)
        self.assertEqual(
            self.target.dbg.memory.query(report.remote_base)["protect"],
            0x04)                           # PAGE_READWRITE
        self.assertTrue(self.target.alive())

        module = _module_by_name(self.target.dbg.modules.enumerate(),
                                 "dump_target.dll")
        self.assertIsNotNone(module, "injected module is not in the target")
        self.assertEqual(module["base_address"] & 0xFFFFFFFF, loaded_base)
        self.assertNotEqual(
            _remote_export(self.target.handle, module["base_address"],
                           "dump_target_answer"),
            0)


@needs_cython
@needs_dump_targets
class TestDllInjectionIntoDumpHostLive(unittest.TestCase):
    """The ticket's named pair: dump_host.exe and dump_target.dll."""

    def setUp(self):
        self.target = _LiveTarget(_DUMP_HOST)
        self.addCleanup(self.target.close)

    def test_dump_host_keeps_the_injected_module_and_its_export(self):
        # dump_host loads the DLL by name at startup; the absolute path below
        # still has to succeed in the target, and its HMODULE is the module's
        # base — checked against the target's own module list.
        report = inject_dll(self.target.dbg, _DUMP_DLL)
        self.assertEqual(
            _pydbg.wait_for_single_object(report.handle, 10000), 0)
        loaded_base = _pydbg.get_exit_code_thread(report.handle)
        _pydbg.close_handle(report.handle)
        self.assertNotEqual(loaded_base, 0)
        self.assertTrue(self.target.alive())

        module = _module_by_name(self.target.dbg.modules.enumerate(),
                                 "dump_target.dll")
        self.assertIsNotNone(module)
        self.assertEqual(
            module["base_address"] & 0xFFFFFFFF, loaded_base & 0xFFFFFFFF)
        self.assertNotEqual(
            _remote_export(self.target.handle, module["base_address"],
                           "dump_target_answer"),
            0)


def _sleep_ex_infinite_alertable():
    """x64 shellcode: SleepEx(INFINITE, TRUE); ret — parks an alertable thread.

    The address of SleepEx is taken from this process's kernel32: same-bitness
    processes share kernel32's base address, which is the same assumption
    `inject_dll` makes (documented there).
    """
    kernel32 = _pydbg.get_module_handle("kernel32.dll")
    sleep_ex = _pydbg.get_proc_address(kernel32, "SleepEx")
    return (
        b"\x48\x83\xEC\x28"                 # sub rsp, 0x28 (shadow space)
        + b"\xB9" + struct.pack("<i", -1)   # mov ecx, INFINITE
        + b"\xBA" + struct.pack("<i", 1)    # mov edx, TRUE
        + b"\x48\xB8" + struct.pack("<Q", sleep_ex)   # mov rax, SleepEx
        + b"\xFF\xD0"                       # call rax
        + b"\x48\x83\xC4\x28"               # add rsp, 0x28
        + b"\xC3")                          # ret


def _write_one_to_absolute(absolute):
    """x64 shellcode: mov rax, absolute; mov dword [rax], 1; ret."""
    return (
        b"\x48\xB8" + struct.pack("<Q", absolute)
        + b"\xC7\x00\x01\x00\x00\x00"
        + b"\xC3")


def _write_apc_param_to_absolute(absolute):
    """x64 APC body: mov eax,[rcx]; mov rdx,absolute; mov [rdx],eax; ret.

    The APC's parameter arrives in rcx, which is the pointer to the bytes
    `queue_apc(data=...)` copied into the target.
    """
    return (
        b"\x8B\x01"                         # mov eax, [rcx]
        + b"\x48\xBA" + struct.pack("<Q", absolute)   # mov rdx, absolute
        + b"\x89\x02"                       # mov [rdx], eax
        + b"\xC3")                          # ret


def _wait_for_dword(dbg, address, expected, timeout=5.0):
    """Poll a target dword until it equals 'expected', returning the last read."""
    deadline = time.time() + timeout
    observed = b"\x00\x00\x00\x00"
    while time.time() < deadline:
        observed = dbg.memory.read(address, 4)
        if observed == expected:
            return observed
        time.sleep(0.02)
    return observed


@needs_cython
@needs_target
class TestQueueApcLive(unittest.TestCase):

    def setUp(self):
        self.target = _LiveTarget(_TARGET)
        self.addCleanup(self.target.close)

    def test_apc_runs_on_a_thread_in_an_alertable_wait(self):
        dbg = self.target.dbg
        # Park a fresh remote thread in SleepEx(INFINITE, TRUE): an alertable
        # wait owned by the target, so the APC below must be delivered by it.
        sleeper = inject_shellcode(dbg, _sleep_ex_infinite_alertable())
        result = dbg.memory.alloc_remote(4, 0x04)      # PAGE_READWRITE
        routine = dbg.memory.alloc_remote(17, 0x40)    # PAGE_EXECUTE_READWRITE
        dbg.memory.write(routine, _write_one_to_absolute(result))

        self.assertNotEqual(queue_apc(dbg, sleeper.thread_id, routine), 0)

        observed = _wait_for_dword(dbg, result, b"\x01\x00\x00\x00")
        self.assertEqual(observed, b"\x01\x00\x00\x00",
                         "APC never ran on the alertable target thread")
        self.assertTrue(self.target.alive())

    def test_data_is_copied_into_the_target_as_the_apc_parameter(self):
        dbg = self.target.dbg
        sleeper = inject_shellcode(dbg, _sleep_ex_infinite_alertable())
        result = dbg.memory.alloc_remote(4, 0x04)      # PAGE_READWRITE
        routine = dbg.memory.alloc_remote(15, 0x40)    # PAGE_EXECUTE_READWRITE
        dbg.memory.write(routine, _write_apc_param_to_absolute(result))

        self.assertNotEqual(
            queue_apc(dbg, sleeper.thread_id, routine,
                      data=b"\x2A\x00\x00\x00"), 0)

        observed = _wait_for_dword(dbg, result, b"\x2A\x00\x00\x00")
        self.assertEqual(observed, b"\x2A\x00\x00\x00",
                         "the APC ran without the copied data")

    def test_invalid_thread_id_fails_at_the_apc_stage(self):
        with self.assertRaises(InjectionError) as ctx:
            queue_apc(self.target.dbg, 0x7FFFFFFF, 0x1000)
        message = str(ctx.exception).lower()
        self.assertIn("apc", message)
        self.assertIn("87", message)


@needs_cython
@needs_target
class TestSuspendResumeLive(unittest.TestCase):

    def setUp(self):
        self.target = _LiveTarget(_TARGET)
        self.addCleanup(self.target.close)

    def test_every_thread_is_suspended_and_resumed(self):
        dbg = self.target.dbg
        thread_ids = dbg.get_thread_ids()
        self.assertGreaterEqual(len(thread_ids), 1)

        suspended = suspend_process(dbg)
        self.assertEqual(suspended, len(thread_ids))
        self.assertTrue(self.target.alive(), "target died while suspended")

        resumed = resume_process(dbg)
        self.assertEqual(resumed, len(thread_ids))
        time.sleep(0.1)
        self.assertTrue(self.target.alive(), "target died after resume")


if __name__ == "__main__":                  # pragma: no cover - manual use
    unittest.main()
