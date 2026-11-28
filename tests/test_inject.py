"""Injection primitives acceptance (spec §13.2, ticket P38/D9).

What this file proves, in the order the ticket lists it:

1. `inject_dll` maps `dump_target.dll` into `dump_host.exe`'s module list and
   the target's own export directory answers `dump_target_answer` — checked by
   walking the *target's* PE headers, not by loading the DLL here;
2. `inject_shellcode` runs `xor eax,eax; ret` to a zero thread exit code and
   the target keeps running;
3. `queue_apc` executes on a thread parked in an alertable wait;
4. `suspend_process`/`resume_process` count every distinct thread once and
   leave the target alive;
5. invalid path / empty code / invalid thread each raise `InjectionError`
   naming the stage and the Win32 code;
6. the extension is not needed to import `pydbg` or `pydbg.inject`, and the
   live checks declare `optional dependency: Cython extension` /
   `target not built:` when their preconditions are missing;
7. the same three primitives work on a WOW64 target (the 2026-11-28 extension,
   spec §13.2/§13.8 item 7): `inject_dll` maps a 32-bit DLL through the
   target's own 32-bit `LoadLibraryW` and its export resolves from the target,
   `inject_shellcode` runs 32-bit code from an allocation below 4 GiB, and
   `queue_apc` runs on the host's own thread in an alertable wait. A 32-bit DLL
   asked of a 64-bit target, and an injection attempted before the 32-bit
   module table exists, are both `InjectionError`s rather than success. Those
   two files are built by `scripts/build-target32.ps1`.

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
import tempfile
import time
import unittest

from pydbg import MemError, PydbgError
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
# The WOW64 pair is built out of band by scripts/build-target32.ps1, so these
# name the source-tree artefacts; tests/meson.build sets the same paths.
_INJECT_HOST32 = os.environ.get(
    "TEST_INJECT_HOST32_PATH",
    os.path.join(_HERE, "target", "inject_host32.exe"))
_INJECT_DLL32 = os.environ.get(
    "TEST_INJECT_DLL32_PATH",
    os.path.join(_HERE, "target", "inject_target32.dll"))

needs_cython = unittest.skipUnless(
    _has_cython, "optional dependency: Cython extension")
needs_target = unittest.skipUnless(
    os.path.isfile(_TARGET), "target not built: " + _TARGET)
needs_dump_targets = unittest.skipUnless(
    os.path.isfile(_DUMP_DLL) and os.path.isfile(_DUMP_HOST),
    "target not built: " + _DUMP_DLL + " and " + _DUMP_HOST)
needs_inject_dll32 = unittest.skipUnless(
    os.path.isfile(_INJECT_DLL32),
    "target not built: " + _INJECT_DLL32 +
    " (scripts/build-target32.ps1)")
needs_inject_targets32 = unittest.skipUnless(
    os.path.isfile(_INJECT_HOST32) and os.path.isfile(_INJECT_DLL32),
    "target not built: " + _INJECT_HOST32 + " and " + _INJECT_DLL32 +
    " (scripts/build-target32.ps1)")
# A 32-bit host cannot exercise WOW64 at all; that is an environment limit, not
# a missing target, so it is reported separately (test_wow64.py says the same).
needs_64bit_host = unittest.skipUnless(
    struct.calcsize("P") == 8 and sys.platform == "win32",
    "environment: 64-bit Windows host")

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
            "assert pydbg.inject is not None\n"
            "assert '_pydbg' not in sys.modules, sorted(sys.modules)\n"
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

    def test_a_failure_without_a_win32_code_does_not_print_win32_zero(self):
        """`win32=0` reads as "Windows said success" when there was no call.

        Only a real Win32/errno number belongs in the message; a precondition
        that never reached Windows says so instead of inventing a code.
        """
        message = self._message(suspend_process, None)
        self.assertNotIn("win32=0", message)
        self.assertIn("no Win32 code", message)

    def test_a_translated_failure_without_a_code_also_omits_win32_zero(self):
        """The same rule for an exception with no winerror/errno to carry."""
        from pydbg.inject import api

        with self.assertRaises(InjectionError) as ctx:
            api._translate("alloc", MemError("the allocator said no"))
        message = str(ctx.exception)
        self.assertNotIn("win32=0", message)
        self.assertIn("no Win32 code", message)
        self.assertIn("the allocator said no", message)

    def test_queue_apc_docstring_requires_an_alertable_wait(self):
        self.assertIn("alertable", queue_apc.__doc__.lower())

    def test_queue_apc_docstring_names_the_data_leak(self):
        """A non-empty `data` allocation is never returned or freed."""
        doc = queue_apc.__doc__.lower()
        self.assertIn("leak", doc)
        self.assertIn("data", doc)


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

    def __init__(self, path, args=()):
        self.process = subprocess.Popen(
            [path, *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
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
        # Asked from Windows, not assumed: the session's architecture is what
        # `enum_modules(arch=32)` checks, so guessing 64 for a 32-bit target
        # would send the WOW64 tests down the 64-bit table.
        session.target_arch = 32 if _pydbg.is_wow64_process(self.handle) else 64

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


def _write_marker_to_absolute_32(absolute):
    """x86 APC body: mov eax,absolute; mov dword [eax],42; ret.

    Every instruction means the same thing in 32-bit and 64-bit mode: `B8 id`
    is `mov eax, imm32` in both (zero-extending to rax in 64-bit mode), and
    `C7 00 id` is `mov dword [eax/rax], imm32`. That matters because Windows
    documents `QueueUserAPC` as unsupported across architectures and the APC is
    dispatched natively, so a 32-bit-only encoding is not safe here — `A3
    moffs32` (a plain 32-bit absolute store) is decoded as a 64-bit `moffs`
    store, writes to a bogus address and takes the target down. This body
    proves the APC ran without depending on which dispatcher delivered it.
    """
    return (
        b"\xB8" + struct.pack("<I", absolute)     # mov eax, absolute
        + b"\xC7\x00\x2A\x00\x00\x00"             # mov dword [eax], 42
        + b"\xC3")                                # ret


def _read_text(path):
    """The text file at 'path', or '' while it is not readable yet."""
    try:
        with open(path, "r", encoding="ascii", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def _wait_for_file_text(path, needle, timeout=10.0):
    """Poll 'path' until its text contains 'needle'; return that text."""
    deadline = time.time() + timeout
    text = ""
    while time.time() < deadline:
        text = _read_text(path)
        if needle in text:
            return text
        time.sleep(0.02)
    raise AssertionError(f"{path} never contained {needle!r}: {text!r}")


def _status_field(text, name):
    """The value half of a 'name=value' line in inject_host32's status file."""
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip() == name:
            return value.strip()
    return None


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


def _settled_thread_ids(dbg, samples=5, interval=0.04, timeout=10.0):
    """The target's thread ids once the set stops changing.

    A freshly started process is not yet a fixed set of threads: the Windows
    loader, a runner's monitoring agent, or the process's own runtime can add
    worker threads a few milliseconds after `CreateProcess` returns. Measuring
    the set inside that window and comparing it with the count
    `suspend_process` derives from its own (later) enumeration compares two
    different thread sets, not two counts of the same one. Wait for `samples`
    consecutive identical snapshots before handing the set to an assertion.
    """
    previous = ()
    stable = 0
    deadline = time.time() + timeout
    while time.time() < deadline:
        current = tuple(sorted(set(dbg.get_thread_ids())))
        if current and current == previous:
            stable += 1
            if stable >= samples:
                return list(current)
        else:
            stable = 0
        previous = current
        time.sleep(interval)
    return list(previous)


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


class _FakeExtension:
    """Just enough of `pydbg._pydbg` to observe what suspend/resume act on."""

    def __init__(self, thread_ids):
        self.thread_ids = list(thread_ids)
        self.suspended = []
        self.resumed = []
        self.closed = []

    def enumerate_threads(self, pid):
        return [dict(tid=tid, owner_pid=pid, base_priority=8)
                for tid in self.thread_ids]

    def open_thread(self, thread_id, access=0):
        return 0x1000 + thread_id

    def suspend_thread(self, handle):
        self.suspended.append(handle)
        return 0

    def resume_thread(self, handle):
        self.resumed.append(handle)
        return 0

    def close_handle(self, handle):
        self.closed.append(handle)
        return 0


class _FakeSession:
    pid = 4242
    process_handle = 0x99
    target_arch = 64


class _FakeDebugger:
    """The session surface `pydbg.inject.api` actually uses."""

    def __init__(self):
        self._session = _FakeSession()


def _api_module():
    """`pydbg.inject.api`, imported against a stub extension when absent.

    The module imports `_pydbg` at its top, so without the compiled extension
    it cannot be imported the normal way. The stub exists only while the module
    executes; the test replaces `_pydbg` with its own fake afterwards, and the
    module is not left cached for other tests.
    """
    try:
        from pydbg.inject import api
        return api
    except ImportError:
        pass

    import importlib
    import sys
    import types
    from unittest import mock

    with mock.patch.dict(
            sys.modules,
            {"pydbg._pydbg": types.ModuleType("pydbg._pydbg")}):
        module = importlib.import_module("pydbg.inject.api")
    package = sys.modules["pydbg.inject"]
    if getattr(package, "api", None) is module:
        delattr(package, "api")
    sys.modules.pop("pydbg.inject.api", None)
    return module


class _FakeApcMemory:
    """Just enough target memory to watch the APC parameter buffer."""

    def __init__(self):
        self.allocations = []
        self.freed = []
        self.writes = []

    def alloc_remote(self, size, protect=0x04):
        address = 0x10000 + 0x1000 * len(self.allocations)
        self.allocations.append(address)
        return address

    def write(self, address, data):
        self.writes.append((address, bytes(data)))

    def free_remote(self, address):
        self.freed.append(address)


class _FakeApcTarget:
    """A Debugger whose session and memory are enough for queue_apc()."""

    def __init__(self):
        self._session = _FakeSession()
        self.memory = _FakeApcMemory()


class TestQueueApcFailureCleanup(unittest.TestCase):
    """The parameter buffer must not outlive an APC that never queued.

    A successful APC owns the bytes it receives (see the docstring), but an
    APC that was never queued never runs, so the caller has no way to free the
    buffer itself.
    """

    def test_a_failed_open_thread_frees_the_parameter_buffer(self):
        from unittest import mock

        api = _api_module()
        target = _FakeApcTarget()
        extension = mock.Mock()
        extension.open_thread.side_effect = OSError(87, "no such thread")

        with mock.patch.object(api, "_pydbg", extension):
            with self.assertRaises(InjectionError):
                api.queue_apc(target, 1234, 0x1000, data=b"\x2A\x00\x00\x00")

        self.assertEqual(len(target.memory.allocations), 1)
        self.assertEqual(target.memory.freed, target.memory.allocations,
                         "the remote parameter buffer leaked")

    def test_a_refused_queue_user_apc_frees_the_parameter_buffer_too(self):
        from unittest import mock

        api = _api_module()
        target = _FakeApcTarget()
        extension = mock.Mock()
        extension.open_thread.return_value = 0x99
        extension.queue_user_apc.side_effect = OSError(5, "access denied")

        with mock.patch.object(api, "_pydbg", extension):
            with self.assertRaises(InjectionError):
                api.queue_apc(target, 1234, 0x1000, data=b"\x2A\x00\x00\x00")

        self.assertEqual(target.memory.freed, target.memory.allocations,
                         "the remote parameter buffer leaked")
        self.assertEqual(extension.close_handle.call_count, 1,
                         "the opened thread handle leaked too")


@needs_cython
class TestSuspendCountUnit(unittest.TestCase):
    """The count is distinct threads successfully suspended, not attempts."""

    def test_a_duplicate_tid_is_suspended_once_and_counted_once(self):
        from unittest import mock

        from pydbg.inject import api

        fake = _FakeExtension([101, 202, 101, 202, 101])
        with mock.patch.object(api, "_pydbg", fake):
            suspended = suspend_process(_FakeDebugger())

        self.assertEqual(suspended, 2)
        self.assertEqual(fake.suspended, [0x1000 + 101, 0x1000 + 202])
        self.assertEqual(fake.closed, [0x1000 + 101, 0x1000 + 202])

    def test_resume_counts_a_duplicate_tid_once_too(self):
        from unittest import mock

        from pydbg.inject import api

        fake = _FakeExtension([7, 7, 9])
        with mock.patch.object(api, "_pydbg", fake):
            resumed = resume_process(_FakeDebugger())

        self.assertEqual(resumed, 2)
        self.assertEqual(fake.resumed, [0x1007, 0x1009])


@needs_cython
@needs_target
class TestSuspendResumeLive(unittest.TestCase):

    def setUp(self):
        self.target = _LiveTarget(_TARGET)
        self.addCleanup(self.target.close)
        self.dbg = self.target.dbg

    def test_every_thread_is_suspended_and_resumed(self):
        # One snapshot, taken once the target's thread set has settled, is the
        # yardstick: suspend_process must account for exactly those threads.
        thread_ids = _settled_thread_ids(self.dbg)
        self.assertGreaterEqual(len(thread_ids), 1)

        suspended = suspend_process(self.dbg)
        self.assertEqual(suspended, len(set(thread_ids)))
        self.assertTrue(self.target.alive(), "target died while suspended")

        resumed = resume_process(self.dbg)
        self.assertEqual(resumed, suspended,
                         "resume did not undo every suspension")
        time.sleep(0.1)
        self.assertTrue(self.target.alive(), "target died after resume")

    def test_a_thread_injected_before_the_suspend_is_counted_too(self):
        """A target with more than its startup threads: every one is counted."""
        sleeper = inject_shellcode(self.dbg, _sleep_ex_infinite_alertable())
        self.addCleanup(_pydbg.close_handle, sleeper.handle)

        thread_ids = _settled_thread_ids(self.dbg)
        self.assertIn(sleeper.thread_id, thread_ids,
                      "the injected thread is missing from the thread set")
        self.assertGreaterEqual(len(thread_ids), 2)

        suspended = suspend_process(self.dbg)
        self.assertEqual(suspended, len(set(thread_ids)))
        self.assertTrue(self.target.alive(), "target died while suspended")

        resumed = resume_process(self.dbg)
        self.assertEqual(resumed, suspended,
                         "resume did not undo every suspension")
        time.sleep(0.1)
        self.assertTrue(self.target.alive(), "target died after resume")


class _Wow64HostCase(unittest.TestCase):
    """Start inject_host32.exe and read the state it publishes.

    The host writes a status file naming its worker thread and whether it
    loaded inject_target32.dll; the worker appends to "<status>.apc" once an
    APC has run on its alertable wait. Subclasses add `host_args`.
    """

    host_args = ()

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="pydbg-inject32-")
        self.addCleanup(self._tmp.cleanup)
        self.status_path = os.path.join(self._tmp.name, "inject_host32.txt")
        self.marker_path = self.status_path + ".apc"
        self.target = _LiveTarget(
            _INJECT_HOST32, args=[self.status_path, *self.host_args])
        self.addCleanup(self.target.close)
        self.dbg = self.target.dbg
        # "end" is the last line, so waiting for it means every earlier field
        # (worker_tid in particular) was fully written before it was parsed.
        self.status = _wait_for_file_text(self.status_path, "end")

    def worker_tid(self):
        """The host's alertable worker thread, as the host itself named it."""
        value = _status_field(self.status, "worker_tid")
        self.assertIsNotNone(value, "inject_host32 published no worker_tid")
        return int(value, 0)


@needs_cython
@needs_64bit_host
@needs_inject_targets32
class TestDllInjectionIntoWow64(_Wow64HostCase):
    """§13.8 item 7: a 32-bit DLL, mapped by the target's 32-bit LoadLibraryW."""

    def test_inject_dll_adds_the_32_bit_module_and_its_export(self):
        self.assertEqual(
            _status_field(self.status, "loaded"), "0",
            "this host loaded the DLL itself; the injection would prove less")
        self.assertIsNone(
            _module_by_name(self.dbg.enum_modules(arch=32),
                            "inject_target32.dll"),
            "the DLL was already in the target before injection")

        report = inject_dll(self.dbg, _INJECT_DLL32)
        self.assertLess(report.remote_base, 0x100000000,
                        "the path buffer is not a 32-bit address")
        self.assertNotEqual(report.remote_base, 0)
        self.assertEqual(
            self.dbg.memory.query(report.remote_base)["protect"],
            0x04)                           # PAGE_READWRITE
        self.assertEqual(
            _pydbg.wait_for_single_object(report.handle, 10000), 0,
            "the remote LoadLibraryW thread did not finish")
        loaded_base = _pydbg.get_exit_code_thread(report.handle)
        _pydbg.close_handle(report.handle)
        self.assertNotEqual(loaded_base, 0, "LoadLibraryW returned NULL")
        self.assertTrue(self.target.alive(),
                        "the target died during the injection")

        module = _module_by_name(self.dbg.enum_modules(arch=32),
                                 "inject_target32.dll")
        self.assertIsNotNone(module, "the injected module is not in the 32-bit "
                                     "table")
        self.assertLess(module["base_address"], 0x100000000)
        self.assertEqual(module["base_address"] & 0xFFFFFFFF,
                         loaded_base & 0xFFFFFFFF)
        export = _remote_export(self.target.handle, module["base_address"],
                                "inject_target32_answer")
        self.assertNotEqual(
            export, 0,
            "the target's mapping has no inject_target32_answer export")
        self.assertLess(export, 0x100000000)


@needs_cython
@needs_64bit_host
@needs_inject_targets32
class TestShellcodeInjectionIntoWow64(_Wow64HostCase):
    """§13.8 item 7: a `ret`-level 32-bit stub runs without killing the host."""

    def test_a_32_bit_ret_stub_runs_and_the_target_survives(self):
        code = b"\x31\xC0\xC3"                  # xor eax,eax; ret
        report = inject_shellcode(self.dbg, code)

        self.assertNotEqual(report.remote_base, 0)
        self.assertLess(report.remote_base, 0x100000000,
                        "the shellcode page is not a 32-bit address")
        self.assertEqual(
            _pydbg.read_process_memory(
                self.target.handle, report.remote_base, len(code)), code)
        self.assertEqual(
            self.dbg.memory.query(report.remote_base)["protect"],
            0x40)                           # PAGE_EXECUTE_READWRITE
        self.assertEqual(
            _pydbg.wait_for_single_object(report.handle, 10000), 0)
        self.assertEqual(_pydbg.get_exit_code_thread(report.handle), 0)
        _pydbg.close_handle(report.handle)
        self.assertTrue(self.target.alive(),
                        "the 32-bit stub killed the target")


@needs_cython
@needs_64bit_host
@needs_inject_targets32
class TestQueueApcOnWow64(_Wow64HostCase):
    """§13.8 item 7: the APC runs on the host's own alertable 32-bit thread."""

    # Load and call the DLL first: this case is "a 32-bit process already using
    # a DLL, then an APC is queued to its alertable thread".
    host_args = ("--load-dll",)

    def test_the_host_used_the_dll_before_the_apc(self):
        """A precondition, so the APC cannot pass on a host that never ran."""
        self.assertEqual(_status_field(self.status, "loaded"), "1")
        self.assertEqual(_status_field(self.status, "answer"), "1234")
        self.assertNotEqual(
            int(_status_field(self.status, "dll_base") or "0", 0), 0)

    def test_apc_runs_on_the_hosts_alertable_thread(self):
        self.assertEqual(_status_field(self.status, "answer"), "1234")
        result = self.dbg.memory.alloc_remote(4, 0x04)   # PAGE_READWRITE
        routine_bytes = _write_marker_to_absolute_32(result)
        routine = self.dbg.memory.alloc_remote(
            len(routine_bytes), 0x40)                    # PAGE_EXECUTE_READWRITE
        self.assertLess(result, 0x100000000)
        self.assertLess(routine, 0x100000000)
        self.dbg.memory.write(routine, routine_bytes)

        self.assertNotEqual(
            queue_apc(self.dbg, self.worker_tid(), routine,
                      data=b"\x2A\x00\x00\x00"), 0)

        self.assertEqual(
            _wait_for_dword(self.dbg, result, b"\x2A\x00\x00\x00"),
            b"\x2A\x00\x00\x00",
            "the APC did not run on the host's alertable thread")
        # The worker only writes this after SleepEx returned
        # WAIT_IO_COMPLETION, i.e. after the APC ran and returned.
        _wait_for_file_text(self.marker_path, "apc")
        self.assertTrue(self.target.alive(), "the APC killed the target")

    def test_an_apc_routine_above_4_gib_is_refused(self):
        with self.assertRaises(InjectionError) as ctx:
            queue_apc(self.dbg, self.worker_tid(), 0x100000000)
        message = str(ctx.exception)
        self.assertIn("apc", message)
        self.assertIn("32-bit", message)
        self.assertTrue(self.target.alive())


@needs_cython
@needs_64bit_host
@needs_target
@needs_inject_dll32
class TestWow64InjectionRefusals(unittest.TestCase):
    """A 32-bit DLL asked of a 64-bit target is an InjectionError."""

    def test_a_32_bit_dll_is_refused_for_a_64_bit_target(self):
        target = _LiveTarget(_TARGET)           # instrument_target.exe, x64
        self.addCleanup(target.close)
        self.assertEqual(target.dbg._session.target_arch, 64)

        with self.assertRaises(InjectionError) as ctx:
            inject_dll(target.dbg, _INJECT_DLL32)
        message = str(ctx.exception)
        self.assertIn("arch", message)
        self.assertIn("32-bit DLL", message)
        self.assertIn("64-bit target", message)
        self.assertTrue(target.alive())


@needs_cython
@needs_64bit_host
@needs_inject_targets32
class TestWow64LoaderBoundary(unittest.TestCase):
    """Injecting before the 32-bit image is loaded is an InjectionError."""

    def test_injection_at_the_loader_breakpoint_is_an_injection_error(self):
        """Before the 32-bit image is in the table, resolving must fail.

        create_process() returns with the target stopped on the initial loader
        breakpoint. On this Windows build the 32-bit table already answers, but
        it is still empty (an older answer is ERROR_PARTIAL_COPY, which #122
        documents). Either way the resolve has to raise InjectionError naming
        the missing table/image, never fall back to this process's kernel32.
        """
        from pydbg import Debugger
        from tests.helpers import teardown

        dbg = Debugger()
        try:
            dbg.create_process(_INJECT_HOST32)
            if _module_by_name(dbg.enum_modules(arch=32),
                               "kernel32.dll") is not None:
                self.skipTest(
                    "environment: the 32-bit kernel32 is already enumerated "
                    "at the initial loader breakpoint")

            with self.assertRaises(InjectionError) as ctx:
                inject_dll(dbg, _INJECT_DLL32)
            message = str(ctx.exception)
            self.assertIn("32-bit", message)
            self.assertIn("module table", message)
        finally:
            teardown(dbg)


class _FakeWow64Session:
    pid = 4242
    process_handle = 0x99
    target_arch = 32


class _FakeHighMemory:
    """Target memory whose next allocation lands above 32-bit address space."""

    HIGH = 0x7FFE00000000

    def __init__(self):
        self.hints = []
        self.freed = []

    def alloc_remote(self, size, protect=0x04, hint=0):
        self.hints.append(hint)
        return self.HIGH

    def free_remote(self, address):
        self.freed.append(address)


class _FakeWow64Target:
    def __init__(self):
        self._session = _FakeWow64Session()
        self.memory = _FakeHighMemory()


class _FakeNoTableDebugger:
    """A 32-bit session whose module table is not visible yet (#122).

    Mirrors what ModuleResolver does before the loader has mapped the 32-bit
    image: EnumProcessModulesEx refuses with ERROR_PARTIAL_COPY and the
    resolver wraps that as MemError. The boundary is platform timing, not a
    controllable live state, so it is reproduced here.
    """

    def __init__(self):
        self._session = _FakeWow64Session()
        self.memory = _FakeHighMemory()

    def enum_modules(self, arch=None):
        try:
            raise OSError(299, "ERROR_PARTIAL_COPY")
        except OSError as exc:
            raise MemError("EnumProcessModulesEx(32-bit)") from exc


@needs_inject_dll32
class TestWow64TableBoundary(unittest.TestCase):
    """A missing 32-bit table is an InjectionError, never a 64-bit fallback."""

    def test_a_missing_32_bit_module_table_is_an_injection_error(self):
        api = _api_module()
        target = _FakeNoTableDebugger()

        with self.assertRaises(InjectionError) as ctx:
            api.inject_dll(target, _INJECT_DLL32)

        message = str(ctx.exception)
        self.assertIn("32-bit module table", message)
        self.assertIn("299", message)       # ERROR_PARTIAL_COPY
        self.assertEqual(target.memory.hints, [],
                         "a missing table must fail before allocating")


class _FakeRefusingMemory:
    """Refuses the first 'refusals' bases, then answers one below 4 GiB."""

    def __init__(self, refusals=2):
        self.refusals = refusals
        self.hints = []
        self.writes = []

    def alloc_remote(self, size, protect=0x04, hint=0):
        self.hints.append(hint)
        if len(self.hints) <= self.refusals:
            raise MemError("VirtualAllocEx failed: the base is taken")
        return 0x12340000

    def write(self, address, data):
        self.writes.append((address, bytes(data)))

    def free_remote(self, address):
        pass


class TestWow64AllocationPolicy(unittest.TestCase):
    """A 32-bit target's allocations are steered, checked and never truncated."""

    def test_a_high_allocation_answer_is_refused_and_released(self):
        from unittest import mock

        api = _api_module()
        target = _FakeWow64Target()
        extension = mock.Mock()

        with mock.patch.object(api, "_pydbg", extension):
            with self.assertRaises(InjectionError) as ctx:
                api.inject_shellcode(target, b"\xC3")

        message = str(ctx.exception)
        self.assertIn("alloc", message)
        self.assertIn("7FFE00000000", message)
        self.assertIn("32-bit", message)
        self.assertEqual(target.memory.freed, [_FakeHighMemory.HIGH],
                         "the refused allocation leaked")
        extension.create_remote_thread.assert_not_called()

    def test_a_refused_hint_is_retried_with_the_next_one(self):
        from unittest import mock

        api = _api_module()
        target = _FakeWow64Target()
        target.memory = _FakeRefusingMemory(refusals=2)
        extension = mock.Mock()
        extension.create_remote_thread.return_value = (7, 0x88)

        with mock.patch.object(api, "_pydbg", extension):
            report = api.inject_shellcode(target, b"\xC3")

        self.assertEqual(report.remote_base, 0x12340000)
        self.assertEqual(len(target.memory.hints), 3,
                         "the allocator was not asked again after a refusal")
        for hint in target.memory.hints:
            self.assertLess(hint, 0x100000000)
        self.assertEqual(extension.create_remote_thread.call_args[0][1],
                         0x12340000)

    def test_the_apc_parameter_block_is_kept_below_4_gib(self):
        from unittest import mock

        api = _api_module()
        target = _FakeWow64Target()
        target.memory = _FakeRefusingMemory(refusals=0)   # answers 0x12340000
        extension = mock.Mock()
        extension.open_thread.return_value = 0x99
        extension.queue_user_apc.return_value = 1

        with mock.patch.object(api, "_pydbg", extension):
            self.assertEqual(
                api.queue_apc(target, 1234, 0x20000000,
                              data=b"\x2A\x00\x00\x00"), 1)

        self.assertEqual(target.memory.hints, [0x10000000],
                         "the parameter block was not steered to a 32-bit base")
        self.assertEqual(target.memory.writes,
                         [(0x12340000, b"\x2A\x00\x00\x00")])
        self.assertEqual(extension.queue_user_apc.call_args[0][2], 0x12340000)

    def test_a_high_apc_parameter_block_is_refused(self):
        from unittest import mock

        api = _api_module()
        target = _FakeWow64Target()
        extension = mock.Mock()
        extension.open_thread.return_value = 0x99

        with mock.patch.object(api, "_pydbg", extension):
            with self.assertRaises(InjectionError) as ctx:
                api.queue_apc(target, 1234, 0x20000000, data=b"\x2A")

        self.assertIn("alloc", str(ctx.exception))
        self.assertEqual(target.memory.freed, [_FakeHighMemory.HIGH],
                         "the refused parameter block leaked")
        extension.queue_user_apc.assert_not_called()


if __name__ == "__main__":                  # pragma: no cover - manual use
    unittest.main()
