"""Tests for pydbg.antidebug — read-only detection of a debugged target.

The pure half (PEB layouts and evidence assembly) runs without a target and
without the Cython extension. The live half needs the extension and a built
`antidebug_target.exe`; it is skipped, never silently green.

The live half verifies the **debugged** state only: `detect()` needs an
attached target, so a process with no debugger has no `detect()` to observe.
That half of the answer — DebuggerCheck(detected=False) — is covered through
the FakeProbe seam (`TestChecks.test_a_clean_state_is_not_detected`).
"""

import os
import struct
import unittest

from pydbg import antidebug
from pydbg.exceptions import PydbgError

try:
    from pydbg import _pydbg  # noqa: F401

    _has_cython = True
except ImportError:
    _has_cython = False

from tests import TEST_ANTIDEBUG_TARGET_PATH, TEST_TARGET_PATH


def _peb(arch, being_debugged=0, nt_global_flag=0, image_base=0):
    """A PEB-sized buffer with the fields parse_peb() reads filled in."""
    offsets = antidebug.peb_offsets(arch)
    size = max(offsets["nt_global_flag"] + 4,
               offsets["image_base"] + (8 if arch == 64 else 4), 0x100)
    data = bytearray(size)
    data[offsets["being_debugged"]] = being_debugged
    struct.pack_into("<I", data, offsets["nt_global_flag"], nt_global_flag)
    struct.pack_into("<Q" if arch == 64 else "<I", data, offsets["image_base"],
                     image_base)
    return bytes(data)


def _image(entry_rva=0x1234, magic=0x20B):
    """A PE header page whose AddressOfEntryPoint is `entry_rva`."""
    image = bytearray(0x1000)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)          # e_lfanew
    image[0x80:0x84] = b"PE\x00\x00"
    optional = 0x80 + 24
    struct.pack_into("<H", image, optional, magic)
    struct.pack_into("<I", image, optional + 0x10, entry_rva)
    return bytes(image)


class TestPebLayout(unittest.TestCase):
    """The PEB field offsets are the one piece of ABI this module hard-codes."""

    def test_x64_offsets(self):
        self.assertEqual(antidebug.peb_offsets(64), {
            "being_debugged": 0x02,
            "nt_global_flag": 0xBC,
            "image_base": 0x10,
        })

    def test_x86_offsets(self):
        self.assertEqual(antidebug.peb_offsets(32), {
            "being_debugged": 0x02,
            "nt_global_flag": 0x68,
            "image_base": 0x08,
        })

    def test_unknown_arch_is_refused(self):
        with self.assertRaises(ValueError):
            antidebug.peb_offsets(48)

    def test_parse_x64_peb(self):
        fields = antidebug.parse_peb(
            _peb(64, being_debugged=1, nt_global_flag=0x70,
                 image_base=0x7FF612340000), 64)
        self.assertEqual(fields["being_debugged"], 1)
        self.assertEqual(fields["nt_global_flag"], 0x70)
        self.assertEqual(fields["image_base"], 0x7FF612340000)

    def test_parse_x86_peb(self):
        fields = antidebug.parse_peb(
            _peb(32, being_debugged=0, nt_global_flag=0x40000070,
                 image_base=0x00400000), 32)
        self.assertEqual(fields["being_debugged"], 0)
        self.assertEqual(fields["nt_global_flag"], 0x40000070)
        self.assertEqual(fields["image_base"], 0x00400000)

    def test_truncated_peb_is_refused(self):
        with self.assertRaises(ValueError):
            antidebug.parse_peb(b"\x00" * 8, 64)


class TestEntryPoint(unittest.TestCase):
    """AddressOfEntryPoint resolution, from bytes rather than from a live PE."""

    def test_entry_point_is_base_plus_rva(self):
        self.assertEqual(
            antidebug.entry_point_from_image(_image(0x1234), 0x400000),
            0x401234)

    def test_pe32_header_is_accepted(self):
        self.assertEqual(
            antidebug.entry_point_from_image(_image(0x2000, magic=0x10B),
                                             0x400000),
            0x402000)

    def test_no_entry_point_answers_none(self):
        self.assertIsNone(
            antidebug.entry_point_from_image(_image(0), 0x400000))

    def test_non_pe_bytes_are_refused(self):
        with self.assertRaises(ValueError):
            antidebug.entry_point_from_image(b"not an image", 0x400000)

    def test_broken_e_lfanew_is_refused(self):
        image = bytearray(_image())
        struct.pack_into("<I", image, 0x3C, 0xFFFF)
        with self.assertRaises(ValueError):
            antidebug.entry_point_from_image(bytes(image), 0x400000)


class TestScanInt3(unittest.TestCase):
    """The 0xCC sweep reports addresses, not a verdict."""

    def test_finds_every_int3(self):
        data = b"\x55\xCC\x90\xCC\xC3"
        self.assertEqual(antidebug.scan_int3(data, 0x401000),
                         [0x401001, 0x401003])

    def test_clean_bytes_yield_nothing(self):
        self.assertEqual(antidebug.scan_int3(b"\x90" * 64, 0x401000), [])


class TestDebugRegisterState(unittest.TestCase):
    """DR0-3/DR7 facts, isolated from the thread they came from."""

    def test_clean_registers(self):
        slots, enabled, dr7 = antidebug.debug_register_state(
            {"dr0": 0, "dr1": 0, "dr2": 0, "dr3": 0, "dr7": 0x400})
        self.assertEqual(slots, ())
        self.assertEqual(enabled, ())
        self.assertEqual(dr7, 0x400)

    def test_armed_slot_is_reported(self):
        slots, enabled, dr7 = antidebug.debug_register_state(
            {"dr0": 0x401000, "dr1": 0, "dr2": 0, "dr3": 0, "dr7": 0x401})
        self.assertEqual(slots, (0,))
        self.assertEqual(enabled, (0,))

    def test_enable_bit_without_address_still_counts(self):
        slots, enabled, _ = antidebug.debug_register_state(
            {"dr0": 0, "dr1": 0, "dr2": 0, "dr3": 0, "dr7": 0x4})
        self.assertEqual(slots, ())
        self.assertEqual(enabled, (1,))


class TestDebuggerCheck(unittest.TestCase):

    def test_check_holds_its_three_facts(self):
        check = antidebug.DebuggerCheck("IsDebuggerPresent", True,
                                        "PEB.BeingDebugged=0x01")
        self.assertEqual(check.name, "IsDebuggerPresent")
        self.assertTrue(check.detected)
        self.assertEqual(check.evidence, "PEB.BeingDebugged=0x01")

    def test_check_is_frozen(self):
        check = antidebug.DebuggerCheck("x", False, "")
        with self.assertRaises(Exception):
            check.detected = True


class FakeProbe:
    """Fabricated facts for one target, including the failures.

    `antidebug._LiveProbe` is the read seam: a test replaces it with this and
    exercises every check without a process or the extension. Each knob can
    also be set to an exception to model a query that fails.
    """

    DEBUGGED_PEB = {"being_debugged": 1, "nt_global_flag": 0x70,
                    "image_base": 0x400000}
    CLEAN_PEB = {"being_debugged": 0, "nt_global_flag": 0x0,
                 "image_base": 0x400000}

    def __init__(self, peb=None, image=None, debug_port=0, debug_flags=1,
                 debug_object=0, remote=0, threads=None, registers=None,
                 system=(0, b"\x00\x01")):
        self.arch = 64
        self.process_handle = 0x1234
        self.peb_address = 0x7FFE0000
        self._peb_data = dict(self.DEBUGGED_PEB if peb is None else peb)
        self._image = _image(0x800) if image is None else image
        self.debug_port = debug_port
        self.debug_flags = debug_flags
        self.debug_object = debug_object
        self.remote = remote
        self._threads = [4321] if threads is None else list(threads)
        self._registers = ({"dr0": 0, "dr1": 0, "dr2": 0, "dr3": 0,
                            "dr7": 0} if registers is None else registers)
        self._system = system

    def image(self):
        return self._image

    @property
    def peb(self):
        return dict(self._peb_data)

    def read(self, addr, size):
        base = self.peb["image_base"]
        return bytes(self._image[addr - base:addr - base + size])

    def process_info(self, info_class, size):
        if info_class == antidebug.PROCESS_DEBUG_PORT:
            return 0, int(self.debug_port).to_bytes(size, "little")
        if info_class == antidebug.PROCESS_DEBUG_FLAGS:
            return 0, int(self.debug_flags).to_bytes(size, "little")
        if info_class == antidebug.PROCESS_DEBUG_OBJECT_HANDLE:
            if isinstance(self.debug_object, tuple):
                return self.debug_object
            return 0, int(self.debug_object).to_bytes(size, "little")
        raise AssertionError(f"unexpected info class {info_class}")

    def system_info(self, info_class, size):
        return self._system

    def remote_debugger_present(self):
        return self.remote

    def threads(self):
        return list(self._threads)

    def registers(self, tid):
        regs = self._registers
        if isinstance(regs, dict):
            return regs
        if callable(regs):
            return regs(tid)
        return regs[tid]


class TestChecks(unittest.TestCase):
    """Every check, driven by fabricated facts through the _LiveProbe seam."""

    NAMES = (
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "PEB.BeingDebugged",
        "PEB.NtGlobalFlag",
        "NtQueryInformationProcess(ProcessDebugPort)",
        "NtQueryInformationProcess(ProcessDebugFlags)",
        "NtQueryInformationProcess(ProcessDebugObjectHandle)",
        "HardwareBreakpoints",
        "INT3Scan",
        "NtQuerySystemInformation(SystemKernelDebuggerInformation)",
    )

    def run_checks(self, probe):
        checks = antidebug._run_checks(probe)
        return {check.name: check for check in checks}

    def test_all_checks_are_reported_in_a_fixed_order(self):
        checks = antidebug._run_checks(FakeProbe())
        self.assertEqual([check.name for check in checks], list(self.NAMES))

    def test_a_debugged_state_is_detected_by_the_api_checks(self):
        by_name = self.run_checks(FakeProbe(
            debug_port=0xFFFFFFFFFFFFFFFF, debug_flags=0, debug_object=0x138,
            remote=1))
        for name in ("IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                     "PEB.BeingDebugged", "PEB.NtGlobalFlag",
                     "NtQueryInformationProcess(ProcessDebugPort)",
                     "NtQueryInformationProcess(ProcessDebugFlags)",
                     "NtQueryInformationProcess(ProcessDebugObjectHandle)"):
            self.assertTrue(by_name[name].detected, f"{name}: {by_name[name]}")
            self.assertTrue(by_name[name].evidence, f"{name} has no evidence")

    def test_the_two_being_debugged_checks_report_the_same_read(self):
        """`IsDebuggerPresent` and PEB.BeingDebugged are two labels on one byte.

        They share a helper, so the PEB offset and value appear in both
        evidence strings in one spelling — not two hand-built variants of the
        same fact.
        """
        by_name = self.run_checks(FakeProbe())
        self.assertIn("PEB+0x2=0x01", by_name["IsDebuggerPresent"].evidence)
        self.assertIn("PEB+0x2=0x01", by_name["PEB.BeingDebugged"].evidence)

    def test_a_failed_nt_status_becomes_that_checks_evidence(self):
        """One error template for every NtQuery call; the status survives."""
        class Failing(FakeProbe):
            def process_info(self, info_class, size):
                return 0x8000000D, b"\x00" * size

        check = self.run_checks(Failing())[
            "NtQueryInformationProcess(ProcessDebugPort)"]
        self.assertFalse(check.detected)
        self.assertIn("0x8000000D", check.evidence)
        self.assertIn("query failed", check.evidence)

    def test_a_clean_state_is_not_detected(self):
        by_name = self.run_checks(FakeProbe(
            peb=FakeProbe.CLEAN_PEB, debug_port=0, debug_flags=1,
            debug_object=0, remote=0))
        for name in self.NAMES:
            if name == "NtQuerySystemInformation(SystemKernelDebuggerInformation)":
                continue          # host state, not target state
            self.assertFalse(by_name[name].detected, f"{name}: {by_name[name]}")

    def test_nt_global_flag_only_counts_the_heap_debug_flags(self):
        clean = self.run_checks(FakeProbe(peb=FakeProbe.CLEAN_PEB))
        self.assertFalse(clean["PEB.NtGlobalFlag"].detected)
        self.assertIn("mask leaves 0x0", clean["PEB.NtGlobalFlag"].evidence)

        flagged = self.run_checks(FakeProbe(
            peb={"being_debugged": 0, "nt_global_flag": 0x70,
                 "image_base": 0x400000}))
        self.assertTrue(flagged["PEB.NtGlobalFlag"].detected)
        self.assertIn("= 0x70", flagged["PEB.NtGlobalFlag"].evidence)

    def test_process_debug_flags_is_inverted(self):
        one = self.run_checks(FakeProbe(debug_flags=1))
        self.assertFalse(
            one["NtQueryInformationProcess(ProcessDebugFlags)"].detected)
        zero = self.run_checks(FakeProbe(debug_flags=0))
        self.assertTrue(
            zero["NtQueryInformationProcess(ProcessDebugFlags)"].detected)

    def test_port_not_set_means_no_debug_object_not_a_failure(self):
        by_name = self.run_checks(FakeProbe(
            debug_object=(antidebug.STATUS_PORT_NOT_SET, b"")))
        check = by_name["NtQueryInformationProcess(ProcessDebugObjectHandle)"]
        self.assertFalse(check.detected)
        self.assertIn("STATUS_PORT_NOT_SET", check.evidence)
        self.assertNotIn("query failed", check.evidence)

    def test_hardware_breakpoint_slot_is_detected(self):
        by_name = self.run_checks(FakeProbe(
            registers={"dr0": 0x401000, "dr1": 0, "dr2": 0, "dr3": 0,
                       "dr7": 0x1}))
        check = by_name["HardwareBreakpoints"]
        self.assertTrue(check.detected)
        self.assertIn("tid=4321", check.evidence)
        self.assertIn("0x401000", check.evidence)

    def test_disabled_nonzero_slot_is_still_reported(self):
        by_name = self.run_checks(FakeProbe(
            registers={"dr0": 0x401000, "dr1": 0, "dr2": 0, "dr3": 0,
                       "dr7": 0x400}))
        self.assertTrue(by_name["HardwareBreakpoints"].detected)

    def test_one_bad_thread_does_not_hide_another(self):
        def registers(tid):
            if tid == 1111:
                raise OSError("thread is gone")
            return {"dr0": 0x401000, "dr1": 0, "dr2": 0, "dr3": 0, "dr7": 0x1}

        by_name = self.run_checks(FakeProbe(threads=[1111, 2222],
                                            registers=registers))
        check = by_name["HardwareBreakpoints"]
        self.assertTrue(check.detected)
        self.assertIn("thread is gone", check.evidence)

    def test_int3_before_the_entry_point_is_reported_by_offset(self):
        image = bytearray(_image(0x800))
        image[0x7F8] = 0xCC                       # entry (image+0x800) - 8
        by_name = self.run_checks(FakeProbe(image=bytes(image)))
        check = by_name["INT3Scan"]
        self.assertTrue(check.detected)
        self.assertIn("entry-8", check.evidence)

    def test_clean_entry_point_bytes_are_not_detected(self):
        by_name = self.run_checks(FakeProbe())
        check = by_name["INT3Scan"]
        self.assertFalse(check.detected)
        self.assertIn("no 0xCC", check.evidence)

    def test_kernel_debugger_information_is_reported(self):
        enabled = self.run_checks(FakeProbe(system=(0, b"\x01\x00")))
        self.assertTrue(
            enabled["NtQuerySystemInformation("
                    "SystemKernelDebuggerInformation)"].detected)
        absent = self.run_checks(FakeProbe(system=(0, b"\x00\x01")))
        self.assertFalse(
            absent["NtQuerySystemInformation("
                   "SystemKernelDebuggerInformation)"].detected)

    def test_one_failing_query_does_not_hide_the_others(self):
        class NoPeb(FakeProbe):
            @property
            def peb(self):
                raise OSError("PEB unreadable")

        by_name = self.run_checks(NoPeb(
            debug_port=0xFFFFFFFFFFFFFFFF, debug_flags=0, debug_object=0x138,
            remote=1))
        # The PEB-dependent checks fail closed, with the reason.
        for name in ("IsDebuggerPresent", "PEB.BeingDebugged",
                     "PEB.NtGlobalFlag", "INT3Scan"):
            self.assertFalse(by_name[name].detected, name)
            self.assertIn("PEB unreadable", by_name[name].evidence, name)
        # Everything else still answered: this is the anti-short-circuit rule.
        for name in ("CheckRemoteDebuggerPresent",
                     "NtQueryInformationProcess(ProcessDebugPort)",
                     "NtQueryInformationProcess(ProcessDebugFlags)",
                     "NtQueryInformationProcess(ProcessDebugObjectHandle)"):
            self.assertTrue(by_name[name].detected, name)

    def test_failed_query_evidence_names_the_error(self):
        class Broken(FakeProbe):
            def process_info(self, info_class, size):
                raise OSError("ntdll said no")

            def remote_debugger_present(self):
                raise OSError("kernel32 said no")

        by_name = self.run_checks(Broken())
        check = by_name["CheckRemoteDebuggerPresent"]
        self.assertFalse(check.detected)
        self.assertIn("kernel32 said no", check.evidence)
        self.assertIn("OSError", check.evidence)


class TestPackageExport(unittest.TestCase):
    """`pydbg.antidebug` and `pydbg.DebuggerCheck` resolve lazily (ADR-0001)."""

    def test_module_is_exported(self):
        import pydbg

        self.assertIs(pydbg.antidebug, antidebug)

    def test_debugger_check_is_exported(self):
        import pydbg

        self.assertIs(pydbg.DebuggerCheck, antidebug.DebuggerCheck)


class TestNoTarget(unittest.TestCase):

    @unittest.skipUnless(_has_cython,
                         "optional dependency: Cython extension")
    def test_detect_without_a_target_raises_pydbgerror(self):
        from pydbg import Debugger

        with self.assertRaises(PydbgError):
            antidebug.detect(Debugger())


def _stop(dbg):
    """Kill the target and drop the handles detect() borrowed, without masking
    the assertion that brought us here."""
    try:
        dbg.terminate_process(0)
    except Exception:
        pass
    for handle in (dbg._session.thread_handle, dbg._session.process_handle):
        if not handle:
            continue
        try:
            dbg.close_handle(handle)
        except Exception:
            pass


def _debugged(path):
    """Create 'path' under debug control and stop on its first event."""
    from pydbg import Debugger

    dbg = Debugger()
    dbg.create_process(path)
    dbg.wait_event(5000)
    return dbg


class LiveDetectionMixin:
    """Shared assertions for the two live targets."""

    def assert_api_checks_fire(self, checks):
        """The kernel-state checks must see a debugger for every target."""
        by_name = {check.name: check for check in checks}
        self.assertEqual(len(checks), len(antidebug._CHECKS))
        self.assertEqual(len(by_name), len(checks), "duplicate check names")
        for name in ("IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                     "PEB.BeingDebugged"):
            check = by_name[name]
            self.assertTrue(check.detected, f"{name}: {check.evidence}")
            self.assertTrue(check.evidence, f"{name} has no evidence")
        self.assertIn("=0x01", by_name["IsDebuggerPresent"].evidence)
        self.assertIn("BOOL=1",
                      by_name["CheckRemoteDebuggerPresent"].evidence)
        for check in checks:
            self.assertTrue(check.evidence, f"{check.name} has no evidence")


@unittest.skipUnless(_has_cython,
                     "optional dependency: Cython extension")
@unittest.skipUnless(os.path.isfile(TEST_ANTIDEBUG_TARGET_PATH),
                     "target not built: " + TEST_ANTIDEBUG_TARGET_PATH)
class TestLiveAntidebugTarget(LiveDetectionMixin, unittest.TestCase):
    """A target that itself performs the classic checks, while debugged."""

    def test_debugged_target_reports_the_api_checks_and_the_nt_classes(self):
        dbg = _debugged(TEST_ANTIDEBUG_TARGET_PATH)
        try:
            checks = antidebug.detect(dbg)
        finally:
            _stop(dbg)

        self.assert_api_checks_fire(checks)
        by_name = {check.name: check for check in checks}
        for name in (
                "NtQueryInformationProcess(ProcessDebugPort)",
                "NtQueryInformationProcess(ProcessDebugFlags)",
                "NtQueryInformationProcess(ProcessDebugObjectHandle)"):
            self.assertTrue(by_name[name].detected,
                            f"{name}: {by_name[name].evidence}")

    def test_detect_writes_nothing_to_the_target(self):
        dbg = _debugged(TEST_ANTIDEBUG_TARGET_PATH)
        try:
            probe = antidebug._LiveProbe(dbg)
            peb_address = probe.peb_address
            image_base = probe.peb["image_base"]
            before = (dbg.read_memory(peb_address, 0x100),
                      dbg.read_memory(image_base, 0x1000))
            antidebug.detect(dbg)
            after = (dbg.read_memory(peb_address, 0x100),
                     dbg.read_memory(image_base, 0x1000))
        finally:
            _stop(dbg)

        self.assertEqual(before, after,
                         "detect() modified the PEB or the image header")


@unittest.skipUnless(_has_cython,
                     "optional dependency: Cython extension")
@unittest.skipUnless(os.path.isfile(TEST_TARGET_PATH),
                     "target not built: " + TEST_TARGET_PATH)
class TestLiveSimpleTarget(LiveDetectionMixin, unittest.TestCase):
    """A target that asks nothing still reports the debugging state.

    This is the documented boundary: detect() reports whether a debugger is
    attached, not whether the target runs anti-debug code. The opposite state
    (no debugger) cannot be reached through detect() — it needs an attached
    target — so `TestChecks` covers it with a fake probe.
    """

    def test_api_checks_fire_even_though_the_target_never_asks(self):
        dbg = _debugged(TEST_TARGET_PATH)
        try:
            checks = antidebug.detect(dbg)
        finally:
            _stop(dbg)

        self.assert_api_checks_fire(checks)


if __name__ == "__main__":
    unittest.main()
