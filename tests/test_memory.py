"""Tests for memory operations: read, write, query, modules, allocation."""

import os
import shutil
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from pydbg.exceptions import MemError
from tests import TEST_TARGET_PATH

try:
    from pydbg import _pydbg

    _has_cython = True
except ImportError:
    _has_cython = False


@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
class TestMemoryReadWrite(unittest.TestCase):
    """Test reading and writing process memory."""

    def setUp(self):
        self.pid, self.tid, self.h_proc, self.h_thr = _pydbg.create_process(
            TEST_TARGET_PATH
        )
        # Consume CREATE_PROCESS event
        _pydbg.wait_for_debug_event(5000)
        _pydbg.continue_debug_event(self.pid, self.tid)

        for _ in range(20):
            event = _pydbg.wait_for_debug_event(5000)
            if event is None:
                break
            if event["event_name"] == "EXCEPTION":
                break
            _pydbg.continue_debug_event(event["pid"], event["tid"])

    def tearDown(self):
        _pydbg.debug_active_process_stop(self.pid)
        _pydbg.terminate_process(self.h_proc, 0)
        _pydbg.close_handle(self.h_proc)
        _pydbg.close_handle(self.h_thr)

    def test_read_memory_from_image(self):
        """Read the PE header from the target process."""
        # First get module info
        modules = _pydbg.enum_process_modules(self.h_proc)
        self.assertGreater(len(modules), 0)

        base = modules[0]["base_address"]
        # Read MZ header
        data = _pydbg.read_process_memory(self.h_proc, base, 2)
        self.assertEqual(data[:2], b"MZ")

    def test_write_and_read_back(self):
        """Write bytes, read back, verify."""
        # Get a writable region
        modules = _pydbg.enum_process_modules(self.h_proc)
        base = modules[0]["base_address"]

        # Find a committed, writable region via VirtualQueryEx
        addr = base + 0x1000
        for _ in range(100):
            try:
                info = _pydbg.virtual_query_ex(self.h_proc, addr)
                if info["state"] == 0x1000:  # MEM_COMMIT
                    break
                addr = info["base_address"] + info["region_size"]
            except OSError:
                break

        # Write test data
        test_data = b"\xde\xad\xbe\xef"
        written = _pydbg.write_process_memory(self.h_proc, addr, test_data)
        self.assertEqual(written, 4)

        # Read back and verify
        read_back = _pydbg.read_process_memory(self.h_proc, addr, 4)
        self.assertEqual(read_back[:4], test_data)

    def test_virtual_query(self):
        """Query memory at module base returns committed region."""
        modules = _pydbg.enum_process_modules(self.h_proc)
        base = modules[0]["base_address"]

        info = _pydbg.virtual_query_ex(self.h_proc, base)
        self.assertIn("base_address", info)
        self.assertIn("region_size", info)
        self.assertIn("protect", info)


@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
class TestModuleEnum(unittest.TestCase):
    """Test module enumeration."""

    def setUp(self):
        self.pid, self.tid, self.h_proc, self.h_thr = _pydbg.create_process(
            TEST_TARGET_PATH
        )
        _pydbg.wait_for_debug_event(5000)
        _pydbg.continue_debug_event(self.pid, self.tid)

        for _ in range(20):
            event = _pydbg.wait_for_debug_event(5000)
            if event is None:
                break
            if event["event_name"] == "EXCEPTION":
                break
            _pydbg.continue_debug_event(event["pid"], event["tid"])

    def tearDown(self):
        _pydbg.debug_active_process_stop(self.pid)
        _pydbg.terminate_process(self.h_proc, 0)
        _pydbg.close_handle(self.h_proc)
        _pydbg.close_handle(self.h_thr)

    def test_enum_modules(self):
        """Verify at least one module is loaded."""
        modules = _pydbg.enum_process_modules(self.h_proc)
        self.assertGreater(len(modules), 0)

    def test_get_module_filename(self):
        """Verify we can get the filename of the first module."""
        modules = _pydbg.enum_process_modules(self.h_proc)
        filename = _pydbg.get_module_file_name_ex(self.h_proc, modules[0]["handle"])
        self.assertTrue(len(filename) > 0)


@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
class TestLongModulePath(unittest.TestCase):
    """A module path longer than MAX_PATH must come back whole, not cut at 260.

    The old fixed char[260] buffer made GetModuleFileNameExA truncate the path
    while still returning success, so the caller could not tell a real path
    from a cut one. The helper now grows its buffer; this starts the target
    from a >MAX_PATH directory and checks the full path survives.
    """

    # Each segment is long enough that a handful of them push the total well
    # past MAX_PATH (260) even after the \\?\ prefix is stripped from the
    # answer.
    _SEGMENT = "pydbg-long-module-path-segment"

    def setUp(self):
        if not os.path.isfile(TEST_TARGET_PATH):
            self.skipTest(f"target not built: {TEST_TARGET_PATH}")

        root = tempfile.mkdtemp(prefix="pydbg-longpath-")
        # rmtree needs the extended-length form too: the root path is short,
        # but the descendants below it are what is being deleted.
        self.addCleanup(shutil.rmtree, "\\\\?\\" + root, True)

        deep = root
        while len(deep) < 300:
            deep = os.path.join(deep, self._SEGMENT)

        # Past MAX_PATH, both the filesystem APIs and CreateProcessA need the
        # \\?\ prefix. The helper's answer may keep or drop it, so the
        # assertions look only at the total length and the suffix.
        self.exe_path = "\\\\?\\" + os.path.join(deep, "long_path_target.exe")
        try:
            os.makedirs("\\\\?\\" + deep)
            shutil.copyfile(TEST_TARGET_PATH, self.exe_path)
        except OSError as exc:
            self.skipTest(f"environment: long paths unavailable ({exc})")

        self.pid = self.tid = self.h_proc = self.h_thr = None
        try:
            self.pid, self.tid, self.h_proc, self.h_thr = (
                _pydbg.create_process(self.exe_path))
        except OSError as exc:
            self.skipTest(
                f"environment: cannot debug from a long path ({exc})")

        _pydbg.wait_for_debug_event(5000)
        _pydbg.continue_debug_event(self.pid, self.tid)
        for _ in range(20):
            event = _pydbg.wait_for_debug_event(5000)
            if event is None:
                break
            if event["event_name"] == "EXCEPTION":
                break
            _pydbg.continue_debug_event(event["pid"], event["tid"])

    def tearDown(self):
        if self.h_proc is None:
            return
        _pydbg.debug_active_process_stop(self.pid)
        _pydbg.terminate_process(self.h_proc, 0)
        _pydbg.close_handle(self.h_proc)
        _pydbg.close_handle(self.h_thr)

    def test_the_whole_path_survives(self):
        modules = _pydbg.enum_process_modules(self.h_proc)
        self.assertGreater(len(modules), 0)
        filename = _pydbg.get_module_file_name_ex(
            self.h_proc, modules[0]["handle"])
        self.assertGreater(
            len(filename), 260,
            f"the module path was cut at MAX_PATH: {filename!r}")
        self.assertTrue(
            filename.lower().endswith("long_path_target.exe"), filename)


# Named constants for readability (used by TestMemoryManagerCoverage).
NULL_PAGE = 0x1
PAGE_READWRITE = 0x04


class TestMemoryManagerCoverage(unittest.TestCase):
    """Live-process coverage for MemoryManager error paths and handle variants."""

    @unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
    def setUp(self):
        from tests.helpers import create_debugger
        self.dbg, self.pid, self.tid = create_debugger()

    def tearDown(self):
        from tests.helpers import teardown
        teardown(self.dbg)

    def test_write_roundtrip(self):
        from tests.helpers import alloc_writable
        base = alloc_writable(self.dbg, 0x1000)
        self.assertNotEqual(base, 0)
        payload = b"\xde\xad\xbe\xef"
        self.dbg.write_memory(base, payload)
        self.assertEqual(self.dbg.read_memory(base, 4), payload)

    def test_protect_and_query(self):
        from tests.helpers import alloc_writable
        base = alloc_writable(self.dbg, 0x1000)
        self.assertNotEqual(base, 0)
        old = self.dbg.protect_memory(base, 0x100, PAGE_READWRITE)
        q = self.dbg.query_memory(base)
        self.assertEqual(q["protect"] & 0xFF, PAGE_READWRITE)
        self.dbg.protect_memory(base, 0x100, old)  # restore
        q2 = self.dbg.query_memory(base)
        self.assertEqual(q2["protect"] & 0xFF, old & 0xFF)

    def test_read_invalid_addr_raises(self):
        from pydbg.exceptions import MemError
        with self.assertRaises(MemError):
            self.dbg.memory.read(NULL_PAGE, 4)

    def test_write_invalid_addr_raises(self):
        from pydbg.exceptions import MemError
        with self.assertRaises(MemError):
            self.dbg.memory.write(NULL_PAGE, b"x")

    def test_query_invalid_addr_raises(self):
        import struct

        from pydbg.exceptions import MemError
        # VirtualQueryEx succeeds on free regions (e.g. 0x1 returns a
        # MEM_FREE region), so use an all-ones address outside the process
        # address space to force the ERROR_INVALID_PARAMETER path.
        # Max uintptr for the host arch: 0xFFFFFFFF on 32-bit,
        # 0xFFFFFFFFFFFFFFFF on 64-bit (keeps this test arch-safe).
        invalid_addr = (1 << (struct.calcsize("P") * 8)) - 1
        with self.assertRaises(MemError):
            self.dbg.memory.query(invalid_addr)

    def test_protect_invalid_addr_raises(self):
        from pydbg.exceptions import MemError
        with self.assertRaises(MemError):
            self.dbg.memory.protect(NULL_PAGE, 1, PAGE_READWRITE)

    def test_handle_variants(self):
        from pydbg.exceptions import MemError
        from tests.helpers import module_base
        h = self.dbg._session.process_handle
        base = module_base(self.dbg)
        self.assertEqual(self.dbg.memory.read_handle(h, base, 2), b"MZ")
        with self.assertRaises(MemError):
            self.dbg.memory.read_handle(0, base, 2)
        with self.assertRaises(MemError):
            self.dbg.memory.write_handle(0, base, b"x")
        with self.assertRaises(MemError):
            self.dbg.memory.query_handle(0, base)
        with self.assertRaises(MemError):
            self.dbg.memory.protect_handle(0, base, 1, 0x04)


# The near allocator's window and placement rule. Spelled out here rather than
# imported so the numbers are checked against the documented ±2GB, not against
# the implementation's own constant.
NEAR_LIMIT = 0x80000000
BASE = 0x140000000


@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
class TestNearAllocator(unittest.TestCase):
    """`alloc_near`: the placement rule, and a refusal that says why."""

    def setUp(self):
        from pydbg.memory.manager import (   # needs the extension
            _near_hint, MemoryManager)
        self.hint = _near_hint
        self.manager = MemoryManager(SimpleNamespace(process_handle=0x1234))
        self.regions = []
        self.scan_calls = []
        self.manager.regions_handle = self._regions

    def _regions(self, handle, low, high):
        self.scan_calls.append((handle, low, high))
        return self.regions

    @staticmethod
    def free(base, size):
        return {"base_address": base, "region_size": size, "state": 0x10000}

    # ── where inside a free region the hint goes ──

    def test_an_aligned_free_region_is_used_as_is(self):
        self.assertEqual(
            self.hint(self.free(BASE + 0x100000, 0x10000), BASE,
                      NEAR_LIMIT, 0x1000),
            BASE + 0x100000)

    def test_a_misaligned_region_base_is_rounded_up(self):
        self.assertEqual(
            self.hint(self.free(BASE + 0x100123, 0x20000), BASE,
                      NEAR_LIMIT, 0x1000),
            BASE + 0x110000)

    def test_a_region_smaller_than_the_request_is_rejected(self):
        self.assertIsNone(
            self.hint(self.free(BASE + 0x100000, 0x800), BASE,
                      NEAR_LIMIT, 0x1000))

    def test_a_hint_that_would_leave_the_window_is_clamped(self):
        high = BASE + NEAR_LIMIT
        self.assertEqual(
            self.hint(self.free(high - 0x8000, 0x10000), BASE,
                      NEAR_LIMIT, 0x1000),
            high - 0x1000)

    def test_a_clamp_that_falls_before_the_region_is_rejected(self):
        high = BASE + NEAR_LIMIT
        self.assertIsNone(
            self.hint(self.free(high - 0x100, 0x20000), BASE,
                      NEAR_LIMIT, 0x8000))

    # ── the allocation itself ──

    def test_the_scan_covers_the_window_around_near(self):
        self.regions = [self.free(BASE + 0x100000, 0x10000)]

        with mock.patch("pydbg.memory.manager._pydbg.virtual_alloc_ex",
                        return_value={"base_address": BASE + 0x100000}):
            self.assertEqual(
                self.manager.alloc_near(0x1000, BASE), BASE + 0x100000)

        low = (BASE - NEAR_LIMIT) & ~0xFFFF
        self.assertEqual(self.scan_calls, [(0x1234, low, BASE + NEAR_LIMIT)])

    def test_the_first_placeable_region_wins(self):
        self.regions = [self.free(BASE + 0x100000, 0x10000),
                        self.free(BASE + 0x400000, 0x10000)]
        allocated = BASE + 0x400000

        with mock.patch(
                "pydbg.memory.manager._pydbg.virtual_alloc_ex",
                side_effect=[OSError(487, "invalid address"),
                             {"base_address": allocated}]) as alloc:
            self.assertEqual(self.manager.alloc_near(0x1000, BASE),
                             allocated)

        self.assertEqual([call.args[1] for call in alloc.call_args_list],
                         [BASE + 0x100000, BASE + 0x400000])

    def test_every_failed_candidate_is_named_in_the_refusal(self):
        self.regions = [
            self.free(BASE + 0x100000, 0x10000),
            self.free(BASE + 0x400000, 0x10000),
            self.free(BASE + 0x800000, 0x800),      # too small
        ]

        with mock.patch(
                "pydbg.memory.manager._pydbg.virtual_alloc_ex",
                side_effect=[OSError(5, "access denied"),
                             OSError(487, "invalid address")]):
            with self.assertRaises(MemError) as caught:
                self.manager.alloc_near(0x1000, BASE)

        message = str(caught.exception)
        self.assertIn("access denied", message)
        self.assertIn("invalid address", message)
        self.assertIn("cannot hold", message)
        self.assertIn("no free region", message)

    def test_an_allocation_without_an_address_is_a_failure_too(self):
        self.regions = [self.free(BASE + 0x100000, 0x10000)]

        with mock.patch("pydbg.memory.manager._pydbg.virtual_alloc_ex",
                        return_value={}):
            with self.assertRaises(MemError) as caught:
                self.manager.alloc_near(0x1000, BASE)

        self.assertIn("returned no address", str(caught.exception))

    def test_no_free_region_is_reported_as_what_the_scan_saw(self):
        self.regions = [{"base_address": BASE, "region_size": 0x1000,
                         "state": 0x1000}]       # MEM_COMMIT

        with self.assertRaises(MemError) as caught:
            self.manager.alloc_near(0x1000, BASE)

        self.assertIn("saw no free region", str(caught.exception))

    def test_a_failed_region_walk_is_reported_not_guessed(self):
        self.manager.regions_handle = mock.Mock(side_effect=MemError("denied"))

        with self.assertRaises(MemError) as caught:
            self.manager.alloc_near(0x1000, BASE)

        self.assertIn("cannot scan", str(caught.exception))

    def test_a_non_positive_size_is_refused(self):
        with self.assertRaises(MemError):
            self.manager.alloc_near(0, BASE)
        self.assertEqual(self.scan_calls, [])


if __name__ == "__main__":
    unittest.main()
