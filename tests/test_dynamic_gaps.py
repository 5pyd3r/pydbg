"""Regression tests for the dynamic-analysis gaps in targets/pydbg-gaps.md §C.

Each test here corresponds to a defect hit while analysing real 32-bit targets
(SpaceSniffer, OllyDbg, uTorrent). They share a symptom worth naming: the
library reported success, or simply spun, while nothing was progressing — so
the caller could not tell the state apart from a target that was merely busy.
"""

import os
import struct
import tempfile
import time
import unittest
from unittest import mock

try:
    from pydbg import _pydbg  # noqa: F401

    _has_cython = True
except ImportError:
    _has_cython = False


def _entry_point(dbg):
    """Absolute address of the target's PE entry point."""
    from tests.helpers import entry_point
    return entry_point(dbg)


class DynamicGapTestCase(unittest.TestCase):
    """Shared setup: a target paused on its loader breakpoint."""

    def setUp(self):
        from tests.helpers import create_debugger
        self.dbg, self.pid, self.tid = create_debugger()

    def tearDown(self):
        from tests.helpers import teardown
        teardown(self.dbg)


@unittest.skipUnless(_has_cython, "requires Cython extension")
class TestCreateProcessCmdline(unittest.TestCase):
    """C1 — create_process() could not pass a command line.

    Targets configured by argv (SpaceSniffer only scans under `scan <path>`)
    forced callers onto attach(), which loses every startup-time breakpoint.
    """

    def setUp(self):
        from tests import TEST_ARGV_TARGET_PATH
        self.target = TEST_ARGV_TARGET_PATH

    def _run_to_exit(self, dbg, timeout_ms=500):
        """Drive the event loop until the target exits; return (code, events)."""
        code = None
        for _ in range(200):
            event = dbg.wait_event(timeout_ms)
            if event is None:
                continue
            dbg.continue_event(event.pid, event.tid)
            if event.type == "EXIT_PROCESS":
                code = event.raw.get("exit_code")
                break
        return code

    def test_cmdline_reaches_the_target(self):
        """The command line is handed over verbatim, argv[0] included."""
        if not os.path.exists(self.target):
            self.skipTest(f"argv target not built: {self.target}")

        marker = "pydbg-cmdline-marker"
        out = os.path.join(tempfile.gettempdir(), "pydbg_argv_out.txt")
        if os.path.exists(out):
            os.remove(out)
        cmdline = f'"{self.target}" "{out}" {marker}'

        from pydbg import Debugger
        dbg = Debugger()
        try:
            dbg.create_process(self.target, cmdline=cmdline)
            self._run_to_exit(dbg)
        finally:
            try:
                dbg.terminate_process(0)
            except Exception:
                pass

        self.assertTrue(os.path.exists(out), "target never wrote its argv")
        with open(out, "r", encoding="utf-8", errors="replace") as f:
            lines = [ln.rstrip("\n") for ln in f]

        argv = {}
        for line in lines:
            if line.startswith("argc="):
                continue
            index, _, value = line.partition(":")
            argv[int(index)] = value

        # argv[0] is whatever the caller put in the command line: nothing is
        # prepended, which is the documented contract of cmdline=.
        self.assertEqual(argv[1], out)
        self.assertEqual(argv[2], marker)
        self.assertEqual(argv[0], self.target)

    def test_no_cmdline_still_starts_the_image(self):
        """Without cmdline the historical shape is kept: path is argv[0] only.

        argv_target exits 2 when it is given no arguments, which is exactly the
        observation that proves argc == 1 here.
        """
        if not os.path.exists(self.target):
            self.skipTest(f"argv target not built: {self.target}")

        from pydbg import Debugger
        dbg = Debugger()
        try:
            pid, tid = dbg.create_process(self.target)
            self.assertGreater(pid, 0)
            code = self._run_to_exit(dbg)
        finally:
            try:
                dbg.terminate_process(0)
            except Exception:
                pass

        self.assertEqual(code, 2, "expected argc == 1 without a cmdline")


@unittest.skipUnless(_has_cython, "requires Cython extension")
class TestSafeReadAndRegions(DynamicGapTestCase):
    """C2/C3 — read_memory() dropped partial results; no region enumeration."""

    def test_committed_read_is_complete(self):
        from pydbg import MemoryRead
        base = self.dbg.enum_modules()[0]["base_address"]
        result = self.dbg.read_memory_safe(base, 0x1000)
        self.assertIsInstance(result, MemoryRead)
        self.assertTrue(result.complete)
        self.assertEqual(result.gaps, [])
        self.assertEqual(result.readable_bytes, 0x1000)
        self.assertEqual(result.data[:2], b"MZ")
        # Byte-for-byte agreement with the strict read on a readable range.
        self.assertEqual(result.data, self.dbg.read_memory(base, 0x1000))

    def test_unreadable_range_reports_gaps_instead_of_raising(self):
        result = self.dbg.read_memory_safe(0, 0x1000)
        self.assertFalse(result.complete)
        self.assertEqual(len(result.data), 0x1000)
        self.assertEqual(result.data, b"\x00" * 0x1000)
        self.assertTrue(result.gaps)
        self.assertEqual(result.gaps[0][0], 0)

    def test_an_unreasonable_size_is_refused_not_attempted(self):
        """'size' usually comes from a header field, and header fields lie.

        Before the cap, a corrupt length meant a multi-gigabyte bytearray and
        a read per region across the address space. It has to fail where the
        number entered, not halfway through the address space.
        """
        with self.assertRaises(ValueError) as caught:
            self.dbg.read_memory_safe(0, 0x40000000)          # 1 GiB
        self.assertIn("max_bytes", str(caught.exception))

    def test_the_cap_can_be_raised_by_the_caller(self):
        """A caller that really means it must not be blocked by the default."""
        base = self.dbg.enum_modules()[0]["base_address"]
        result = self.dbg.read_memory_safe(base, 0x1000, max_bytes=0x2000)
        self.assertTrue(result.complete)

    def test_regions_cover_the_main_image(self):
        from tests.helpers import module_base
        base = module_base(self.dbg)
        regions = self.dbg.enum_regions()
        self.assertTrue(regions)

        holder = [r for r in regions
                  if r["base_address"] <= base < r["base_address"] + r["region_size"]]
        self.assertEqual(len(holder), 1, "main image should sit in exactly one region")
        self.assertEqual(holder[0]["state"], 0x1000, "expected MEM_COMMIT")

    def test_regions_are_ascending_and_sized(self):
        regions = self.dbg.enum_regions()
        addresses = [r["base_address"] for r in regions]
        self.assertEqual(addresses, sorted(addresses))
        self.assertTrue(all(r["region_size"] > 0 for r in regions))


@unittest.skipUnless(_has_cython, "requires Cython extension")
class TestModuleAt(DynamicGapTestCase):
    """C4 — enum_modules() raised ERROR_PARTIAL_COPY (299) on the loader
    breakpoint, i.e. precisely when module information is first wanted."""

    def test_module_at_entry_point_while_stopped_on_loader_breakpoint(self):
        """The whole point: an answer at the moment PSAPI refuses to give one."""
        from tests.helpers import module_base
        base = module_base(self.dbg)
        mod = self.dbg.module_at(_entry_point(self.dbg))
        self.assertIsNotNone(mod)
        self.assertEqual(mod["base_address"], base)
        self.assertGreater(mod["size"], 0, "module size is needed for containment")
        self.assertEqual(mod["arch"], "x64" if struct.calcsize("P") == 8 else "x86")

    def test_module_at_unknown_address_returns_none(self):
        # A clean, unmapped address far from any image base.
        self.assertIsNone(self.dbg.module_at(0x10000))

    def test_enum_modules_falls_back_to_event_observed_images(self):
        """PSAPI failing must not mean "no modules" when events named them."""
        from tests.helpers import module_base
        base = module_base(self.dbg)

        with mock.patch("pydbg.module.resolver._pydbg.enum_process_modules",
                        side_effect=OSError(299, "ERROR_PARTIAL_COPY")):
            modules = self.dbg.enum_modules()

        self.assertTrue(modules, "fallback returned nothing")
        self.assertTrue(all(m.get("source") == "events" for m in modules))
        self.assertIn(base, {m["base_address"] for m in modules})

    def test_enum_modules_without_fallback_still_raises(self):
        """The explicit-handle path keeps its old contract (test_module.py)."""
        from pydbg.exceptions import MemError
        with mock.patch("pydbg.module.resolver._pydbg.enum_process_modules",
                        side_effect=OSError(299, "ERROR_PARTIAL_COPY")):
            with self.assertRaises(MemError):
                self.dbg.modules.enumerate_handle(0)

    def test_the_same_chain_with_a_real_failure_and_no_mock(self):
        """The two tests above with mock.patch taken out of the middle.

        A mock replaces the syscall, so it proves the merge logic and nothing
        about whether a real OSError from EnumProcessModulesEx reaches the
        same except clause — nor whether the surviving path copes with entries
        whose PE headers it cannot then read.

        Handle 0 fails for real, and unlike the loader-breakpoint version that
        failure is certain rather than a race (pydbg-gaps.md §D): PSAPI
        answers ERROR_INVALID_HANDLE instead of sometimes answering fine, so
        this cannot pass for the wrong reason on a machine where the timing
        differs.
        """
        recorded = self.dbg._session.modules_for(self.pid)
        self.assertTrue(recorded, "no modules recorded from debug events")

        modules = self.dbg.modules.enumerate_handle(0, allow_event_fallback=True)

        # Exactly the event table: an invalid handle contributes nothing of
        # its own, so anything present came through the fallback.
        self.assertEqual({m["base_address"] for m in modules},
                         {r["base_address"] for r in recorded})
        self.assertTrue(all(m.get("source") == "events" for m in modules))
        # ...and the decoration degraded instead of raising on every one of
        # them, since handle 0 describes no image.
        self.assertTrue(all(m["arch"] == "unknown" for m in modules))


@unittest.skipUnless(_has_cython, "requires Cython extension")
class TestBreakpointOverwriteDetection(DynamicGapTestCase):
    """C5 — a software breakpoint overwritten by the target went silent.

    Self-unpacking targets overwrite their own OEP by design; the breakpoint
    then stops firing and nothing says so.
    """

    def test_intact_breakpoint_is_not_reported(self):
        self.dbg.set_breakpoint(_entry_point(self.dbg))
        self.assertEqual(self.dbg.verify_breakpoints(), [])

    def test_overwritten_breakpoint_is_reported(self):
        entry = _entry_point(self.dbg)
        bp_id = self.dbg.set_breakpoint(entry)

        self.dbg.write_memory(entry, b"\x90")   # the target clobbers our INT3

        report = self.dbg.verify_breakpoints()
        self.assertEqual(len(report), 1)
        self.assertEqual(report[0]["bp_id"], bp_id)
        self.assertEqual(report[0]["addr"], entry)
        self.assertEqual(report[0]["found"], b"\x90")
        self.assertIn(bp_id, self.dbg.brk_sw.lost)

    def test_removed_breakpoint_disappears_from_the_report(self):
        entry = _entry_point(self.dbg)
        bp_id = self.dbg.set_breakpoint(entry)
        self.dbg.write_memory(entry, b"\x90")
        self.assertEqual(len(self.dbg.verify_breakpoints()), 1)

        self.dbg.remove_breakpoint(bp_id)
        self.assertEqual(self.dbg.verify_breakpoints(), [])
        self.assertNotIn(bp_id, self.dbg.brk_sw.lost)


@unittest.skipUnless(_has_cython, "requires Cython extension")
class TestRunUntil(unittest.TestCase):
    """C6 — no run_until(addr), so "did it get there?" was a wall-clock guess."""

    def setUp(self):
        from pydbg import Debugger
        from tests import TEST_TARGET_PATH
        from tests.helpers import alloc_writable, entry_point, teardown

        self._teardown = teardown
        self.dbg = Debugger()
        self.pid, self.tid = self.dbg.create_process(TEST_TARGET_PATH)
        event = self.dbg.wait_event(5000)          # CREATE_PROCESS
        self.dbg.continue_event(event.pid, event.tid)

        # The image is mapped, so the entry point can be resolved; the target
        # is still headed for its loader breakpoint, which run_until must
        # pass through transparently.
        self.entry = entry_point(self.dbg)
        self.scratch = alloc_writable(self.dbg)

    def tearDown(self):
        self._teardown(self.dbg)

    def test_reaches_the_entry_point(self):
        event = self.dbg.run_until(self.entry, timeout_ms=500, max_wait_ms=10000)
        self.assertEqual(event.type, "EXCEPTION")
        self.assertEqual(event.exception_addr, self.entry)

    def test_does_not_disturb_a_caller_breakpoint_at_the_same_address(self):
        bp_id = self.dbg.set_breakpoint(self.entry)
        self.dbg.run_until(self.entry, timeout_ms=500, max_wait_ms=10000)
        self.assertEqual(self.dbg.find_breakpoint(self.entry), bp_id)

    def test_budget_exhausted_is_reported_not_guessed(self):
        """An address that is never executed must fail loudly and on time."""
        if not self.scratch:
            self.skipTest("could not allocate scratch memory in the target")
        from pydbg.exceptions import TimeoutError as PydbgTimeout

        started = time.monotonic()
        with self.assertRaises(PydbgTimeout) as ctx:
            self.dbg.run_until(self.scratch, timeout_ms=100, max_wait_ms=400)
        elapsed = time.monotonic() - started

        self.assertIn(f"{self.scratch:x}", str(ctx.exception).lower())
        self.assertLess(elapsed, 5.0, "budget of 400 ms should not take 5 s")

    def test_temporary_breakpoint_is_removed_afterwards(self):
        self.dbg.run_until(self.entry, timeout_ms=500, max_wait_ms=10000)
        self.assertIsNone(self.dbg.find_breakpoint(self.entry))


if __name__ == "__main__":
    unittest.main()
