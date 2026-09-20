"""Regression tests for the F19 gaps in targets/pydbg-gaps.md.

The three items here share one failure mode, which is why they are one file:
the probe could not tell "nothing happened" apart from "nothing was ever set
up to happen", and both answers were silent and looked identical.

* A breakpoint that was armed and never reached looked exactly like one that
  was never armed — a round that produced zero hits, and nothing to inspect
  afterwards. One real session drew a false negative from precisely that.
* A target's children are not visible after attach(), so get_child_processes()
  came back empty and read_memory(pid=) said "Unknown process pid" — and the
  process whose memory was wanted sat one debug relationship away.
* WaitForDebugEvent held the GIL for its whole timeout, so the debugger's own
  Python threads made no progress while the target was idle. That is where the
  "a dialog fallback must live in another process" conclusion came from.
"""

import ctypes
import os
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

from tests import TEST_NESTED_TARGET_PATH, TEST_TARGET_PATH

try:
    from pydbg import _pydbg  # noqa: F401

    _has_cython = True
except ImportError:
    _has_cython = False

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))

# PROCESS_ALL_ACCESS: the mask a caller passes to open_process() when it does
# mean to patch a process it is not debugging.
PROCESS_ALL_ACCESS = 0x1F0FFF


def _instrument_target():
    """Path to instrument_target.exe, which loops forever calling an export."""
    return os.environ.get(
        "TEST_INSTRUMENT_TARGET_PATH",
        os.path.join(_TEST_DIR, "target", "instrument_target.exe"))


def _export_address(dbg, exe_path, base, name):
    """Absolute address of an export, via the PE export table."""
    from pydbg.pe import PE
    for exp in PE.from_file(exe_path).exports:
        if exp.name == name:
            return base + exp.rva
    raise AssertionError(f"export {name} not found in {exe_path}")


class ProgressCounter(threading.Thread):
    """A background thread whose only job is to prove it got scheduled.

    time.sleep releases the GIL and then has to take it back, so a thread that
    cannot re-acquire it stops counting. The count is therefore a direct
    measurement of how often the debugger's blocking calls let go.
    """

    INTERVAL = 0.002

    def __init__(self):
        super().__init__(daemon=True)
        self.count = 0
        self._stop = False

    def run(self):
        while not self._stop:
            time.sleep(self.INTERVAL)
            self.count += 1

    def stop(self):
        self._stop = True


@unittest.skipUnless(_has_cython, "requires Cython extension")
class TestBreakpointHitCounts(unittest.TestCase):
    """F19 — "this site never ran" and "the probe was never armed" read alike."""

    def setUp(self):
        from tests.helpers import alloc_writable
        from pydbg import Debugger

        # Only CREATE_PROCESS is consumed, so the target is left *running*
        # toward its loader breakpoint rather than parked on it. These tests
        # need the process to actually execute an address, and a target left
        # stopped at the loader breakpoint never gets anywhere.
        self.dbg = Debugger()
        self.pid, self.tid = self.dbg.create_process(TEST_TARGET_PATH)
        event = self.dbg.wait_event(5000)
        if event is not None:
            self.dbg.continue_event(event.pid, event.tid)

        # A writable page that the target never executes. set_breakpoint() does
        # NOT raise for a data address (only for an unmapped one), which is
        # exactly the case where the INT3 lands and nothing ever hits it.
        self.scratch = alloc_writable(self.dbg)

    def tearDown(self):
        from tests.helpers import teardown
        teardown(self.dbg)

    def _drain_to_exit(self):
        """Drive the target to its exit, continuing every event it produces."""
        for _ in range(50):
            event = self.dbg.wait_event(2000)
            if event is None or event.type == "EXIT_PROCESS":
                break
            self.dbg.continue_event(event.pid, event.tid)

    def test_armed_but_never_hit_is_an_answer(self):
        """The half of the question that had no answer before.

        Being armed is provable (set_breakpoint raises for an unmapped
        address). Being armed AND never reached was not — the run simply
        produced no hit, and nothing distinguished it from a misspelled or
        failed setup.
        """
        if not self.scratch:
            self.skipTest("could not allocate scratch memory in the target")

        bp_id = self.dbg.set_breakpoint(self.scratch)
        self._drain_to_exit()

        entries = {e["bp_id"]: e for e in self.dbg.breakpoint_report()}
        self.assertIn(bp_id, entries, "the breakpoint vanished from the report")
        entry = entries[bp_id]
        self.assertEqual(entry["addr"], self.scratch)
        self.assertEqual(entry["hits"], 0, "nothing should have reached it")
        self.assertIs(entry["armed"], True, "the INT3 should still be there")

    def test_the_never_armed_case_is_absence_from_the_report(self):
        """An address with no breakpoint must not produce a zero-hit entry."""
        if not self.scratch:
            self.skipTest("could not allocate scratch memory in the target")
        addresses = {e["addr"] for e in self.dbg.breakpoint_report()}
        self.assertNotIn(self.scratch, addresses)

    def test_hits_are_counted_not_just_flagged(self):
        """A repeatedly executed site must report the real number of hits.

        instrument_target.exe loops forever calling the exported add_numbers
        every 20 ms, so this is a site that genuinely runs more than once —
        a counter that only ever said "hit" would pass a one-hit test.
        """
        target = _instrument_target()
        if not os.path.exists(target):
            self.skipTest(f"instrument target not built: {target}")

        from tests.helpers import teardown
        from pydbg import Debugger

        dbg = Debugger()
        try:
            dbg.create_process(target)
            for _ in range(60):
                event = dbg.wait_event(2000)
                if event is None:
                    break
                dbg.continue_event(event.pid, event.tid)
                if event.type == "EXCEPTION":
                    break

            base = [m for m in dbg.enum_modules()
                    if m["name"].lower().endswith("instrument_target.exe")]
            self.assertTrue(base, "instrument_target.exe not among the modules")
            addr = _export_address(dbg, target, base[0]["base_address"],
                                   "add_numbers")
            bp_id = dbg.set_breakpoint(addr)

            wanted = 3
            delivered = []

            def callback(event):
                if event.type == "EXCEPTION" and event.exception_addr == addr:
                    delivered.append(event.exception_addr)
                    if len(delivered) >= wanted:
                        return False
                return None

            dbg.run(callback, timeout_ms=1000)

            self.assertEqual(len(delivered), wanted,
                             "the loop should have reached add_numbers")
            entries = {e["bp_id"]: e for e in dbg.breakpoint_report()}
            self.assertEqual(entries[bp_id]["hits"], wanted,
                             "the counter must match the hits delivered")
        finally:
            teardown(dbg)

    def test_one_assertion_separates_all_three_states(self):
        """The acceptance case for F19 (1): never armed / armed 0 / armed N.

        Three addresses, one report, one comparison per state. Before this,
        the first two produced the same thing (nothing at all) and the third
        produced an unquantified event.
        """
        from tests.helpers import entry_point

        if not self.scratch:
            self.skipTest("could not allocate scratch memory in the target")

        never_armed = self.scratch + 0x800     # no breakpoint here at all
        armed_never = self.scratch             # armed, never executed
        entry = entry_point(self.dbg)          # executed exactly once

        self.dbg.set_breakpoint(armed_never)
        self.dbg.set_breakpoint(entry)
        self.dbg.run_until(entry, timeout_ms=500, max_wait_ms=10000)
        self._drain_to_exit()

        state = {e["addr"]: (e["armed"], e["hits"])
                 for e in self.dbg.breakpoint_report()}

        self.assertNotIn(never_armed, state)             # never armed
        self.assertEqual(state[armed_never], (True, 0))  # armed, zero hits
        self.assertEqual(state[entry][1], 1)             # armed, N hits

    def test_removing_a_breakpoint_drops_its_count(self):
        if not self.scratch:
            self.skipTest("could not allocate scratch memory in the target")
        bp_id = self.dbg.set_breakpoint(self.scratch)
        self.assertIn(bp_id, {e["bp_id"] for e in self.dbg.breakpoint_report()})
        self.dbg.remove_breakpoint(bp_id)
        self.assertNotIn(bp_id, {e["bp_id"] for e in self.dbg.breakpoint_report()})

    def test_overwritten_breakpoint_reports_armed_false_not_zero_hits(self):
        """"Armed and never hit" must not be reported for a killed INT3.

        A breakpoint that is gone from the target cannot hit, so its zero is
        not evidence that the site never ran — the report has to say so.
        """
        if not self.scratch:
            self.skipTest("could not allocate scratch memory in the target")
        bp_id = self.dbg.set_breakpoint(self.scratch)
        self.dbg.write_memory(self.scratch, b"\x90")
        entry = {e["bp_id"]: e for e in self.dbg.breakpoint_report()}[bp_id]
        self.assertIs(entry["armed"], False)
        self.assertEqual(entry["hits"], 0)

    def test_verify_breakpoints_contract_is_unchanged(self):
        """The pre-existing report must keep its shape and its contents."""
        if not self.scratch:
            self.skipTest("could not allocate scratch memory in the target")
        bp_id = self.dbg.set_breakpoint(self.scratch)
        self.assertEqual(self.dbg.verify_breakpoints(), [])
        self.assertEqual(self.dbg.brk_sw.degraded_hits, 0)
        self.assertIsNone(self.dbg.brk_sw.last_error)

        self.dbg.write_memory(self.scratch, b"\x90")
        report = self.dbg.verify_breakpoints()
        self.assertEqual(len(report), 1)
        self.assertEqual(set(report[0]), {"bp_id", "addr", "found"})
        self.assertEqual(report[0]["bp_id"], bp_id)
        self.assertEqual(report[0]["found"], b"\x90")
        self.assertIn(bp_id, self.dbg.brk_sw.lost)


@unittest.skipUnless(_has_cython, "requires Cython extension")
class TestForeignProcessReads(unittest.TestCase):
    """F19 (2) part one — reading a process by pid through pydbg's own API."""

    def setUp(self):
        from pydbg import Debugger
        self.dbg = Debugger()

    def tearDown(self):
        self.dbg._close_foreign_handles()

    @staticmethod
    def _own_buffer(text=b"pydbg-foreign-read", size=64):
        """A buffer in this process at a known, committed address."""
        return ctypes.create_string_buffer(text, size)

    def test_read_another_process_memory_by_pid(self):
        """No debuggee involved at all: the target is this Python process.

        Before, read_memory(pid=...) answered ProcessError("Unknown process
        pid") for anything that was not the debug target or a debug child, and
        the caller had to drop to ctypes OpenProcess + ReadProcessMemory.
        """
        buf = self._own_buffer()
        data = self.dbg.read_memory(ctypes.addressof(buf), 18, pid=os.getpid())
        self.assertEqual(data, b"pydbg-foreign-read")

    def test_regions_and_query_work_by_pid(self):
        buf = self._own_buffer()
        addr = ctypes.addressof(buf)

        regions = self.dbg.enum_regions(pid=os.getpid())
        self.assertTrue(regions)
        addresses = [r["base_address"] for r in regions]
        self.assertEqual(addresses, sorted(addresses))

        # query_memory must answer for the address, and must agree with
        # itself: the region it names has to contain the address asked about.
        # (It is not compared against enum_regions: the two report the same
        # allocation at different granularities, which is pre-existing.)
        region = self.dbg.query_memory(addr, pid=os.getpid())
        self.assertLessEqual(region["base_address"], addr)
        self.assertGreater(region["base_address"] + region["region_size"], addr)
        self.assertEqual(region["state"], 0x1000, "expected MEM_COMMIT")

    def test_a_pid_that_does_not_exist_still_raises(self):
        """The old error contract for a truly unknown pid is kept."""
        from pydbg.exceptions import ProcessError
        with self.assertRaises(ProcessError):
            self.dbg.read_memory(0x1000, 4, pid=999999)

    def test_reading_does_not_grant_writing_or_terminating(self):
        """Reading a foreign process must not imply the right to change it.

        The implicit open is read-only, and the write paths check the mask the
        handle carries, so "read_memory(pid=X) worked" can never quietly turn
        into "terminate_process(pid=X) worked" — nor into a write that fails
        somewhere else with ERROR_NOACCESS.
        """
        from pydbg.exceptions import ProcessError
        pid = os.getpid()
        addr = ctypes.addressof(self._own_buffer())
        self.dbg.read_memory(addr, 4, pid=pid)        # opens it, read-only

        for label, call in (
            ("write_memory", lambda: self.dbg.write_memory(addr, b"\x00", pid=pid)),
            ("protect_memory", lambda: self.dbg.protect_memory(addr, 1, 0x40, pid=pid)),
            ("set_breakpoint", lambda: self.dbg.set_breakpoint(addr, pid=pid)),
            ("terminate_process", lambda: self.dbg.terminate_process(0, pid=pid)),
        ):
            with self.assertRaises(ProcessError, msg=f"{label} was allowed"):
                call()

    def test_an_explicit_wider_open_is_what_unlocks_writing(self):
        """The read-only default is not a dead end, just an explicit one.

        Asking for more must reopen the process rather than hand back the
        read-only handle and fail later with ERROR_NOACCESS. The write here
        lands in this process's own buffer, so it is checkable.
        """
        from pydbg.exceptions import ProcessError
        pid = os.getpid()
        buf = self._own_buffer(b"AAAA")
        addr = ctypes.addressof(buf)

        self.dbg.read_memory(addr, 1, pid=pid)        # cached read-only
        self.assertEqual(self.dbg._session.foreign_access[pid],
                         self.dbg._READ_ACCESS)
        with self.assertRaises(ProcessError):
            self.dbg.write_memory(addr, b"\x00", pid=pid)

        self.dbg.open_process(pid, PROCESS_ALL_ACCESS)
        self.assertEqual(self.dbg._session.foreign_access[pid],
                         PROCESS_ALL_ACCESS)
        self.dbg.write_memory(addr, b"\x00", pid=pid)
        self.assertEqual(buf.raw[:1], b"\x00")

    def test_close_process_is_idempotent_and_releases_the_handle(self):
        pid = os.getpid()
        self.dbg.open_process(pid)
        self.assertIn(pid, self.dbg._session.foreign_handles)
        self.dbg.close_process(pid)
        self.assertNotIn(pid, self.dbg._session.foreign_handles)
        self.assertNotIn(pid, self.dbg._session.foreign_access)
        self.dbg.close_process(pid)                   # nothing to close


@unittest.skipUnless(_has_cython, "requires Cython extension")
class TestProcessTreeEnumeration(unittest.TestCase):
    """F19 (2) part two — enumerating children from a snapshot, not events."""

    def setUp(self):
        from pydbg import Debugger
        self.dbg = Debugger()

    def test_snapshot_sees_this_process_and_its_parent(self):
        procs = self.dbg.enumerate_processes()
        mine = [p for p in procs if p["pid"] == os.getpid()]
        self.assertEqual(len(mine), 1)
        self.assertTrue(mine[0]["exe_name"], "exe name should be populated")
        self.assertEqual(mine[0]["parent_pid"], os.getppid())

    def test_a_real_child_is_found_by_parent(self):
        """Deterministic, no debuggee: spawn one and look it up."""
        child = subprocess.Popen([sys.executable, "-c",
                                  "import time; time.sleep(20)"])
        try:
            children = self.dbg.enumerate_child_processes(os.getpid())
            by_pid = {c["pid"]: c for c in children}
            self.assertIn(child.pid, by_pid)
            self.assertEqual(by_pid[child.pid]["parent_pid"], os.getpid())
            self.assertTrue(all(c["parent_pid"] == os.getpid()
                                for c in children))
        finally:
            child.terminate()
            child.wait(timeout=10)

    def test_recursive_walks_the_whole_subtree(self):
        """A grandchild is one level down, which is the whole difference."""
        child = subprocess.Popen([sys.executable, "-c", (
            "import subprocess, sys, time;"
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)']);"
            "time.sleep(20)")])
        try:
            grandchild = None
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and grandchild is None:
                found = self.dbg.enumerate_child_processes(child.pid)
                if found:
                    grandchild = found[0]["pid"]
                else:
                    time.sleep(0.05)
            self.assertIsNotNone(grandchild, "the child never spawned a child")

            direct = {c["pid"] for c in
                      self.dbg.enumerate_child_processes(os.getpid())}
            deep = {c["pid"] for c in
                    self.dbg.enumerate_child_processes(os.getpid(), recursive=True)}

            self.assertIn(child.pid, direct)
            self.assertNotIn(grandchild, direct, "one level only, by default")
            self.assertIn(grandchild, deep)
            self.assertTrue(direct < deep, "recursive must go deeper, not sideways")
        finally:
            child.terminate()
            child.wait(timeout=10)

    def test_no_target_and_no_pid_is_an_error_not_an_empty_list(self):
        """An empty list here would read as "no children"."""
        from pydbg.exceptions import ProcessError
        with self.assertRaises(ProcessError):
            self.dbg.enumerate_child_processes()

    def test_the_event_fallback_does_not_merge_another_pids_modules(self):
        """The fallback merges the event table of the pid being asked about.

        The table is keyed by pid, so a read of some other process used to
        merge the session target's modules into that process's answer: a list
        of the right shape holding the wrong DLLs at the wrong addresses, and
        no way to tell from the result. Found while wiring up the foreign-pid
        reads below, which is what made the wrong pid reachable.
        """
        from pydbg import Debugger

        dbg = Debugger()
        dbg._session.pid = 4242
        dbg._session.record_module(4242, 0x400000)
        failing = mock.patch(
            "pydbg.module.resolver._pydbg.enum_process_modules",
            side_effect=OSError(299, "ERROR_PARTIAL_COPY"))

        with failing:
            session_pid = dbg.modules.enumerate_handle(0, allow_event_fallback=True)
            other_pid = dbg.modules.enumerate_handle(0, allow_event_fallback=True,
                                                     pid=99)

        self.assertEqual([m["base_address"] for m in session_pid], [0x400000],
                         "the fallback must still serve the session's own pid")
        self.assertEqual(other_pid, [],
                         "another pid's event table was merged in")


@unittest.skipUnless(_has_cython, "requires Cython extension")
class TestNestedDebugging(unittest.TestCase):
    """F19 (2) — the debuggee of a process we attached to.

    Shape: attach() to a process that spawns a child of its own, the way
    OllyDbg's debuggee sits one debug relationship beyond the debugger.
    nested_parent.exe waits 1500 ms before spawning, so the child genuinely
    appears *after* the attach — otherwise "we saw no event for it" would have
    the competing explanation that it already existed.
    """

    SPAWN_WAIT_S = 15.0
    SETTLE_S = 2.0      # let the child's loader finish before PSAPI asks

    def setUp(self):
        from pydbg import Debugger
        if not os.path.exists(TEST_NESTED_TARGET_PATH):
            self.skipTest(f"nested target not built: {TEST_NESTED_TARGET_PATH}")
        self.pid, self.tid, self.h_proc, self.h_thr = \
            _pydbg.create_process_suspended(TEST_NESTED_TARGET_PATH)
        self.dbg = Debugger()
        self.dbg.attach(self.pid)
        _pydbg.resume_thread(self.h_thr)
        self.events = []
        self.child = None

    def tearDown(self):
        if self.child:
            # The child was opened read-only (that is all reads need), so the
            # explicit wider open is what makes terminating it possible — the
            # same split the API documents.
            try:
                self.dbg.close_process(self.child["pid"])
                self.dbg.open_process(self.child["pid"], PROCESS_ALL_ACCESS)
                self.dbg.terminate_process(0, pid=self.child["pid"])
            except Exception:
                pass
        try:
            self.dbg.detach()
        except Exception:
            pass
        for handle in (getattr(self, "h_thr", None), getattr(self, "h_proc", None)):
            if handle:
                try:
                    _pydbg.close_handle(handle)
                except OSError:
                    pass

    def _drive_until_child(self):
        """Collect events until the snapshot reports the child, then settle."""
        deadline = time.monotonic() + self.SPAWN_WAIT_S
        while time.monotonic() < deadline and self.child is None:
            event = self.dbg.wait_event(100)
            if event is not None:
                self.events.append(event)
                self.dbg.continue_event(event.pid, event.tid)
            children = self.dbg.enumerate_child_processes(self.pid)
            if children:
                self.child = children[0]
        if self.child is not None:
            time.sleep(self.SETTLE_S)
        return self.child

    def test_attach_receives_no_create_process_for_the_child(self):
        """The measurement F19 recorded as unverified, made.

        Result: attach() attaches to ONE process. The target's children
        produce no CREATE_PROCESS event at all — the event stream names the
        attached pid and nothing else — while the snapshot shows the child
        running. So after attach() (and after create_process() without
        set_debug_children(True)) get_child_processes() is a statement about
        what we are debugging, never about what children exist.
        """
        child = self._drive_until_child()
        self.assertIsNotNone(
            child, "the target never spawned a visible child; nothing to "
                   "conclude about the event stream")

        # Control group first: the probe is demonstrably alive. A zero here
        # would mean the observation failed, not that events do not arrive.
        own = [e for e in self.events if e.pid == self.pid]
        self.assertTrue(own, "no events at all for the attached process")

        named = [e for e in self.events
                 if e.type == "CREATE_PROCESS" and e.pid == child["pid"]]
        self.assertEqual(named, [],
                         "attach() is documented as receiving no "
                         "CREATE_PROCESS for the target's children")
        self.assertNotIn(child["pid"], {e.pid for e in self.events})

        # The same fact seen through the API that used to return a bare {}.
        self.assertEqual(self.dbg.get_child_processes(), {})
        self.assertIsNone(self.dbg.get_child_process(child["pid"]))
        # ...and the snapshot, which is the honest way to ask.
        self.assertIn(child["pid"],
                      {c["pid"] for c in self.dbg.enumerate_child_processes(self.pid)})

    def test_detach_releases_the_foreign_handles(self):
        """Handles opened by pid belong to the session, not to the handle it
        happened to be attached to, so detach has to release them too."""
        child = self._drive_until_child()
        self.assertIsNotNone(child, "no child was observed")
        self.dbg.enum_modules(pid=child["pid"])
        self.assertIn(child["pid"], self.dbg._session.foreign_handles)

        self.dbg.detach()
        self.assertEqual(self.dbg._session.foreign_handles, {})
        self.assertEqual(self.dbg._session.foreign_access, {})

    def test_the_childs_memory_is_readable_through_pydbg(self):
        """The read that previously needed ctypes OpenProcess + RPM."""
        child = self._drive_until_child()
        self.assertIsNotNone(child, "no child was observed")

        modules = self.dbg.enum_modules(pid=child["pid"])
        self.assertTrue(modules)

        # The child's list must be the child's: exactly what PSAPI reports,
        # with nothing merged in from the attached process's event table.
        handle = self.dbg.open_process(child["pid"])
        raw = self.dbg.modules.enumerate_handle(handle,
                                                allow_event_fallback=False)
        self.assertEqual(sorted(m["base_address"] for m in modules),
                         sorted(m["base_address"] for m in raw),
                         "modules from another pid were merged in")

        base = modules[0]["base_address"]
        self.assertEqual(self.dbg.read_memory(base, 2, pid=child["pid"]), b"MZ")

        regions = self.dbg.enum_regions(pid=child["pid"])
        self.assertTrue(regions)
        holder = [r for r in regions
                  if r["base_address"] <= base < r["base_address"] + r["region_size"]]
        self.assertEqual(len(holder), 1)

        # module_at answers for it too, so the read paths are consistent.
        found = self.dbg.module_at(base, pid=child["pid"])
        self.assertIsNotNone(found)
        self.assertEqual(found["base_address"], base)


@unittest.skipUnless(_has_cython, "requires Cython extension")
class TestGILIsReleasedWhileWaiting(unittest.TestCase):
    """F19 (3) — a blocking debug wait must not starve other Python threads.

    Measured on this machine, 2 ms per iteration in the counter thread:

        run() blocking ~1.0 s in a silent window   before  after
            another Python thread advanced            1-2    406-731
        wait_for_single_object blocking 1.5 s          1      650

    The threshold below is far below the fixed figure and far above the broken
    one, so it fails loudly if the GIL is ever held across the wait again.
    """

    MIN_PROGRESS = 50

    QUIET_TARGET = (
        "import time; time.sleep(4)")

    def test_run_lets_another_thread_progress_while_it_blocks(self):
        """The acceptance case: progress during run(), in the silent window.

        The debuggee is a Python interpreter that sleeps for four seconds, so
        there is a long, known interval in which the only thing run() can be
        doing is blocking inside WaitForDebugEvent. simple_target.exe is too
        short-lived for this: its own sleep would be over before the drain
        loop reached it, and the measurement would come out near zero whether
        or not the GIL was released.
        """
        from pydbg import Debugger
        from tests.helpers import teardown

        dbg = Debugger()
        try:
            dbg.create_process(
                sys.executable,
                cmdline=f'"{sys.executable}" -c "{self.QUIET_TARGET}"')
            # Drain every startup event, including the loader breakpoint, so
            # the target is running inside its sleep and nothing is queued.
            while True:
                event = dbg.wait_event(1000)
                if event is None:
                    break
                dbg.continue_event(event.pid, event.tid)

            counter = ProgressCounter()
            counter.start()
            before = counter.count
            dbg.run(lambda event: None, timeout_ms=1000)
            progress = counter.count - before
            counter.stop()

            self.assertGreaterEqual(
                progress, self.MIN_PROGRESS,
                f"another Python thread advanced only {progress} times while "
                f"run() blocked; the debug wait is holding the GIL")
        finally:
            teardown(dbg)

    def test_a_blocking_wait_releases_the_gil_without_a_debuggee(self):
        """Same property, deterministic: a handle that cannot signal.

        Nothing is debugged here, so the wait cannot end early on an event and
        the only thing that can let the counter run is the GIL being released.
        """
        kernel32 = ctypes.windll.kernel32
        kernel32.CreateEventW.restype = ctypes.c_void_p
        handle = kernel32.CreateEventW(None, True, False, None)
        self.assertTrue(handle, "CreateEventW failed")

        counter = ProgressCounter()
        counter.start()
        before = counter.count
        result = _pydbg.wait_for_single_object(handle, 1500)
        progress = counter.count - before
        counter.stop()

        self.assertEqual(result, 258, "expected WAIT_TIMEOUT")
        self.assertGreaterEqual(
            progress, self.MIN_PROGRESS,
            f"another Python thread advanced only {progress} times across a "
            f"1.5 s blocking wait; the GIL was held")


if __name__ == "__main__":
    unittest.main()
