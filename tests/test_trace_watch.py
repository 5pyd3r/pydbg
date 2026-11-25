"""Live tests for the hardware write watch (spec §9.5).

A data breakpoint is delivered as a single-step exception whose ExceptionAddress
is the *next* instruction, so every MEM_WRITE carries rva=0: the address the CPU
reports is not the address that was written. The tests drive the real
instrument_target, whose main loop writes its exported `g_sum` every 20 ms.

Hardware breakpoints armed at the initial loader stop are dropped by the next
continue (measured on this machine), so every test that arms one first stops at
the exported `add_numbers` with `tests.helpers.stop_at` — a normal debug stop.
"""

import os
import tempfile
import unittest

from pydbg.exceptions import BreakpointError
from pydbg.trace import (
    MEM_WRITE, STOP_MAX_EVENTS, MemoryWatch, TraceWriter, read_trace,
)

try:
    from pydbg import _pydbg  # noqa: F401

    _has_cython = True
except ImportError:
    _has_cython = False

_TARGET_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'target')
_TEST_TARGET = os.environ.get(
    'TEST_INSTRUMENT_TARGET_PATH',
    os.path.join(_TARGET_DIR, 'instrument_target.exe'),
)


@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
@unittest.skipUnless(os.path.isfile(_TEST_TARGET),
                     "target not built: instrument_target.exe (meson)")
class _WatchLiveCase(unittest.TestCase):
    """A target paused on its loader breakpoint, with its exports resolved."""

    def setUp(self):
        from tests.helpers import create_debugger, export_address

        self.dbg, self.pid, self.tid = create_debugger(_TEST_TARGET)
        module = self.dbg.enum_modules()[0]
        self.base = module['base_address']
        self.g_sum = export_address(self.dbg, _TEST_TARGET, 'g_sum')
        self.add_numbers = export_address(self.dbg, _TEST_TARGET, 'add_numbers')

    def tearDown(self):
        from tests.helpers import teardown

        teardown(self.dbg)

    def resume_at_function(self):
        """Reach a normal stop inside the target, then release it again.

        Returns the paused debug event, so a test can continue it after the
        watch has been armed.
        """
        from tests.helpers import stop_at

        # Release the loader breakpoint before run_until(): it was delivered
        # to create_debugger() and is still uncontinued, so no further debug
        # event arrives until it is released.
        self.dbg.continue_event(self.pid, self.tid)
        event = stop_at(self.dbg, self.add_numbers)
        return event


class TestMemoryWatchAlignment(_WatchLiveCase):
    """Only the lengths and alignments Windows can encode are accepted."""

    def test_a_misaligned_address_is_refused(self):
        with self.assertRaises(BreakpointError) as caught:
            MemoryWatch(self.dbg, self.g_sum + 1, 4).arm()

        self.assertIn("align", str(caught.exception).lower())
        self.assertEqual(self.dbg.find_breakpoint(self.g_sum + 1), None)

    def test_an_unsupported_length_is_refused(self):
        with self.assertRaises(BreakpointError) as caught:
            MemoryWatch(self.dbg, self.g_sum, 3).arm()

        self.assertIn("length", str(caught.exception).lower())


class TestMemoryWatchArming(_WatchLiveCase):
    """Slots 0-3 are shared; a fifth watch must say so, not overwrite one."""

    def test_a_fifth_watch_finds_no_free_debug_register_slot(self):
        self.resume_at_function()
        watches = [MemoryWatch(self.dbg, self.g_sum + 4 * i, 4)
                   for i in range(4)]
        try:
            for watch in watches:
                self.assertIsInstance(watch.arm(), int)
            with self.assertRaises(BreakpointError) as caught:
                MemoryWatch(self.dbg, self.g_sum + 16, 4).arm()
            self.assertIn("no free debug-register slot",
                          str(caught.exception))
        finally:
            for watch in watches:
                self.assertEqual(watch.disarm(), ())
        for i in range(4):
            self.assertIsNone(self.dbg.find_breakpoint(self.g_sum + 4 * i))

    def test_a_second_arm_is_the_same_arm(self):
        self.resume_at_function()
        watch = MemoryWatch(self.dbg, self.g_sum, 4)
        try:
            first = watch.arm()
            self.assertEqual(watch.arm(), first,
                             "a second arm must not take a second slot")
        finally:
            self.assertEqual(watch.disarm(), ())
        self.assertIsNone(self.dbg.find_breakpoint(self.g_sum))


@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
class TestMemoryWatchRun(_WatchLiveCase):
    """Every write to the watched range becomes one MEM_WRITE event."""

    def test_continuous_writes_are_recorded(self):
        """Two writes are exactly two facts: the budget stops on the third."""
        event = self.resume_at_function()
        before = int.from_bytes(self.dbg.read_memory(self.g_sum, 4), 'little')
        watch = MemoryWatch(self.dbg, self.g_sum, 4, max_events=2)
        recorded = []
        watch.sink = recorded.append
        self.assertIsInstance(watch.arm(), int)
        self.dbg.continue_event(event.pid, event.tid)

        summary = watch.run(max_idle_timeouts=5)

        self.assertEqual(summary.events, 2,
                         "max_events=2 must record exactly two writes")
        self.assertEqual(summary.events, len(recorded))
        self.assertTrue(summary.truncated)
        self.assertEqual(summary.reason, STOP_MAX_EVENTS)
        self.assertEqual(summary.blocks, 0)
        self.assertEqual(summary.instructions, 0)
        for item in recorded:
            self.assertEqual(item.kind, MEM_WRITE)
            self.assertEqual(item.a, self.g_sum)
            self.assertEqual(item.b, 4)
            self.assertEqual(item.rva, 0,
                             "a data breakpoint reports the next instruction")
        ts = [item.ts for item in recorded]
        self.assertEqual(ts, sorted(ts), "a trace's timestamps run forwards")

        after = int.from_bytes(self.dbg.read_memory(self.g_sum, 4), 'little')
        self.assertGreater(after, before, "g_sum did not advance while watched")
        self.assertEqual(watch.disarm(), ())
        self.assertEqual(self.dbg.verify_breakpoints(), [])
        self.assertIsNone(self.dbg.find_breakpoint(self.g_sum))

        self.dbg.terminate_process(0)
        self.assertEqual(self.dbg.get_exit_code(), 0)

    def test_the_budget_stop_clears_the_latched_dr6_slot(self):
        """dr6's slot bit must not survive a budget stop.

        The hit that trips the budget is a real hardware hit: its dr6 bit is
        set. Leaving it latched makes the caller's next single-step look like
        another write. The whole low nibble is checked, so the test does not
        depend on which slot was free.
        """
        event = self.resume_at_function()
        watch = MemoryWatch(self.dbg, self.g_sum, 4, max_events=2)
        try:
            watch.arm()
            self.dbg.continue_event(event.pid, event.tid)
            summary = watch.run(max_idle_timeouts=5)
            dr6 = self.dbg.get_registers(self.tid)['dr6']
        finally:
            self.assertEqual(watch.disarm(), ())

        self.assertEqual(summary.events, 2)
        self.assertEqual(summary.reason, STOP_MAX_EVENTS)
        self.assertEqual(dr6 & 0xF, 0,
                         "the budget stop left a slot latched in dr6")

    def test_a_one_event_budget_truncates_before_the_second_write(self):
        event = self.resume_at_function()
        watch = MemoryWatch(self.dbg, self.g_sum, 4, max_events=1)
        try:
            watch.arm()
            self.dbg.continue_event(event.pid, event.tid)
            summary = watch.run(max_idle_timeouts=5)
        finally:
            self.assertEqual(watch.disarm(), ())

        self.assertEqual(summary.events, 1)
        self.assertEqual(summary.reason, STOP_MAX_EVENTS)
        self.assertTrue(summary.truncated)
        self.assertTrue(summary.single_step_pending,
                        "the caller owns the uncontinued single-step event")
        self.assertEqual(summary.blocks, 0)
        self.assertEqual(summary.instructions, 0)

    def test_writer_and_reader_agree_on_every_event(self):
        event = self.resume_at_function()
        watch = MemoryWatch(self.dbg, self.g_sum, 4, max_events=2)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "writes.pdbgtrc")
            with TraceWriter(path) as writer:
                watch.sink = writer.write
                watch.arm()
                self.dbg.continue_event(event.pid, event.tid)
                summary = watch.run(max_idle_timeouts=5)
            written = list(read_trace(path))

        self.assertEqual(watch.disarm(), ())
        self.assertEqual(summary.events, 2)
        self.assertEqual(len(written), summary.events,
                         "writer and reader disagree on how many events exist")
        self.assertEqual([item.kind for item in written], [MEM_WRITE] * 2)
        self.assertEqual([item.rva for item in written], [0, 0])
        self.assertGreater(summary.elapsed_ns, 0)
        print(f"\nmemory watch: events={summary.events} "
              f"elapsed={summary.elapsed_ns / 1e9:.3f}s")


class _FakeCleanupDebugger:
    """The calls disarm()/discard() make, so cleanup needs no target."""

    def __init__(self):
        self.breakpoints = {}       # bp_id -> addr
        self.removed = []
        self.closed = []

    def add(self, bp_id, addr):
        self.breakpoints[bp_id] = addr

    def remove_breakpoint(self, bp_id):
        self.removed.append(bp_id)
        self.breakpoints.pop(bp_id, None)

    def find_breakpoint(self, addr):
        return next((bid for bid, a in self.breakpoints.items() if a == addr),
                    None)

    def close_handle(self, h):
        self.closed.append(h)

    def get_exit_code(self):
        return 259                  # STILL_ACTIVE


class TestMemoryWatchTeardown(unittest.TestCase):
    """The watch answers the teardown contract close() walks (ADR-0004)."""

    def armed(self):
        dbg = _FakeCleanupDebugger()
        watch = MemoryWatch(dbg, 0x1000, 4)
        watch._bp_id = 7
        watch._slot = 1
        watch._h_threads = {123: 0x55, 456: 0x66}
        dbg.add(7, 0x1000)
        return watch, dbg

    def test_teardown_disarms_and_closes_every_thread_handle(self):
        watch, dbg = self.armed()

        self.assertEqual(watch.teardown(), ())
        self.assertEqual(dbg.removed, [7])
        self.assertEqual(sorted(dbg.closed), [0x55, 0x66])
        self.assertIsNone(watch._bp_id)
        self.assertIsNone(watch._slot)
        self.assertEqual(watch._h_threads, {})
        self.assertEqual(watch.teardown(), (), "teardown is idempotent")

    def test_discard_forgets_the_slot_without_touching_the_target(self):
        watch, dbg = self.armed()

        watch.discard()

        self.assertEqual(dbg.removed, [])
        self.assertEqual(dbg.breakpoints, {7: 0x1000},
                         "discard wrote to a target it was told is gone")
        self.assertIsNone(watch._bp_id)
        self.assertIsNone(watch._slot)
        self.assertEqual(watch._h_threads, {})
        self.assertEqual(sorted(dbg.closed), [0x55, 0x66],
                         "the handles the watch opened still had to be closed")
        watch.discard()         # idempotent


if __name__ == "__main__":
    unittest.main()
