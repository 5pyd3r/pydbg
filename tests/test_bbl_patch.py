"""Thread-safe patching: swing the target's threads, then write five bytes.

`install_patch` is the only code in Phase 3c that mutates executable bytes of a
live process, so the tests here are about what it refuses, not only about what
it writes. A fake debugger stands in for the extension: it owns a memory image
and a handful of threads, and every thread action is recorded so a test can ask
whether a refusal still resumed what it suspended.

The installed patch is a value (`InstalledPatch`), not state hidden on the
debugger: the test that destroys the installing debugger and uninstalls through
a second one is the point of that shape.

The live test at the bottom patches one byte of `instrument_target`'s
`add_numbers` with an INT3 placeholder (and does not execute it), reads it back,
and restores the original bytes. It needs the Cython extension and a built
target, so it skips with the two declared skip families otherwise.
"""

import os
import unittest

from pydbg.exceptions import PydbgError
from pydbg.instrument.bbl import (
    InstalledPatch,
    TargetBusy,
    install_patch,
    uninstall_patch,
)

# The page protections the code under test moves the page through.
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40

# A block entry inside a module. It is an address, not a module-relative RVA:
# the window it opens is compared with thread RIPs, which are absolute.
BLOCK = 0x140001000
# A five-byte detour: the shape a BBL install writes.
PATCH = b"\xE9\x11\x22\x33\x44"
# What was there first: push rbp; mov rbp, rsp; ... (five bytes of real code).
ORIGINAL = b"\x55\x48\x89\xE5\x48"

_TARGET = os.environ.get(
    "TEST_INSTRUMENT_TARGET_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "target", "instrument_target.exe"))

try:
    from pydbg import _pydbg  # noqa: F401

    _has_cython = True
except ImportError:
    _has_cython = False


class FakeThread:
    """One target thread: its tid, its RIP, and the errors a test injects."""

    def __init__(self, tid, rip=0x7FF000001000):
        self.tid = tid
        self.rip = rip
        self.handle = tid * 0x10
        self.suspend_count = 0
        self.open_error = None
        self.suspend_error = None
        self.context_error = None
        self.resume_error = None


class FakeDebugger:
    """A debugger-shaped object: memory bytes plus thread primitives.

    The methods mirror `Debugger`'s public facade (`open_thread`,
    `suspend_thread`, `get_registers`, ...), so the production code needs no
    special case for tests. Every call is recorded; `writes` and `suspend_calls`
    are the two facts the acceptance criteria name.
    """

    def __init__(self, threads):
        self.threads = {thread.tid: thread for thread in threads}
        self.by_handle = {thread.handle: thread for thread in threads}
        self.memory = {}
        self.read_calls = []
        self.writes = []
        self.protect_calls = []
        self.open_calls = []
        self.close_calls = []
        self.suspend_calls = []
        self.resume_calls = []
        self.context_calls = []
        # What the page was protected as before the code under test touches it.
        self.original_protect = PAGE_EXECUTE_READ
        # When set, putting the page back is the operation that fails.
        self.restore_error = None

    # ── memory ──

    def put(self, address, data):
        """Seed the target's memory image."""
        for offset, byte in enumerate(data):
            self.memory[address + offset] = byte

    def bytes_at(self, address, size):
        """The current bytes at `address`, read without recording a call."""
        return bytes(self.memory.get(address + offset, 0)
                     for offset in range(size))

    def read_memory(self, address, size):
        self.read_calls.append((address, size))
        return self.bytes_at(address, size)

    def write_memory(self, address, data):
        self.writes.append((address, bytes(data)))
        self.put(address, data)

    def protect_memory(self, address, size, protect):
        self.protect_calls.append((address, size, protect))
        if protect == self.original_protect and self.restore_error is not None:
            raise self.restore_error
        return self.original_protect

    # ── threads ──

    def enumerate_threads(self):
        return [{"tid": tid} for tid in sorted(self.threads)]

    def open_thread(self, tid):
        self.open_calls.append(tid)
        thread = self.threads[tid]
        if thread.open_error is not None:
            raise thread.open_error
        return thread.handle

    def suspend_thread(self, handle):
        thread = self.by_handle[handle]
        self.suspend_calls.append(thread.tid)
        if thread.suspend_error is not None:
            raise thread.suspend_error
        thread.suspend_count += 1
        return thread.suspend_count - 1

    def resume_thread(self, handle):
        thread = self.by_handle[handle]
        self.resume_calls.append(thread.tid)
        if thread.resume_error is not None:
            raise thread.resume_error
        thread.suspend_count -= 1
        return thread.suspend_count

    def get_registers(self, handle):
        thread = self.by_handle[handle]
        self.context_calls.append(thread.tid)
        if thread.context_error is not None:
            raise thread.context_error
        return {"rip": thread.rip}

    def close_handle(self, handle):
        self.close_calls.append(handle)

    def reset_calls(self):
        """Forget the setup's calls, so a test asserts only its own operation."""
        for name in ("read_calls", "writes", "protect_calls", "open_calls",
                     "close_calls", "suspend_calls", "resume_calls",
                     "context_calls"):
            getattr(self, name).clear()


class TestInstallPatchRefuses(unittest.TestCase):
    """A thread parked in the window means no write at all."""

    def setUp(self):
        self.busy = FakeThread(101, BLOCK + 2)
        self.idle = FakeThread(202)
        self.dbg = FakeDebugger([self.idle, self.busy])
        self.dbg.put(BLOCK, ORIGINAL)

    def test_a_thread_inside_the_window_refuses_the_patch(self):
        with self.assertRaises(TargetBusy) as caught:
            install_patch(self.dbg, BLOCK, PATCH, original=ORIGINAL)

        error = caught.exception
        self.assertIsInstance(error, PydbgError)
        self.assertEqual(error.address, BLOCK)
        self.assertEqual(error.tid, self.busy.tid)
        self.assertIn("target busy", str(error))
        self.assertEqual(self.dbg.writes, [],
                         "a refused patch must not write a single byte")
        self.assertEqual(self.dbg.bytes_at(BLOCK, len(ORIGINAL)), ORIGINAL)
        # Both threads were suspended before the RIPs were checked, so both
        # must be resumed again despite the refusal.
        self.assertEqual(sorted(self.dbg.suspend_calls),
                         sorted([self.busy.tid, self.idle.tid]))
        self.assertEqual(sorted(self.dbg.resume_calls),
                         sorted([self.busy.tid, self.idle.tid]))
        self.assertEqual([thread.suspend_count
                          for thread in (self.busy, self.idle)], [0, 0])
        self.assertEqual(sorted(self.dbg.close_calls),
                         sorted([self.busy.handle, self.idle.handle]))

    def test_a_resume_failure_during_a_refusal_is_attached_to_it(self):
        self.idle.resume_error = OSError(6, "invalid handle")

        with self.assertRaises(TargetBusy) as caught:
            install_patch(self.dbg, BLOCK, PATCH, original=ORIGINAL)

        self.assertEqual(len(caught.exception.warnings), 1)
        self.assertTrue(caught.exception.warnings[0].startswith(
            f"thread {self.idle.tid}:"), caught.exception.warnings)

    def test_a_changed_pre_image_refuses_instead_of_overwriting_it(self):
        """Another owner's INT3 is not ours to replace."""
        other = b"\xCC" + ORIGINAL[1:]
        self.dbg.put(BLOCK, other)
        self.busy.rip = 0x7FF000001000      # no thread in the window; bytes refuse

        with self.assertRaises(TargetBusy) as caught:
            install_patch(self.dbg, BLOCK, PATCH, original=ORIGINAL)

        error = caught.exception
        self.assertEqual(error.address, BLOCK)
        self.assertIn("bytes changed under us", str(error))
        self.assertEqual(self.dbg.writes, [])
        self.assertEqual(self.dbg.bytes_at(BLOCK, len(ORIGINAL)), other)
        # The refusal happens inside the suspended window, so every thread it
        # suspended is resumed again.
        self.assertEqual([thread.suspend_count
                          for thread in (self.busy, self.idle)], [0, 0])
        self.assertEqual(sorted(self.dbg.resume_calls),
                         sorted([self.busy.tid, self.idle.tid]))


class TestInstallPatchWrites(unittest.TestCase):
    """A clear window gets the bytes, the page protection back, and no warnings."""

    def setUp(self):
        self.first = FakeThread(101)
        self.second = FakeThread(202)
        self.dbg = FakeDebugger([self.first, self.second])
        self.dbg.put(BLOCK, ORIGINAL)

    def test_the_patch_is_written_once_and_every_thread_resumes(self):
        installed = install_patch(self.dbg, BLOCK, PATCH, original=ORIGINAL)

        self.assertEqual(installed.warnings, ())
        self.assertEqual(self.dbg.writes, [(BLOCK, PATCH)])
        self.assertEqual(len(self.dbg.writes[0][1]), len(PATCH))
        self.assertEqual(self.dbg.bytes_at(BLOCK, len(PATCH)), PATCH)
        self.assertEqual(self.dbg.suspend_calls, [101, 202])
        self.assertEqual(self.dbg.resume_calls, [202, 101])
        self.assertEqual([thread.suspend_count
                          for thread in (self.first, self.second)], [0, 0])

    def test_the_record_names_the_address_the_patch_and_the_original(self):
        installed = install_patch(self.dbg, BLOCK, PATCH, original=ORIGINAL)

        self.assertEqual(installed, InstalledPatch(BLOCK, PATCH, ORIGINAL))
        self.assertEqual(installed.address, BLOCK)
        self.assertEqual(installed.patch, PATCH)
        self.assertEqual(installed.original, ORIGINAL)

    def test_the_page_is_made_writable_and_then_restored(self):
        install_patch(self.dbg, BLOCK, PATCH, original=ORIGINAL)

        self.assertEqual(self.dbg.protect_calls, [
            (BLOCK, len(PATCH), PAGE_EXECUTE_READWRITE),
            (BLOCK, len(PATCH), PAGE_EXECUTE_READ),
        ])

    def test_only_a_rip_inside_the_window_refuses(self):
        """The window is half-open: the byte after the patch is not covered."""
        for offset, refused in ((0, True), (len(PATCH) - 1, True),
                                (len(PATCH), False)):
            with self.subTest(offset=offset):
                thread = FakeThread(303, BLOCK + offset)
                dbg = FakeDebugger([thread])
                dbg.put(BLOCK, ORIGINAL)

                if refused:
                    with self.assertRaises(TargetBusy):
                        install_patch(dbg, BLOCK, PATCH, original=ORIGINAL)
                    self.assertEqual(dbg.writes, [])
                else:
                    installed = install_patch(
                        dbg, BLOCK, PATCH, original=ORIGINAL)
                    self.assertEqual(installed.warnings, ())
                    self.assertEqual(dbg.writes, [(BLOCK, PATCH)])

    def test_an_empty_patch_is_refused(self):
        with self.assertRaises(PydbgError):
            install_patch(self.dbg, BLOCK, b"", original=ORIGINAL)

        self.assertEqual(self.dbg.writes, [])
        self.assertEqual(self.dbg.suspend_calls, [],
                         "nothing needs suspending for a refused empty patch")

    def test_a_patch_longer_than_its_pre_image_is_refused(self):
        with self.assertRaises(PydbgError):
            install_patch(self.dbg, BLOCK, ORIGINAL + b"\x90",
                          original=ORIGINAL)

        self.assertEqual(self.dbg.writes, [])
        self.assertEqual(self.dbg.suspend_calls, [],
                         "the record cannot cover a restore, so refuse first")


class TestInstallPatchFailures(unittest.TestCase):
    """Every refusal still resumes what it suspended, and says why."""

    def setUp(self):
        self.first = FakeThread(101)
        self.blocked = FakeThread(202)
        self.later = FakeThread(303)
        self.dbg = FakeDebugger([self.first, self.blocked, self.later])
        self.dbg.put(BLOCK, ORIGINAL)

    def test_a_failed_suspend_refuses_and_resumes_the_earlier_ones(self):
        self.blocked.suspend_error = OSError(5, "access denied")

        with self.assertRaises(TargetBusy) as caught:
            install_patch(self.dbg, BLOCK, PATCH, original=ORIGINAL)

        self.assertEqual(caught.exception.tid, self.blocked.tid)
        self.assertIn("cannot suspend", str(caught.exception))
        self.assertEqual(self.dbg.writes, [])
        self.assertEqual(self.dbg.suspend_calls, [101, 202])
        self.assertEqual(self.dbg.resume_calls, [101])
        self.assertEqual(self.first.suspend_count, 0)
        self.assertEqual(self.later.suspend_count, 0,
                         "a thread that was never suspended must not be resumed")
        self.assertEqual(self.dbg.open_calls, [101, 202])
        self.assertEqual(sorted(self.dbg.close_calls),
                         sorted([self.first.handle, self.blocked.handle]))

    def test_a_thread_that_cannot_be_opened_refuses(self):
        self.blocked.open_error = OSError(6, "invalid handle")

        with self.assertRaises(TargetBusy) as caught:
            install_patch(self.dbg, BLOCK, PATCH, original=ORIGINAL)

        self.assertEqual(caught.exception.tid, self.blocked.tid)
        self.assertEqual(self.dbg.writes, [])
        self.assertEqual(self.first.suspend_count, 0)
        self.assertNotIn(self.blocked.tid, self.dbg.suspend_calls)
        self.assertNotIn(self.later.tid, self.dbg.open_calls)

    def test_a_failed_context_read_refuses_and_resumes_every_thread(self):
        self.blocked.context_error = OSError(6, "invalid handle")

        with self.assertRaises(TargetBusy) as caught:
            install_patch(self.dbg, BLOCK, PATCH, original=ORIGINAL)

        self.assertEqual(caught.exception.tid, self.blocked.tid)
        self.assertIn("context", str(caught.exception))
        self.assertEqual(self.dbg.writes, [])
        self.assertEqual([thread.suspend_count
                          for thread in (self.first, self.blocked, self.later)],
                         [0, 0, 0])
        self.assertEqual(sorted(self.dbg.resume_calls),
                         [self.first.tid, self.blocked.tid, self.later.tid])

    def test_a_failed_resume_is_reported_not_raised(self):
        self.first.resume_error = OSError(6, "invalid handle")

        installed = install_patch(self.dbg, BLOCK, PATCH, original=ORIGINAL)

        self.assertEqual(len(installed.warnings), 1)
        self.assertTrue(installed.warnings[0].startswith(
            f"thread {self.first.tid}:"), installed.warnings)
        self.assertEqual(self.dbg.writes, [(BLOCK, PATCH)],
                         "a resume failure must not undo a completed write")
        self.assertEqual(self.blocked.suspend_count, 0)
        self.assertEqual(self.later.suspend_count, 0)
        self.assertIn(self.first.handle, self.dbg.close_calls)

    def test_a_page_that_cannot_be_made_read_only_again_is_reported(self):
        self.dbg.restore_error = OSError(5, "access denied")

        installed = install_patch(self.dbg, BLOCK, PATCH, original=ORIGINAL)

        self.assertEqual(len(installed.warnings), 1)
        self.assertTrue(installed.warnings[0].startswith("page protection at"),
                        installed.warnings)
        self.assertEqual(self.dbg.writes, [(BLOCK, PATCH)])


class TestUninstallPatch(unittest.TestCase):
    """Restore only what is still ours; never overwrite someone else's bytes."""

    def setUp(self):
        self.first = FakeThread(101)
        self.second = FakeThread(202)
        self.dbg = FakeDebugger([self.first, self.second])
        self.dbg.put(BLOCK, ORIGINAL)
        # A real uninstall follows a real install: the record is the only thing
        # that says which patch the bytes should still hold.
        self.installed = install_patch(
            self.dbg, BLOCK, PATCH, original=ORIGINAL)
        self.dbg.reset_calls()

    def test_matching_bytes_are_restored_once(self):
        warnings = uninstall_patch(self.dbg, self.installed)

        self.assertEqual(warnings, ())
        self.assertEqual(self.dbg.read_calls, [(BLOCK, len(ORIGINAL))],
                         "the bytes must be read back before writing")
        self.assertEqual(self.dbg.writes, [(BLOCK, ORIGINAL)])
        self.assertEqual(self.dbg.bytes_at(BLOCK, len(ORIGINAL)), ORIGINAL)
        self.assertEqual(self.dbg.protect_calls, [
            (BLOCK, len(ORIGINAL), PAGE_EXECUTE_READWRITE),
            (BLOCK, len(ORIGINAL), PAGE_EXECUTE_READ),
        ])
        self.assertEqual(sorted(self.dbg.suspend_calls), [101, 202])
        self.assertEqual([thread.suspend_count
                          for thread in (self.first, self.second)], [0, 0])

    def test_bytes_changed_under_us_are_reported_and_left_alone(self):
        changed = bytes([PATCH[0], PATCH[1], PATCH[2] ^ 0xFF, PATCH[3],
                         PATCH[4]])
        self.dbg.put(BLOCK, changed)

        warnings = uninstall_patch(self.dbg, self.installed)

        self.assertEqual(len(warnings), 1)
        self.assertTrue(warnings[0].startswith("bytes changed under us"),
                        warnings)
        self.assertEqual(self.dbg.writes, [],
                         "a changed byte must not be overwritten")
        self.assertEqual(self.dbg.bytes_at(BLOCK, len(changed)), changed)
        self.assertEqual(self.dbg.suspend_calls, [],
                         "nothing needs suspending when nothing will be written")

    def test_a_thread_inside_the_window_refuses_the_restore(self):
        self.second.rip = BLOCK + len(ORIGINAL) - 1

        with self.assertRaises(TargetBusy) as caught:
            uninstall_patch(self.dbg, self.installed)

        self.assertEqual(caught.exception.tid, self.second.tid)
        self.assertEqual(caught.exception.address, BLOCK)
        self.assertEqual(self.dbg.writes, [])
        self.assertEqual(self.dbg.bytes_at(BLOCK, len(ORIGINAL)), PATCH)
        self.assertEqual([thread.suspend_count
                          for thread in (self.first, self.second)], [0, 0])

    def test_an_empty_record_is_refused(self):
        with self.assertRaises(PydbgError):
            uninstall_patch(self.dbg, InstalledPatch(BLOCK, b"", ORIGINAL))

        self.assertEqual(self.dbg.writes, [])

    def test_a_second_uninstall_writes_nothing(self):
        self.assertEqual(uninstall_patch(self.dbg, self.installed), ())
        self.dbg.reset_calls()

        self.assertEqual(uninstall_patch(self.dbg, self.installed), ())
        self.assertEqual(self.dbg.writes, [])
        self.assertEqual(self.dbg.suspend_calls, [],
                         "a no-op uninstall must not touch the threads")

    def test_a_short_patch_is_verified_by_its_own_length(self):
        """A 1-byte placeholder over 5 original bytes restores all five."""
        dbg = FakeDebugger([FakeThread(1)])
        dbg.put(BLOCK, ORIGINAL)
        installed = install_patch(dbg, BLOCK, b"\xCC", original=ORIGINAL)
        self.assertEqual(installed.warnings, ())
        dbg.reset_calls()

        self.assertEqual(uninstall_patch(dbg, installed), ())
        self.assertEqual(dbg.writes, [(BLOCK, ORIGINAL)])
        self.assertEqual(dbg.bytes_at(BLOCK, len(ORIGINAL)), ORIGINAL)

    def test_the_bytes_are_already_original_so_nothing_is_written(self):
        self.dbg.put(BLOCK, ORIGINAL)

        self.assertEqual(uninstall_patch(self.dbg, self.installed), ())
        self.assertEqual(self.dbg.writes, [])
        self.assertEqual(self.dbg.suspend_calls, [])

    def test_the_record_alone_is_enough_on_a_fresh_debugger(self):
        """Uninstall does not depend on the debugger that installed the patch."""
        other = FakeDebugger([FakeThread(7)])
        other.put(BLOCK, self.dbg.bytes_at(BLOCK, len(PATCH)))

        self.assertEqual(uninstall_patch(other, self.installed), ())
        self.assertEqual(other.writes, [(BLOCK, ORIGINAL)])
        self.assertEqual(other.bytes_at(BLOCK, len(ORIGINAL)), ORIGINAL)

    def test_a_record_whose_patch_was_never_there_is_not_restored(self):
        forged = InstalledPatch(BLOCK, b"\xE9\xAA\xAA\xAA\xAA", ORIGINAL)
        self.dbg.put(BLOCK, PATCH)

        warnings = uninstall_patch(self.dbg, forged)

        self.assertEqual(len(warnings), 1)
        self.assertTrue(warnings[0].startswith("bytes changed under us"),
                        warnings)
        self.assertEqual(self.dbg.writes, [])


@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
@unittest.skipUnless(os.path.isfile(_TARGET), "target not built: " + _TARGET)
class TestLivePatch(unittest.TestCase):
    """One INT3 placeholder on a real target: install, read back, restore."""

    def test_an_int3_placeholder_round_trips(self):
        """Patching proves itself on bytes, not on what the API returned."""
        from tests.helpers import create_debugger, export_address, teardown

        dbg, _pid, _tid = create_debugger(_TARGET)
        try:
            target = export_address(dbg, _TARGET, "add_numbers")
            original = dbg.read_memory(target, len(PATCH))

            installed = install_patch(dbg, target, b"\xCC", original=original)
            self.assertEqual(installed.warnings, ())
            self.assertEqual(dbg.read_memory(target, 1), b"\xCC",
                             "the placeholder is not in the target")

            warnings = uninstall_patch(dbg, installed)
            self.assertEqual(warnings, ())
            self.assertEqual(dbg.read_memory(target, len(original)), original,
                             "the original bytes were not restored")
        finally:
            teardown(dbg)


if __name__ == "__main__":
    unittest.main()
