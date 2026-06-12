"""Tests for child process debugging support."""

import os
import struct
import unittest

HOST_ARCH = struct.calcsize("P") * 8
_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_CHILD_TARGET = os.path.join(_TEST_DIR, "target", "child_target.exe")
TEST_CHILD_TARGET = os.environ.get("TEST_CHILD_TARGET", _DEFAULT_CHILD_TARGET)

try:
    from pydbg import _pydbg  # noqa: F401
    _has_cython = True
except ImportError:
    _has_cython = False


@unittest.skipUnless(_has_cython, "requires Cython extension")
@unittest.skipUnless(os.path.exists(TEST_CHILD_TARGET), "child_target.exe not found")
class TestChildProcessFlag(unittest.TestCase):
    """Tests for set_debug_children flag."""

    def test_set_debug_children(self):
        from pydbg import Debugger
        dbg = Debugger()
        dbg.set_debug_children(True)
        self.assertTrue(dbg._session.debug_children)
        dbg.set_debug_children(False)
        self.assertFalse(dbg._session.debug_children)

    def test_set_debug_children_after_create_raises(self):
        from pydbg import Debugger
        from pydbg.exceptions import ProcessError
        dbg = Debugger()
        pid, tid = dbg.create_process(TEST_CHILD_TARGET)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)
        with self.assertRaises(ProcessError):
            dbg.set_debug_children(True)
        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)


@unittest.skipUnless(_has_cython, "requires Cython extension")
@unittest.skipUnless(os.path.exists(TEST_CHILD_TARGET), "child_target.exe not found")
class TestChildProcessTracking(unittest.TestCase):
    """Tests for automatic child process tracking."""

    def _create_with_children(self):
        from pydbg import Debugger
        dbg = Debugger()
        dbg.set_debug_children(True)
        pid, tid = dbg.create_process(TEST_CHILD_TARGET)
        return dbg, pid, tid

    def test_child_process_event_tracking(self):
        dbg, pid, tid = self._create_with_children()

        child_found = False
        for _ in range(100):
            event = dbg.wait_event(3000)
            if event is None:
                continue
            dbg.continue_event(event.pid, event.tid)
            if event.type == "CREATE_PROCESS" and event.is_child:
                child_found = True
                break
            if event.type == "EXIT_PROCESS" and event.pid == pid:
                break

        self.assertTrue(child_found, "Should receive CREATE_PROCESS for child")
        children = dbg.get_child_processes()
        self.assertGreater(len(children), 0)

        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    def test_child_process_exit_tracking(self):
        dbg, pid, tid = self._create_with_children()

        child_pid = None
        for _ in range(100):
            event = dbg.wait_event(3000)
            if event is None:
                continue
            dbg.continue_event(event.pid, event.tid)
            if event.type == "CREATE_PROCESS" and event.is_child:
                child_pid = event.pid
            if event.type == "EXIT_PROCESS" and child_pid and event.pid == child_pid:
                break

        if child_pid:
            child = dbg.get_child_process(child_pid)
            self.assertIsNotNone(child)
            self.assertIsNotNone(child.exit_code)

        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    def test_get_child_processes(self):
        dbg, pid, tid = self._create_with_children()

        for _ in range(50):
            event = dbg.wait_event(3000)
            if event is None:
                continue
            dbg.continue_event(event.pid, event.tid)
            if event.type == "CREATE_PROCESS" and event.is_child:
                break

        children = dbg.get_child_processes()
        self.assertIsInstance(children, dict)
        self.assertGreater(len(children), 0)

        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    def test_is_child_event(self):
        dbg, pid, tid = self._create_with_children()

        found_parent = False
        found_child = False
        for _ in range(100):
            event = dbg.wait_event(3000)
            if event is None:
                continue
            dbg.continue_event(event.pid, event.tid)
            if event.type == "CREATE_PROCESS":
                if event.pid == pid:
                    found_parent = True
                    self.assertFalse(event.is_child)
                else:
                    found_child = True
                    self.assertTrue(event.is_child)
            if found_parent and found_child:
                break

        self.assertTrue(found_parent)
        self.assertTrue(found_child)

        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)


@unittest.skipUnless(_has_cython, "requires Cython extension")
@unittest.skipUnless(os.path.exists(TEST_CHILD_TARGET), "child_target.exe not found")
class TestChildProcessOperations(unittest.TestCase):
    """Tests for operating on child processes via pid parameter."""

    def _get_child_pid(self, dbg):
        """Wait for child process and return its pid."""
        for _ in range(100):
            event = dbg.wait_event(3000)
            if event is None:
                continue
            dbg.continue_event(event.pid, event.tid)
            if event.type == "CREATE_PROCESS" and event.is_child:
                return event.pid
        return None

    def test_read_child_memory(self):
        from pydbg import Debugger
        dbg = Debugger()
        dbg.set_debug_children(True)
        pid, tid = dbg.create_process(TEST_CHILD_TARGET)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        child_pid = self._get_child_pid(dbg)
        self.assertIsNotNone(child_pid)

        children = dbg.get_child_processes()
        child = children[child_pid]
        if child.process_handle:
            data = dbg.read_memory(child.base_of_image or 0x400000, 2, pid=child_pid)
            self.assertEqual(data[:2], b"MZ")

        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    def test_set_child_breakpoint(self):
        from pydbg import Debugger
        dbg = Debugger()
        dbg.set_debug_children(True)
        pid, tid = dbg.create_process(TEST_CHILD_TARGET)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        child_pid = self._get_child_pid(dbg)
        self.assertIsNotNone(child_pid)

        children = dbg.get_child_processes()
        child = children[child_pid]
        if child.process_handle and child.base_of_image:
            bp_id = dbg.set_breakpoint(child.base_of_image, pid=child_pid)
            self.assertGreater(bp_id, 0)
            dbg.remove_breakpoint(bp_id)

        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)

    def test_detach_child(self):
        from pydbg import Debugger
        dbg = Debugger()
        dbg.set_debug_children(True)
        pid, tid = dbg.create_process(TEST_CHILD_TARGET)
        dbg.wait_event(5000)
        dbg.continue_event(pid, tid)

        child_pid = self._get_child_pid(dbg)
        self.assertIsNotNone(child_pid)

        # Detach child — should not raise
        dbg.detach(pid=child_pid)

        dbg.terminate_process(0)
        dbg.close_handle(dbg._session.process_handle)
        dbg.close_handle(dbg._session.thread_handle)


@unittest.skipUnless(_has_cython, "requires Cython extension")
class TestChildProcessErrors(unittest.TestCase):
    """Tests for error handling."""

    def test_unknown_pid_raises(self):
        from pydbg import Debugger
        from pydbg.exceptions import ProcessError
        dbg = Debugger()
        with self.assertRaises(ProcessError):
            dbg.read_memory(0x1000, 4, pid=999999)

    def test_default_no_children(self):
        """Default behavior: no child tracking."""
        from pydbg import Debugger
        dbg = Debugger()
        self.assertFalse(dbg._session.debug_children)
        self.assertEqual(dbg._session.child_processes, {})


if __name__ == "__main__":
    unittest.main()
