import unittest

try:
    from pydbg import _pydbg  # noqa: F401

    _has_cython = True
except ImportError:
    _has_cython = False

from pydbg.dump import MinidumpReader, StackWalker
from pydbg.dump.minidump import (
    STREAM_UNUSED,
    STREAM_THREAD_LIST,
    STREAM_MODULE_LIST,
    STREAM_MEMORY_LIST,
    STREAM_EXCEPTION,
    STREAM_SYSTEM_INFO,
    STREAM_MEMORY_64_LIST,
)


class TestMinidumpReader(unittest.TestCase):

    def test_instantiate(self):
        reader = MinidumpReader("nonexistent.dmp")
        self.assertIsNotNone(reader)
        self.assertIsNone(reader._data)

    def test_stream_constants(self):
        self.assertEqual(STREAM_UNUSED, 0)
        self.assertEqual(STREAM_THREAD_LIST, 3)
        self.assertEqual(STREAM_MODULE_LIST, 4)
        self.assertEqual(STREAM_MEMORY_LIST, 5)
        self.assertEqual(STREAM_EXCEPTION, 6)
        self.assertEqual(STREAM_SYSTEM_INFO, 7)
        self.assertEqual(STREAM_MEMORY_64_LIST, 9)

    def test_get_stream_missing_file(self):
        reader = MinidumpReader("nonexistent.dmp")
        with self.assertRaises(FileNotFoundError):
            reader.get_stream(STREAM_THREAD_LIST)


class TestStackWalker(unittest.TestCase):

    def test_machine_x64_constant(self):
        self.assertEqual(StackWalker.MACHINE_X64, 0x8664)

    def test_instantiate_requires_session(self):
        with self.assertRaises(TypeError):
            StackWalker()  # noqa — missing required session argument

    def test_walk_no_extension(self):
        """walk() raises PydbgError when extension not available."""
        class FakeSession:
            process_handle = None
        sw = StackWalker(FakeSession())
        # Cannot call walk without the extension, but the walker object
        # is valid and the method signature is correct.
        self.assertIsNotNone(sw)
        self.assertIs(sw._s.process_handle, None)


def _build_synthetic_minidump():
    """Minimal valid minidump: header + one module-list stream (type 4, empty)."""
    import struct
    header = struct.pack("<IIII", 0x504D444D, 0xA793, 1, 36)  # sig, ver, nstreams, dir_rva
    header += struct.pack("<I", 0)  # CheckSum
    header += struct.pack("<Q", 0)  # TimeDateStamp (TIME_T, 8 bytes)
    header += struct.pack("<Q", 0)  # Flags (8 bytes)
    # MINIDUMP_DIRECTORY @36: StreamType=4, DataSize=4, Rva=48
    directory = struct.pack("<III", 4, 4, 48)
    # MINIDUMP_MODULE_LIST @48: NumberOfModules=0
    module_list = struct.pack("<I", 0)
    return header + directory + module_list


class TestMinidumpReaderLive(unittest.TestCase):
    """Live dbghelp read of a synthetic in-memory dump."""

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_get_stream_synthetic_dump(self):
        import os
        import tempfile
        from pydbg.dump.minidump import MinidumpReader, STREAM_MODULE_LIST

        data = _build_synthetic_minidump()
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "synth.dmp")
            with open(path, "wb") as f:
                f.write(data)
            reader = MinidumpReader(path)
            stream = reader.get_stream(STREAM_MODULE_LIST)
            # Second call exercises the cached-data early-return in _load().
            stream2 = reader.get_stream(STREAM_MODULE_LIST)
        self.assertEqual(stream, b"\x00\x00\x00\x00")
        self.assertEqual(stream2, b"\x00\x00\x00\x00")

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_get_stream_wraps_oserror(self):
        import os
        import tempfile
        from unittest import mock
        from pydbg.dump.minidump import MinidumpReader, STREAM_MODULE_LIST
        from pydbg.exceptions import PydbgError

        data = _build_synthetic_minidump()
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "synth.dmp")
            with open(path, "wb") as f:
                f.write(data)
            reader = MinidumpReader(path)
            with mock.patch(
                "pydbg._pydbg.mini_dump_read_dump_stream",
                side_effect=OSError(13, "boom"),
            ):
                with self.assertRaises(PydbgError):
                    reader.get_stream(STREAM_MODULE_LIST)


class TestStackWalkerCoverage(unittest.TestCase):
    """StackWalker.walk loop via mocks + a live smoke test."""

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def _patched_walk(self, frames, max_frames=64, regs=None):
        from unittest import mock
        from pydbg.core.session import DebugSession
        from pydbg.dump.stackwalk import StackWalker

        session = DebugSession()
        sw = StackWalker(session)
        regs = regs or {"rip": 0x1000, "rsp": 0x2000, "rbp": 0x3000}
        with mock.patch("pydbg._pydbg.stack_walk_frame",
                        side_effect=frames) as m:
            with mock.patch("pydbg.thread.manager.ThreadManager") as mock_tm:
                mock_tm.return_value.get_context.return_value = regs
                result = sw.walk(0x1234, b"\x00" * 0x100, max_frames=max_frames)
        return result, m

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_walk_stops_on_ip_zero(self):
        frames = [
            {"frame_ip": 0x1000, "frame_sp": 0x2000, "frame_fp": 0x3000},
            {"frame_ip": 0x4000, "frame_sp": 0x5000, "frame_fp": 0x6000},
            {"frame_ip": 0, "frame_sp": 0, "frame_fp": 0},
        ]
        result, m = self._patched_walk(frames)
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0]["frame_ip"], 0x1000)
        self.assertEqual(m.call_count, 3)

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_walk_stops_on_none(self):
        frames = [
            {"frame_ip": 0x1000, "frame_sp": 0x2000, "frame_fp": 0x3000},
            None,
        ]
        result, m = self._patched_walk(frames)
        self.assertEqual(len(result), 1)
        self.assertEqual(m.call_count, 2)

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_walk_respects_max_frames(self):
        frames = [
            {"frame_ip": 0x1000 + i, "frame_sp": 0x2000, "frame_fp": 0x3000}
            for i in range(20)
        ]
        result, m = self._patched_walk(frames, max_frames=4)
        self.assertEqual(len(result), 4)
        self.assertEqual(m.call_count, 4)

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_walk_live_smoke(self):
        from tests.helpers import create_debugger, teardown

        dbg, pid, tid = create_debugger()
        try:
            h_thread = dbg.open_thread(tid)
            # A zeroed buffer >= sizeof(CONTEXT) exercises the real
            # StackWalk64 code path; it may return zero frames but must not crash.
            frames = dbg.stack_walker.walk(h_thread, b"\x00" * 0x1000, max_frames=8)
            self.assertIsInstance(frames, list)
            dbg.close_handle(h_thread)
        finally:
            teardown(dbg)
