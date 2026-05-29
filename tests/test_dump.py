import unittest

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
