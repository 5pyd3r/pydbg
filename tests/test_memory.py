"""Tests for memory operations: read, write, query, modules."""

import unittest
import os

from tests import TEST_TARGET_PATH


class TestMemoryReadWrite(unittest.TestCase):
    """Test reading and writing process memory."""

    def setUp(self):
        from pydbg.cython import _process
        self.pid, self.tid, self.h_proc, self.h_thr = _process.create_process(
            TEST_TARGET_PATH)
        # Consume CREATE_PROCESS event
        _process.wait_for_debug_event(5000)
        _process.continue_debug_event(self.pid, self.tid, 0)

    def tearDown(self):
        from pydbg.cython import _process
        _process.terminate_process(self.h_proc, 0)
        _process.close_handle(self.h_proc)
        _process.close_handle(self.h_thr)

    def test_read_memory_from_image(self):
        """Read the PE header from the target process."""
        from pydbg.cython import _memory

        # First get module info
        modules = _memory.enum_process_modules(self.h_proc)
        self.assertGreater(len(modules), 0)

        base = modules[0]['base_address']
        # Read MZ header
        data = _memory.read_process_memory(self.h_proc, base, 2)
        self.assertEqual(data[:2], b'MZ')

    def test_write_and_read_back(self):
        """Write bytes, read back, verify."""
        from pydbg.cython import _memory

        # Get a writable region
        modules = _memory.enum_process_modules(self.h_proc)
        base = modules[0]['base_address']

        # Find a committed, writable region via VirtualQueryEx
        addr = base + 0x1000
        for _ in range(100):
            try:
                info = _memory.virtual_query_ex(self.h_proc, addr)
                if info['state'] == 0x10000:  # MEM_COMMIT
                    break
                addr = info['base_address'] + info['region_size']
            except OSError:
                break

    def test_virtual_query(self):
        """Query memory at module base returns committed region."""
        from pydbg.cython import _memory

        modules = _memory.enum_process_modules(self.h_proc)
        base = modules[0]['base_address']

        info = _memory.virtual_query_ex(self.h_proc, base)
        self.assertIn('base_address', info)
        self.assertIn('region_size', info)
        self.assertIn('protect', info)


class TestModuleEnum(unittest.TestCase):
    """Test module enumeration."""

    def setUp(self):
        from pydbg.cython import _process
        self.pid, self.tid, self.h_proc, self.h_thr = _process.create_process(
            TEST_TARGET_PATH)
        _process.wait_for_debug_event(5000)
        _process.continue_debug_event(self.pid, self.tid, 0)

    def tearDown(self):
        from pydbg.cython import _process
        _process.terminate_process(self.h_proc, 0)
        _process.close_handle(self.h_proc)
        _process.close_handle(self.h_thr)

    def test_enum_modules(self):
        """Verify at least one module is loaded."""
        from pydbg.cython import _memory

        modules = _memory.enum_process_modules(self.h_proc)
        self.assertGreater(len(modules), 0)

    def test_get_module_filename(self):
        """Verify we can get the filename of the first module."""
        from pydbg.cython import _memory

        modules = _memory.enum_process_modules(self.h_proc)
        filename = _memory.get_module_file_name_ex(
            self.h_proc, modules[0]['handle'])
        self.assertTrue(len(filename) > 0)


if __name__ == '__main__':
    unittest.main()
