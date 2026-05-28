"""Tests for memory operations: read, write, query, modules."""

import unittest

from tests import TEST_TARGET_PATH

try:
    from pydbg import _pydbg

    _has_cython = True
except ImportError:
    _has_cython = False


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


if __name__ == "__main__":
    unittest.main()
