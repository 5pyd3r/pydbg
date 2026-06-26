import unittest


class TestMemoryChange(unittest.TestCase):
    def test_dataclass(self):
        from pydbg.memory.monitor import MemoryChange
        mc = MemoryChange(address=0x40EFC0, old_value=b'\x00\x00\x00\x00',
                          new_value=b'\x01\x00\x00\x00', timestamp=1000)
        self.assertEqual(mc.address, 0x40EFC0)


class TestWatchpoint(unittest.TestCase):
    def test_dataclass(self):
        from pydbg.memory.monitor import Watchpoint
        wp = Watchpoint(addr=0x40EFC0, size=4, fmt='<I', name='InitFlag')
        self.assertEqual(wp.addr, 0x40EFC0)
        self.assertIsNone(wp.last_value)


class TestMemoryMonitor(unittest.TestCase):
    def test_init(self):
        from pydbg.core.session import DebugSession
        from pydbg.memory.monitor import MemoryMonitor
        monitor = MemoryMonitor(DebugSession())
        self.assertEqual(len(monitor._watchpoints), 0)

    def test_watch_adds_watchpoint(self):
        from pydbg.core.session import DebugSession
        from pydbg.memory.monitor import MemoryMonitor
        monitor = MemoryMonitor(DebugSession())
        monitor.watch(0x40EFC0, size=4, fmt='<I', name='InitFlag')
        self.assertIn(0x40EFC0, monitor._watchpoints)
        self.assertEqual(monitor._watchpoints[0x40EFC0].name, 'InitFlag')

    def test_unwatch_removes_watchpoint(self):
        from pydbg.core.session import DebugSession
        from pydbg.memory.monitor import MemoryMonitor
        monitor = MemoryMonitor(DebugSession())
        monitor.watch(0x40EFC0)
        monitor.unwatch(0x40EFC0)
        self.assertNotIn(0x40EFC0, monitor._watchpoints)

    def test_poll_detects_change(self):
        from pydbg.core.session import DebugSession
        from pydbg.memory.monitor import MemoryMonitor
        monitor = MemoryMonitor(DebugSession())
        read_values = [b'\x00\x00\x00\x00', b'\x01\x00\x00\x00']
        read_index = [0]
        def mock_read(addr, size):
            val = read_values[read_index[0]]
            read_index[0] += 1
            return val
        monitor._read_memory = mock_read
        monitor.watch(0x40EFC0)
        changes = monitor.poll()
        self.assertEqual(len(changes), 0)
        changes = monitor.poll()
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].old_value, b'\x00\x00\x00\x00')
        self.assertEqual(changes[0].new_value, b'\x01\x00\x00\x00')

    def test_poll_no_change(self):
        from pydbg.core.session import DebugSession
        from pydbg.memory.monitor import MemoryMonitor
        monitor = MemoryMonitor(DebugSession())
        read_values = [b'\x00\x00\x00\x00', b'\x00\x00\x00\x00']
        read_index = [0]
        def mock_read(addr, size):
            val = read_values[read_index[0]]
            read_index[0] += 1
            return val
        monitor._read_memory = mock_read
        monitor.watch(0x40EFC0)
        monitor.poll()
        changes = monitor.poll()
        self.assertEqual(len(changes), 0)

    def test_get_snapshot(self):
        from pydbg.core.session import DebugSession
        from pydbg.memory.monitor import MemoryMonitor
        monitor = MemoryMonitor(DebugSession())
        def mock_read(addr, size):
            return b'\x05\x00\x00\x00'
        monitor._read_memory = mock_read
        monitor.watch(0x40EFC0)
        monitor.poll()
        snapshot = monitor.get_snapshot()
        self.assertIn(0x40EFC0, snapshot)

    def test_get_changes_filter(self):
        from pydbg.core.session import DebugSession
        from pydbg.memory.monitor import MemoryMonitor
        monitor = MemoryMonitor(DebugSession())
        read_values = [
            b'\x00\x00\x00\x00', b'\x00\x00\x00\x00',
            b'\x01\x00\x00\x00', b'\x00\x00\x00\x00',
        ]
        read_index = [0]
        def mock_read(addr, size):
            val = read_values[read_index[0]]
            read_index[0] += 1
            return val
        monitor._read_memory = mock_read
        monitor.watch(0x40EFC0)
        monitor.watch(0x40EFF0)
        monitor.poll()
        monitor.poll()
        self.assertEqual(len(monitor.get_changes()), 1)
        self.assertEqual(len(monitor.get_changes(addr=0x40EFC0)), 1)
        self.assertEqual(len(monitor.get_changes(addr=0x40EFF0)), 0)

    def test_clear_history(self):
        from pydbg.core.session import DebugSession
        from pydbg.memory.monitor import MemoryMonitor
        monitor = MemoryMonitor(DebugSession())
        monitor._changes.append(None)
        monitor.clear_history()
        self.assertEqual(len(monitor._changes), 0)
