import json
import os
import tempfile
import unittest

from pydbg.trace.execution import ExecutionTracer, TraceEvent


class TestTraceEvent(unittest.TestCase):

    def test_dataclass_defaults(self):
        ev = TraceEvent(
            index=0, timestamp=1234, tid=1,
            type="insn", address=0x401000, mnemonic="nop", op_str=""
        )
        self.assertEqual(ev.index, 0)
        self.assertEqual(ev.timestamp, 1234)
        self.assertEqual(ev.tid, 1)
        self.assertEqual(ev.type, "insn")
        self.assertEqual(ev.address, 0x401000)
        self.assertEqual(ev.mnemonic, "nop")
        self.assertEqual(ev.op_str, "")
        self.assertEqual(ev.raw_bytes, b'')
        self.assertEqual(ev.registers, {})
        self.assertIsNone(ev.memory_access)
        self.assertIsNone(ev.call_target)

    def test_dataclass_all_fields(self):
        regs = {'eax': 1, 'ebx': 2}
        ev = TraceEvent(
            index=5, timestamp=9999, tid=2,
            type="mem_read", address=0x7FFE0000, mnemonic="mov", op_str="eax, [ebx]",
            raw_bytes=b'\x8b\x03', registers=regs,
            memory_access=(0x7FFE0000, 4, 0x12345678), call_target=None
        )
        self.assertEqual(ev.index, 5)
        self.assertEqual(ev.registers, regs)
        self.assertEqual(ev.memory_access, (0x7FFE0000, 4, 0x12345678))


class TestExecutionTracerInit(unittest.TestCase):

    def test_init_defaults(self):
        tracer = ExecutionTracer(session=None)
        self.assertEqual(tracer._max_events, 1_000_000)
        self.assertFalse(tracer._record_regs)
        self.assertFalse(tracer._record_memory)
        self.assertFalse(tracer._running)
        self.assertEqual(tracer._next_index, 0)
        self.assertEqual(tracer._events, [])
        self.assertEqual(tracer._filters['modules'], [])
        self.assertEqual(tracer._filters['functions'], [])
        self.assertEqual(tracer._filters['skip_ranges'], [])


class TestExecutionTracerConfigure(unittest.TestCase):

    def test_configure(self):
        tracer = ExecutionTracer(session=None)
        tracer.configure(record_regs=True, record_memory=True, max_events=500)
        self.assertTrue(tracer._record_regs)
        self.assertTrue(tracer._record_memory)
        self.assertEqual(tracer._max_events, 500)


class TestExecutionTracerFilters(unittest.TestCase):

    def test_add_module_filter(self):
        tracer = ExecutionTracer(session=None)
        tracer.add_module_filter("kernel32.dll")
        tracer.add_module_filter("ntdll.dll")
        self.assertEqual(tracer._filters['modules'], ["kernel32.dll", "ntdll.dll"])

    def test_add_module_filter_no_duplicates(self):
        tracer = ExecutionTracer(session=None)
        tracer.add_module_filter("kernel32.dll")
        tracer.add_module_filter("kernel32.dll")
        self.assertEqual(tracer._filters['modules'].count("kernel32.dll"), 1)

    def test_add_function_filter(self):
        tracer = ExecutionTracer(session=None)
        tracer.add_function_filter(0x1000, 0x100)
        self.assertEqual(tracer._filters['functions'], [(0x1000, 0x100)])

    def test_add_skip_range(self):
        tracer = ExecutionTracer(session=None)
        tracer.add_skip_range(0x7FFE0000, 0x1000)
        self.assertEqual(tracer._filters['skip_ranges'], [(0x7FFE0000, 0x1000)])


class TestExecutionTracerRecordEvent(unittest.TestCase):

    def test_record_event_manually(self):
        tracer = ExecutionTracer(session=None)
        ev = TraceEvent(
            index=0, timestamp=100, tid=1,
            type="insn", address=0x401000, mnemonic="nop", op_str=""
        )
        tracer.record_event(ev)
        self.assertEqual(len(tracer._events), 1)
        # index is overwritten by record_event
        self.assertEqual(tracer._events[0].index, 0)
        self.assertEqual(tracer._next_index, 1)

    def test_record_assigns_sequential_indices(self):
        tracer = ExecutionTracer(session=None)
        for i in range(5):
            ev = TraceEvent(
                index=0, timestamp=100 + i, tid=1,
                type="insn", address=0x401000 + i, mnemonic="nop", op_str=""
            )
            tracer.record_event(ev)
        indices = [e.index for e in tracer._events]
        self.assertEqual(indices, [0, 1, 2, 3, 4])

    def test_max_events_ring_buffer(self):
        tracer = ExecutionTracer(session=None)
        tracer.configure(max_events=3)
        for i in range(5):
            ev = TraceEvent(
                index=0, timestamp=100 + i, tid=1,
                type="insn", address=0x401000 + i, mnemonic="nop", op_str=""
            )
            tracer.record_event(ev)
        # Only the last 3 events should remain
        self.assertEqual(len(tracer._events), 3)
        # Their indices should still be sequential (3, 4)
        addresses = [e.address for e in tracer._events]
        self.assertEqual(addresses, [0x401002, 0x401003, 0x401004])


class TestExecutionTracerQuery(unittest.TestCase):

    def _make_tracer_with_events(self, count=10):
        tracer = ExecutionTracer(session=None)
        for i in range(count):
            ev = TraceEvent(
                index=0, timestamp=1000 + i, tid=1,
                type="insn", address=0x401000 + i * 0x10, mnemonic="nop", op_str=""
            )
            tracer.record_event(ev)
        return tracer

    def test_get_events_all(self):
        tracer = self._make_tracer_with_events(5)
        events = tracer.get_events()
        self.assertEqual(len(events), 5)

    def test_get_events_range(self):
        tracer = self._make_tracer_with_events(10)
        events = tracer.get_events(start=3, end=7)
        self.assertTrue(all(3 <= e.index < 7 for e in events))
        self.assertEqual(len(events), 4)

    def test_search_memory_access(self):
        tracer = ExecutionTracer(session=None)
        # Event with memory access at 0x7FFE0000, size 4
        ev1 = TraceEvent(
            index=0, timestamp=100, tid=1,
            type="mem_read", address=0x401000, mnemonic="mov", op_str="eax, [0x7FFE0000]",
            memory_access=(0x7FFE0000, 4, 0x12345678)
        )
        # Event with memory access at 0x7FFE0010, size 4
        ev2 = TraceEvent(
            index=0, timestamp=101, tid=1,
            type="mem_write", address=0x401010, mnemonic="mov", op_str="[0x7FFE0010], eax",
            memory_access=(0x7FFE0010, 4, 0xAABBCCDD)
        )
        # Event without memory access
        ev3 = TraceEvent(
            index=0, timestamp=102, tid=1,
            type="insn", address=0x401020, mnemonic="nop", op_str=""
        )
        tracer.record_event(ev1)
        tracer.record_event(ev2)
        tracer.record_event(ev3)

        # Search for address inside ev1's range
        results = tracer.search_memory_access(0x7FFE0002)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].type, "mem_read")

        # Search for address inside ev2's range
        results = tracer.search_memory_access(0x7FFE0013)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].type, "mem_write")

        # Search for address not in any range
        results = tracer.search_memory_access(0xDEADBEEF)
        self.assertEqual(len(results), 0)

    def test_get_execution_heatmap(self):
        tracer = ExecutionTracer(session=None)
        addresses = [0x401000, 0x401000, 0x401000, 0x401010, 0x401020, 0x401020]
        for i, addr in enumerate(addresses):
            ev = TraceEvent(
                index=0, timestamp=1000 + i, tid=1,
                type="insn", address=addr, mnemonic="nop", op_str=""
            )
            tracer.record_event(ev)

        heatmap = tracer.get_execution_heatmap()
        self.assertEqual(heatmap[0x401000], 3)
        self.assertEqual(heatmap[0x401010], 1)
        self.assertEqual(heatmap[0x401020], 2)

    def test_clear(self):
        tracer = self._make_tracer_with_events(5)
        tracer.clear()
        self.assertEqual(len(tracer._events), 0)
        self.assertEqual(tracer._next_index, 0)


class TestExecutionTracerExport(unittest.TestCase):

    def test_export_json(self):
        tracer = ExecutionTracer(session=None)
        ev = TraceEvent(
            index=0, timestamp=12345, tid=1,
            type="call", address=0x401000, mnemonic="call", op_str="0x402000",
            raw_bytes=b'\xe8\xfb\x0f\x00\x00',
            registers={'eax': 0},
            call_target=0x402000
        )
        tracer.record_event(ev)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            path = f.name

        try:
            tracer.export_json(path)
            with open(path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)

            self.assertEqual(len(data), 1)
            self.assertEqual(data[0]['type'], 'call')
            self.assertEqual(data[0]['address'], '0x401000')
            self.assertEqual(data[0]['call_target'], '0x402000')
            self.assertEqual(data[0]['raw_bytes'], 'e8fb0f0000')
            self.assertEqual(data[0]['registers'], {'eax': 0})
        finally:
            os.unlink(path)

    def test_export_json_memory_access(self):
        tracer = ExecutionTracer(session=None)
        ev = TraceEvent(
            index=0, timestamp=99, tid=2,
            type="mem_read", address=0x401000, mnemonic="mov", op_str="eax, [ebx]",
            memory_access=(0x7FFE0000, 4, 0x12345678)
        )
        tracer.record_event(ev)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            path = f.name

        try:
            tracer.export_json(path)
            with open(path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)

            self.assertEqual(data[0]['memory_access'], [0x7FFE0000, 4, 0x12345678])
        finally:
            os.unlink(path)


class TestExecutionTracerLifecycle(unittest.TestCase):

    def test_start_stop(self):
        tracer = ExecutionTracer(session=None)
        self.assertFalse(tracer._running)
        tracer.start()
        self.assertTrue(tracer._running)
        tracer.stop()
        self.assertFalse(tracer._running)


class TestDataFlowTracker(unittest.TestCase):

    def test_init(self):
        from pydbg.core.session import DebugSession
        from pydbg.trace.dataflow import DataFlowTracker
        tracer = ExecutionTracer(DebugSession())
        dft = DataFlowTracker(tracer)
        self.assertIsNotNone(dft)

    def test_track_register_value_propagation(self):
        from pydbg.core.session import DebugSession
        from pydbg.trace.dataflow import DataFlowTracker
        tracer = ExecutionTracer(DebugSession())
        # Simulate: eax = 5 at 0x401000, then eax used at 0x401005
        tracer.record_event(TraceEvent(
            index=0, timestamp=100, tid=1, type="insn",
            address=0x401000, mnemonic="mov", op_str="eax, 5",
            raw_bytes=b'', registers={'eax': 5, 'ebx': 0},
            memory_access=None, call_target=None,
        ))
        tracer.record_event(TraceEvent(
            index=0, timestamp=200, tid=1, type="insn",
            address=0x401005, mnemonic="add", op_str="eax, ebx",
            raw_bytes=b'', registers={'eax': 5, 'ebx': 3},
            memory_access=None, call_target=None,
        ))
        dft = DataFlowTracker(tracer)
        # Find where eax=5 was written
        writes = dft.find_register_writes('eax', 5)
        self.assertEqual(len(writes), 2)  # both events have eax=5
        self.assertEqual(writes[0].address, 0x401000)

    def test_find_register_writes_empty(self):
        from pydbg.core.session import DebugSession
        from pydbg.trace.dataflow import DataFlowTracker
        tracer = ExecutionTracer(DebugSession())
        dft = DataFlowTracker(tracer)
        writes = dft.find_register_writes('eax', 999)
        self.assertEqual(writes, [])

    def test_find_register_readers(self):
        from pydbg.core.session import DebugSession
        from pydbg.trace.dataflow import DataFlowTracker
        tracer = ExecutionTracer(DebugSession())
        tracer.record_event(TraceEvent(
            index=0, timestamp=100, tid=1, type="insn",
            address=0x401000, mnemonic="mov", op_str="eax, 5",
            raw_bytes=b'', registers={'eax': 5},
        ))
        tracer.record_event(TraceEvent(
            index=0, timestamp=200, tid=1, type="insn",
            address=0x401005, mnemonic="add", op_str="eax, ebx",
            raw_bytes=b'', registers={'eax': 5, 'ebx': 3},
        ))
        tracer.record_event(TraceEvent(
            index=0, timestamp=300, tid=1, type="insn",
            address=0x401010, mnemonic="nop", op_str="",
            raw_bytes=b'',
        ))
        dft = DataFlowTracker(tracer)
        readers = dft.find_register_readers('eax', after_index=0)
        # Event 0 has "eax" in op_str but index <= after_index=0, so skipped
        # Event 1 has "eax" in op_str and index > 0
        # Event 2 has no "eax" in op_str
        self.assertEqual(len(readers), 1)
        self.assertEqual(readers[0].index, 1)

    def test_find_origin(self):
        from pydbg.core.session import DebugSession
        from pydbg.trace.dataflow import DataFlowTracker
        tracer = ExecutionTracer(DebugSession())
        tracer.record_event(TraceEvent(
            index=0, timestamp=100, tid=1, type="insn",
            address=0x401000, mnemonic="mov", op_str="eax, 42",
            raw_bytes=b'', registers={'eax': 42},
        ))
        tracer.record_event(TraceEvent(
            index=0, timestamp=200, tid=1, type="insn",
            address=0x401005, mnemonic="nop", op_str="",
            raw_bytes=b'', registers={'eax': 42},
        ))
        tracer.record_event(TraceEvent(
            index=0, timestamp=300, tid=1, type="insn",
            address=0x401010, mnemonic="add", op_str="eax, 1",
            raw_bytes=b'', registers={'eax': 42},
        ))
        dft = DataFlowTracker(tracer)
        origin = dft.find_origin(2, 'eax')
        self.assertIsNotNone(origin)
        self.assertEqual(origin.index, 1)  # last write before index 2

    def test_track_memory_writers(self):
        from pydbg.core.session import DebugSession
        from pydbg.trace.dataflow import DataFlowTracker
        tracer = ExecutionTracer(DebugSession())
        tracer.record_event(TraceEvent(
            index=0, timestamp=100, tid=1, type="mem_write",
            address=0x401000, mnemonic="mov", op_str="[0x500000], eax",
            memory_access=(0x500000, 4, 0x42),
        ))
        tracer.record_event(TraceEvent(
            index=0, timestamp=200, tid=1, type="insn",
            address=0x401005, mnemonic="nop", op_str="",
        ))
        dft = DataFlowTracker(tracer)
        writers = dft.track_memory_writers(0x500000)
        self.assertEqual(len(writers), 1)

    def test_track_memory_readers(self):
        from pydbg.core.session import DebugSession
        from pydbg.trace.dataflow import DataFlowTracker
        tracer = ExecutionTracer(DebugSession())
        tracer.record_event(TraceEvent(
            index=0, timestamp=100, tid=1, type="mem_read",
            address=0x401000, mnemonic="mov", op_str="eax, [0x500000]",
            memory_access=(0x500000, 4, 0x42),
        ))
        dft = DataFlowTracker(tracer)
        readers = dft.track_memory_readers(0x500000)
        self.assertEqual(len(readers), 1)

    def test_find_origin_no_registers(self):
        from pydbg.core.session import DebugSession
        from pydbg.trace.dataflow import DataFlowTracker
        tracer = ExecutionTracer(DebugSession())
        tracer.record_event(TraceEvent(
            index=0, timestamp=100, tid=1, type="insn",
            address=0x401000, mnemonic="nop", op_str="",
        ))
        dft = DataFlowTracker(tracer)
        origin = dft.find_origin(0, 'eax')
        self.assertIsNone(origin)


class TestAddSkipRangeExtended(unittest.TestCase):
    """Extended tests for ExecutionTracer.add_skip_range()."""

    def test_add_skip_range_stores_tuple(self):
        """add_skip_range stores (start_addr, size) tuple."""
        tracer = ExecutionTracer(session=None)
        tracer.add_skip_range(0x7FFE0000, 0x1000)
        self.assertEqual(len(tracer._filters['skip_ranges']), 1)
        self.assertEqual(tracer._filters['skip_ranges'][0],
                         (0x7FFE0000, 0x1000))

    def test_add_multiple_skip_ranges(self):
        """Multiple skip ranges are accumulated."""
        tracer = ExecutionTracer(session=None)
        tracer.add_skip_range(0x7FFE0000, 0x1000)
        tracer.add_skip_range(0x7FFF0000, 0x1000)
        self.assertEqual(len(tracer._filters['skip_ranges']), 2)


class TestTracerClearExtended(unittest.TestCase):
    """Extended tests for ExecutionTracer.clear()."""

    def test_clear_empties_events(self):
        """clear() removes all events and resets index."""
        tracer = ExecutionTracer(session=None)
        for i in range(5):
            tracer.record_event(TraceEvent(
                index=i, timestamp=i * 100, tid=1, type="insn",
                address=0x401000 + i, mnemonic="nop", op_str="",
                raw_bytes=b'\x90', registers={},
                memory_access=None, call_target=None,
            ))
        self.assertEqual(len(tracer.get_events()), 5)

        tracer.clear()
        self.assertEqual(len(tracer.get_events()), 0)
        self.assertEqual(tracer._next_index, 0)

    def test_clear_idempotent(self):
        """clear() can be called multiple times safely."""
        tracer = ExecutionTracer(session=None)
        tracer.clear()
        tracer.clear()
        self.assertEqual(len(tracer.get_events()), 0)


class TestFindRegisterReadersExtended(unittest.TestCase):
    """Extended tests for DataFlowTracker.find_register_readers()."""

    def test_finds_events_with_register_in_op_str(self):
        """Finds events that reference the register in op_str."""
        from pydbg.core.session import DebugSession
        from pydbg.trace.dataflow import DataFlowTracker

        tracer = ExecutionTracer(DebugSession())
        tracer._events.append(TraceEvent(
            index=0, timestamp=100, tid=1, type="insn",
            address=0x401000, mnemonic="mov", op_str="eax, 5",
            raw_bytes=b'', registers={'eax': 5},
            memory_access=None, call_target=None,
        ))
        tracer._events.append(TraceEvent(
            index=1, timestamp=200, tid=1, type="insn",
            address=0x401005, mnemonic="add", op_str="eax, ebx",
            raw_bytes=b'', registers={'eax': 5, 'ebx': 3},
            memory_access=None, call_target=None,
        ))
        tracer._events.append(TraceEvent(
            index=2, timestamp=300, tid=1, type="insn",
            address=0x401008, mnemonic="mov", op_str="ecx, edx",
            raw_bytes=b'', registers={'ecx': 0, 'edx': 0},
            memory_access=None, call_target=None,
        ))
        tracer._next_index = 3

        dft = DataFlowTracker(tracer)
        # Use after_index=-1 to include all events (default 0 skips index 0)
        readers = dft.find_register_readers('eax', after_index=-1)
        # Both events 0 and 1 reference 'eax' in op_str
        self.assertEqual(len(readers), 2)

    def test_find_register_readers_after_index(self):
        """Only returns events after the given index."""
        from pydbg.core.session import DebugSession
        from pydbg.trace.dataflow import DataFlowTracker

        tracer = ExecutionTracer(DebugSession())
        tracer._events.append(TraceEvent(
            index=0, timestamp=100, tid=1, type="insn",
            address=0x401000, mnemonic="mov", op_str="eax, 5",
            raw_bytes=b'', registers={'eax': 5},
            memory_access=None, call_target=None,
        ))
        tracer._events.append(TraceEvent(
            index=1, timestamp=200, tid=1, type="insn",
            address=0x401005, mnemonic="add", op_str="eax, ebx",
            raw_bytes=b'', registers={'eax': 8, 'ebx': 3},
            memory_access=None, call_target=None,
        ))
        tracer._next_index = 2

        dft = DataFlowTracker(tracer)
        readers = dft.find_register_readers('eax', after_index=0)
        # Only event 1 is after index 0
        self.assertEqual(len(readers), 1)
        self.assertEqual(readers[0].index, 1)

    def test_find_register_readers_empty(self):
        """Returns empty list when no events reference the register."""
        from pydbg.core.session import DebugSession
        from pydbg.trace.dataflow import DataFlowTracker

        tracer = ExecutionTracer(DebugSession())
        tracer._events.append(TraceEvent(
            index=0, timestamp=100, tid=1, type="insn",
            address=0x401000, mnemonic="nop", op_str="",
            raw_bytes=b'', registers={},
            memory_access=None, call_target=None,
        ))
        tracer._next_index = 1

        dft = DataFlowTracker(tracer)
        readers = dft.find_register_readers('eax', after_index=-1)
        self.assertEqual(readers, [])


if __name__ == '__main__':
    unittest.main()
