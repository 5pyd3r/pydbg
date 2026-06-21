"""Execution tracing engine with single-step and sampling modes."""

import json
from dataclasses import dataclass, field


@dataclass
class TraceEvent:
    """A single execution trace event."""
    index: int
    timestamp: int
    tid: int
    type: str           # "insn", "call", "ret", "jmp", "mem_read", "mem_write"
    address: int
    mnemonic: str
    op_str: str
    raw_bytes: bytes = b''
    registers: dict = field(default_factory=dict)
    memory_access: tuple = None  # (addr, size, value)
    call_target: int = None


class ExecutionTracer:
    """Execution trace engine with filtering and export."""

    def __init__(self, session):
        self._s = session
        self._events = []
        self._record_regs = False
        self._record_memory = False
        self._max_events = 1_000_000
        self._running = False
        self._next_index = 0
        self._filters = {'modules': [], 'functions': [], 'skip_ranges': []}

    def configure(self, record_regs=False, record_memory=False, max_events=1_000_000):
        """Configure tracing options."""
        self._record_regs = record_regs
        self._record_memory = record_memory
        self._max_events = max_events

    def add_module_filter(self, module_name):
        """Add a module name filter (case-insensitive)."""
        if module_name not in self._filters['modules']:
            self._filters['modules'].append(module_name)

    def add_function_filter(self, start_addr, size):
        """Add a function address range filter."""
        self._filters['functions'].append((start_addr, size))

    def add_skip_range(self, start_addr, size):
        """Add an address range to skip during tracing."""
        self._filters['skip_ranges'].append((start_addr, size))

    def record_event(self, event):
        """Record a trace event, assigning sequential index."""
        event.index = self._next_index
        self._next_index += 1
        self._events.append(event)
        # Enforce ring buffer limit
        if len(self._events) > self._max_events:
            self._events = self._events[-self._max_events:]

    def get_events(self, start=None, end=None):
        """Return recorded events, optionally filtered by index range [start, end)."""
        if start is None and end is None:
            return list(self._events)
        return [e for e in self._events
                if (start is None or e.index >= start) and
                   (end is None or e.index < end)]

    def search_memory_access(self, addr):
        """Find all events that touch the given memory address."""
        results = []
        for event in self._events:
            if event.memory_access is not None:
                mem_addr, mem_size, _ = event.memory_access
                if mem_addr <= addr < mem_addr + mem_size:
                    results.append(event)
        return results

    def get_execution_heatmap(self):
        """Return a dict mapping address -> hit count."""
        heatmap = {}
        for event in self._events:
            heatmap[event.address] = heatmap.get(event.address, 0) + 1
        return heatmap

    def clear(self):
        """Clear all recorded events and reset index."""
        self._events.clear()
        self._next_index = 0

    def start(self):
        """Start tracing."""
        self._running = True

    def stop(self):
        """Stop tracing."""
        self._running = False

    def export_json(self, path):
        """Export trace events to a JSON file."""
        data = []
        for event in self._events:
            d = {
                'index': event.index,
                'timestamp': event.timestamp,
                'tid': event.tid,
                'type': event.type,
                'address': hex(event.address),
                'mnemonic': event.mnemonic,
                'op_str': event.op_str,
                'raw_bytes': event.raw_bytes.hex() if event.raw_bytes else '',
                'registers': event.registers,
                'memory_access': list(event.memory_access) if event.memory_access else None,
                'call_target': hex(event.call_target) if event.call_target else None,
            }
            data.append(d)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
