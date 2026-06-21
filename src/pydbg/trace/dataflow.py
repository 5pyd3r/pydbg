"""Data flow analysis over execution traces."""


class DataFlowTracker:
    """Analyze data propagation through registers and memory."""

    def __init__(self, tracer):
        """
        Args:
            tracer: ExecutionTracer instance with recorded events.
        """
        self._tracer = tracer

    def find_register_writes(self, reg_name, value):
        """Find all events where a register was set to a specific value.

        Returns list of TraceEvent where reg_name == value.
        """
        results = []
        for event in self._tracer.get_events():
            if event.registers and event.registers.get(reg_name) == value:
                results.append(event)
        return results

    def find_register_readers(self, reg_name, after_index=0):
        """Find all events after after_index that read from reg_name.

        Note: This is a heuristic -- we check if reg_name appears in op_str.
        """
        results = []
        for event in self._tracer.get_events():
            if event.index <= after_index:
                continue
            if reg_name in event.op_str:
                results.append(event)
        return results

    def track_memory_writers(self, addr, size=4):
        """Find all events that wrote to the specified memory address."""
        results = []
        for event in self._tracer.get_events():
            if event.type == 'mem_write' and event.memory_access is not None:
                mem_addr, mem_size, _ = event.memory_access
                if mem_addr <= addr < mem_addr + mem_size:
                    results.append(event)
        return results

    def track_memory_readers(self, addr, size=4):
        """Find all events that read from the specified memory address."""
        results = []
        for event in self._tracer.get_events():
            if event.type == 'mem_read' and event.memory_access is not None:
                mem_addr, mem_size, _ = event.memory_access
                if mem_addr <= addr < mem_addr + mem_size:
                    results.append(event)
        return results

    def find_origin(self, event_index, reg_name):
        """Backtrack to find the original source of a register value.

        Walks backwards through events to find where reg_name was last written.
        """
        events = self._tracer.get_events()
        target_event = None
        for e in events:
            if e.index == event_index:
                target_event = e
                break
        if target_event is None or target_event.registers is None:
            return None

        value = target_event.registers.get(reg_name)
        if value is None:
            return None

        # Walk backwards to find the write
        for e in reversed(events):
            if e.index >= event_index:
                continue
            if e.registers and e.registers.get(reg_name) == value:
                return e
        return None
