"""MemoryMonitor — periodic memory monitoring for busy-wait games."""

import time
from dataclasses import dataclass

from .. import _pydbg
from ..exceptions import MemError


@dataclass
class MemoryChange:
    """A detected change in monitored memory."""
    address: int
    old_value: bytes
    new_value: bytes
    timestamp: int


@dataclass
class Watchpoint:
    """A monitored memory address."""
    addr: int
    size: int
    fmt: str
    name: str
    last_value: bytes = None


class MemoryMonitor:
    """Periodic memory monitoring for processes with infrequent API calls."""

    def __init__(self, session):
        self._s = session
        self._watchpoints = {}
        self._changes = []

    def watch(self, addr, size=4, fmt='<I', name=None):
        """Add a memory address to monitor."""
        wp = Watchpoint(addr=addr, size=size, fmt=fmt, name=name or hex(addr))
        self._watchpoints[addr] = wp

    def unwatch(self, addr):
        """Remove a memory address from monitoring."""
        self._watchpoints.pop(addr, None)

    def poll(self):
        """Read all watched addresses and detect changes."""
        changes = []
        now = int(time.time() * 1000)

        for addr, wp in self._watchpoints.items():
            try:
                current = self._read_memory(addr, wp.size)
            except (OSError, MemError):
                continue

            if wp.last_value is not None and current != wp.last_value:
                changes.append(MemoryChange(
                    address=addr,
                    old_value=wp.last_value,
                    new_value=current,
                    timestamp=now,
                ))
            wp.last_value = current

        self._changes.extend(changes)
        return changes

    def get_changes(self, addr=None, since=None):
        """Get recorded changes, optionally filtered."""
        result = self._changes
        if addr is not None:
            result = [c for c in result if c.address == addr]
        if since is not None:
            result = [c for c in result if c.timestamp >= since]
        return result

    def get_snapshot(self):
        """Get current values of all watched addresses."""
        return {addr: wp.last_value for addr, wp in self._watchpoints.items()
                if wp.last_value is not None}

    def clear_history(self):
        """Clear all recorded changes."""
        self._changes.clear()

    def _read_memory(self, addr, size):
        """Read process memory. Override in tests for mocking."""
        return _pydbg.read_process_memory(self._s.process_handle, addr, size)
