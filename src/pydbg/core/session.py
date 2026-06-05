"""DebugSession — pure state holder for the debugger session."""

import struct
from dataclasses import dataclass, field


@dataclass
class DebugSession:
    """Holds debug session state. No logic — pure data."""

    process_handle: int | None = None
    thread_handle: int | None = None
    pid: int | None = None
    tid: int | None = None
    host_arch: int = struct.calcsize("P") * 8  # 32 or 64
    target_arch: int = struct.calcsize("P") * 8  # 32 or 64, auto-detected
    bp_counter: int = 0
    breakpoints: dict = field(default_factory=dict)  # id -> (type, addr, extra)
    # Breakpoint lifecycle: tid -> (bp_id, addr, original_bytes)
    # Tracks breakpoints that have been hit and are pending single-step + restore
    pending_single_step: dict = field(default_factory=dict)
