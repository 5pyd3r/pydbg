"""DebugSession — pure state holder for the debugger session."""

import struct
from dataclasses import dataclass, field


@dataclass
class ChildProcessInfo:
    """Info about a child process being debugged."""
    pid: int
    tid: int                    # 主线程 ID
    process_handle: int         # OpenProcess 返回的句柄
    thread_handle: int          # 主线程句柄
    base_of_image: int = 0      # 加载基址
    exit_code: int | None = None  # 退出后填入


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
    pending_single_step: dict = field(default_factory=dict)

    # Child process debugging
    debug_children: bool = False
    child_processes: dict = field(default_factory=dict)  # pid -> ChildProcessInfo
