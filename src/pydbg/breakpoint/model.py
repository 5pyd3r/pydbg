"""Breakpoint — the one record both kinds of breakpoint are stored as."""

from dataclasses import dataclass


@dataclass
class Breakpoint:
    """One breakpoint, software or hardware.

    The two kinds used to be tuples of different shapes: four fields for an
    INT3, six for a hardware one, read by position. `bp_info[3]` therefore
    meant "process handle" in one manager and "thread scope" in the other, and
    nothing in the type said which. Fields that do not apply to a kind stay
    None, so an INT3 can never be read as if it had a DR slot.

    Stored in DebugSession.breakpoints, keyed by bp_id.
    """

    kind: str                       # "int3" | "hw"
    addr: int
    # Which process it was armed in (None = the main target). Addresses are
    # process-local; a child and its parent can each hold one at 0x401000.
    pid: int | None = None
    # INT3 only: the byte this displaced, and the process handle it was armed
    # through.
    original: bytes | None = None
    h_process: int | None = None
    # Hardware only: the DR slot, the thread it is scoped to (None = every
    # thread of the process), and the condition/length it was armed with.
    slot: int | None = None
    scope: int | None = None
    condition: str | None = None
    length: int | None = None
    # Times delivered to us since it was armed. 0 is a real answer — armed and
    # never reached — which is why the entry exists from the start.
    hits: int = 0
