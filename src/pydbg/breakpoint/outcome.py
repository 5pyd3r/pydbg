"""HandleOutcome — what the debugger actually did with one exception event."""

from enum import Enum


class HandleOutcome(Enum):
    """The answer to "what did the lifecycle do with this event".

    It replaces a bool plus a side-channel counter. A bool cannot say "handled,
    but badly", so callers compared `degraded_hits` before and after to find
    out whether a hit went wrong — and the manual path simply never did.

    A degraded hit is neither success nor failure: the breakpoint has been
    re-armed, but the thread was left with its instruction pointer mid-
    instruction, so the caller must not continue as if nothing happened.
    """

    NOT_MINE = "not_mine"   # not about a breakpoint we own: deliver normally
    HANDLED = "handled"     # INT3 out, IP rewound, a single-step will re-arm
    DEGRADED = "degraded"   # ours, but the thread could not be prepared
