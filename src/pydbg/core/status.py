"""ExitStatus — why run() returned, and what the exit code was."""

from dataclasses import dataclass
from enum import Enum


class ExitReason(str, Enum):
    """Why the run loop stopped."""

    TARGET_EXITED = "target_exited"
    STOPPED_BY_CALLBACK = "stopped_by_callback"


@dataclass(frozen=True)
class ExitStatus:
    """What run() answers instead of a bare int.

    The old return value was `1` both when the callback asked to stop and when
    the target exited with code 1; nothing about the number could tell the two
    apart, and a caller that only looked at it drew the wrong conclusion.

    exit_code is None when the target is still running (stopped_by_callback),
    because there is no exit code yet — and 0 is a real code, so a sentinel
    would be a lie.
    """

    exit_code: int | None
    reason: ExitReason
