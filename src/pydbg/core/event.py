"""DebugEvent — debug event wrapper."""

from .. import _pydbg


class DebugEvent:
    """Represents a debug event."""

    __slots__ = (
        "type",
        "pid",
        "tid",
        "exception_code",
        "exception_addr",
        "first_chance",
        "exception_name",
        "exception_info",
        "raw",
        "is_child",
    )

    def __init__(self, event_dict, is_child=False):
        self.raw = event_dict
        self.type = event_dict.get("event_name", "UNKNOWN")
        self.pid = event_dict.get("pid", 0)
        self.tid = event_dict.get("tid", 0)
        self.exception_code = event_dict.get("exception_code")
        self.exception_addr = event_dict.get("exception_addr")
        self.first_chance = event_dict.get("first_chance")
        self.exception_name = None
        self.exception_info = None
        self.is_child = is_child
        if self.exception_code is not None:
            self.exception_name = _pydbg.exception_code_to_str(self.exception_code)
            self.exception_info = _pydbg.get_exception_info(
                self.exception_code,
                self.exception_addr or 0,
                1 if self.first_chance else 0,
                event_dict.get("exception_params", []),
            )

    def __repr__(self):
        return f"<DebugEvent {self.type} pid={self.pid} tid={self.tid}>"
