"""Windows — what the target's message loop is doing, as a capability object.

These were Debugger methods. Nothing about them needs the debugger, only a pid,
so they answer through `dbg.windows` instead of adding three more names to the
facade (ADR-0002: a capability that can be constructed and tested on its own
does not get an entry on the facade).
"""

from .window_probe import WindowProbeQuery


class Windows:
    """Window inspection for the target (or any pid)."""

    def __init__(self, session):
        self._s = session

    def probe(self, pid=None):
        """What the target's message loop is doing, or None if unavailable.

        None means the probe could not be built — no Cython extension, or not
        Windows — and is deliberately distinct from a probe whose answer is
        UNKNOWN. Both are refusals, but only one of them is a refusal this
        package can do anything about, and a caller reporting a zero result
        needs to say which.
        """
        target = self._s.pid if pid is None else pid
        if target is None:
            return None
        try:
            return WindowProbeQuery().probe(target)
        except Exception:                              # noqa: BLE001
            return None

    def state(self, pid=None):
        """`MessageLoopState`, or None when the probe is unavailable."""
        probe = self.probe(pid)
        return None if probe is None else probe.state

    def texts(self, pid=None):
        """(class name, text) for every window of the target, top level first."""
        probe = self.probe(pid)
        if probe is None:
            return ()
        found = []

        def walk(window):
            found.append((window.class_name, window.text))
            for child in window.children:
                walk(child)

        for window in probe.windows:
            walk(window)
        return tuple(found)
