class PydbgError(Exception):
    """Base exception for all pydbg errors."""


class ProcessError(PydbgError):
    """Process-related errors (create, attach, detach)."""


class MemError(PydbgError):
    """Memory operation errors (read, write, query)."""


class ThreadError(PydbgError):
    """Thread operation errors (context, suspend, resume)."""


class BreakpointError(PydbgError):
    """Breakpoint operation errors."""


class TimeoutError(PydbgError):
    """Timeout waiting for debug event."""


class TeardownError(PydbgError):
    """Something installed into the target could not be undone.

    close() finishes every step regardless and reports the failures together:
    stopping at the first one is how a target ends up with an INT3 in it while
    nobody is looking.
    """

    def __init__(self, problems):
        self.problems = list(problems)
        detail = "; ".join(f"{where}: {why}" for where, why in self.problems)
        super().__init__(
            f"{len(self.problems)} step(s) could not be undone: {detail}")
