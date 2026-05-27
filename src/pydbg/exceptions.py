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
