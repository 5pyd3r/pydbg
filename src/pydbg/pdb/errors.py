"""Errors raised while reading a PDB."""

from ..exceptions import PydbgError


class PdbError(PydbgError):
    """Base class for PDB reading errors."""


class PdbFormatError(PdbError, ValueError):
    """The file is not a structurally valid container, or a record is missing.

    Both a PydbgError and a ValueError for the same reason TraceFormatError is:
    the bytes are malformed, and a caller that already catches PydbgError
    should not need to know this subpackage exists. Every message names the
    rule that failed and, where it applies, the offset or stream number — a
    rejected PDB has to be diagnosable from the exception alone.
    """
