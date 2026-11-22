"""PDB reading — the self-built MSF validation shell (spec §10.2, §10.3).

dbghelp is the reader for symbols and types; this package owns what dbghelp
does not do, which is refuse a PDB that does not belong to the image. It is
pure Python (ADR-0001), so it must keep working on a machine with no compiled
extension.
"""

from .errors import PdbError, PdbFormatError
from .msf import MSFFile, PdbInfo

__all__ = ['MSFFile', 'PdbError', 'PdbFormatError', 'PdbInfo']
