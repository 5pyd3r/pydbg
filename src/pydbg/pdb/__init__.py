"""PDB reading — MSF validation, discovery, and the PDB handle (spec §10.2, §10.3).

dbghelp is the reader for symbols and types; this package owns what dbghelp
does not do, which is find the PDB for an image and refuse one that does not
belong to it. `find` / `open_for` are the entry points; `Pdb` is the verified
handle. It is pure Python (ADR-0001), so it must keep working on a machine with
no compiled extension.
"""

from .dbghelp import PdbSymbol
from .errors import PdbError, PdbFormatError
from .lookup import Pdb, PdbLookup, find, open_for
from .msf import MSFFile, PdbInfo

__all__ = ['MSFFile', 'Pdb', 'PdbError', 'PdbFormatError', 'PdbInfo',
           'PdbLookup', 'PdbSymbol', 'find', 'open_for']
