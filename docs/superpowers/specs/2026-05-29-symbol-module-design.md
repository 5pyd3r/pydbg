# Symbol Module Design

## Goal

Add symbol resolution support (`symbol/`) wrapping dbghelp.dll. Provides symbol-by-name lookup,
symbol-by-address lookup, and module symbol loading. No new external dependencies (dbghelp.dll
is already linked in meson.build).

## Scope

Three files:

- `cython/_symbol.pxi` — Cython wrappers for dbghelp.dll
- `symbol/__init__.py` — package exports
- `symbol/resolver.py` — `SymbolResolver`: high-level Python API

## Architecture

```
Win32 (dbghelp.dll) → _symbol.pxi → _pydbg → symbol/resolver.py → Debugger
```

### Dependency Direction

```
Debugger ──uses──> symbol/resolver.py ──uses──> _pydbg (via cython)
```

## Cython Layer — _symbol.pxi

New functions (added to `_pydbg` via include):

```cython
cpdef void sym_initialize(unsigned long long h_process, str user_search_path, int invade):
    """Initialize the symbol handler for a process."""

cpdef void sym_cleanup(unsigned long long h_process):
    """Deallocate all symbol resources for a process."""

cpdef dict sym_from_name(unsigned long long h_process, str name):
    """Look up symbol by name. Returns dict with address, size, module, name."""

cpdef dict sym_from_addr(unsigned long long h_process, unsigned long long address):
    """Look up symbol by address. Returns dict with address, displacement, name."""

cpdef unsigned long long sym_load_module_ex(unsigned long long h_process,
    unsigned long long h_file, str image_name, str module_name,
    unsigned long long base_of_dll, int dll_size):
    """Load symbol table for a module."""

cpdef void sym_set_options(int options):
    """Set symbol handler options."""

cpdef int sym_get_options():
    """Get current symbol handler options."""
```

New types in `_win32types.pxd`:
- `SYMBOL_INFOW` structure (with MAX_SYM_NAME = 2000)
- `SymInitializeW`, `SymFromNameW`, `SymFromAddrW`, `SymLoadModuleExW`
- `SymCleanup`, `SymSetOptions`, `SymGetOptions`
- `SYMOPT_UNDNAME`, `SYMOPT_DEFERRED_LOADS`, etc.

## symbol/resolver.py — SymbolResolver

```python
class SymbolResolver:
    def __init__(self, session):
        self._s = session
        self._initialized = False

    def initialize(self, search_path=None, invade=True):
        """Initialize symbol handler. Call once after process creation."""

    def cleanup(self):
        """Clean up symbol resources."""

    def from_name(self, name: str) -> dict | None:
        """Look up symbol by name."""

    def from_addr(self, address: int) -> dict | None:
        """Look up symbol by address. Returns {address, displacement, name}."""

    def load_module(self, image_name, base_of_dll, dll_size=0):
        """Load symbol table for a module."""
```

## Public API (pydbg/__init__.py)

```python
from .symbol.resolver import SymbolResolver
# __all__: + "SymbolResolver"
```

## Integration with Debugger

```python
class Debugger:
    def __init__(self):
        ...
        self.symbols = SymbolResolver(self._session)
```

## Non-goals

- PDB file parsing (no construct dependency)
- Type information / source line numbers (future)
- Cross-process symbol resolution
