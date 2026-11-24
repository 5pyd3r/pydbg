"""pydbg instrumentation module — hardcoded stubs + LLVM dynamic codegen.

The public names are resolved on first use, like the top-level package
(ADR-0001): importing `pydbg.instrument` must not pull in `_pydbg`. That is what
lets the pure-Python parts of this package — the event buffer layout, the stub
and relocation encoder — be imported and tested on a machine that never built
the extension.

    from pydbg.instrument import Instrumenter        # extension imported here
    from pydbg.instrument.event_buffer import ...    # extension-free
    from pydbg.instrument.bbl import take_prefix     # extension-free

A submodule name is not in `_LAZY`: `from pydbg.instrument import event_buffer`
is resolved by Python's own submodule import.
"""

# name -> the submodule that defines it. Importing any of these pulls in
# `_pydbg` through the managers, which is exactly what must not happen at
# package import time.
_LAZY = {
    'Instrumenter': '.instrumenter',
    'InstrumentInfo': '.instrumenter',
    'InstrumentTemplates': '.templates',
}

__all__ = ['Instrumenter', 'InstrumentInfo', 'InstrumentTemplates']


def __getattr__(name):
    """Import one of the public names on first use (ADR-0001)."""
    module_name = _LAZY.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    value = getattr(importlib.import_module(module_name, __name__), name)
    globals()[name] = value          # resolve once; later lookups skip __getattr__
    return value


def __dir__():
    return sorted(set(globals()) | set(_LAZY))
