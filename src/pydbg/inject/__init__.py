"""pydbg injection primitives — DLL, shellcode, APC, process suspend/resume.

Importing this package must not import the Cython extension (ADR-0001). The
report and error types are plain Python and are always available; the functions
are resolved on first use from `.api`, which is where `_pydbg` enters:

    from pydbg.inject import InjectionReport, InjectionError  # extension-free
    from pydbg.inject import inject_dll                       # extension here

The spec entry point is `pydbg.inject.inject_dll(dbg, ...)`; `import pydbg`
resolves this package lazily too, so `pydbg.inject` is available after a bare
`import pydbg`.

Remote allocations made by these functions are deliberately not freed
automatically — the address is in the report and belongs to the caller (free it
with `dbg.memory.free_remote(report.remote_base)` once the remote thread has
finished). See each function's docstring for the lifetime rule.
"""

from dataclasses import dataclass

from ..exceptions import InjectionError


@dataclass(frozen=True)
class InjectionReport:
    """What an injection call left behind in the target.

    Attributes:
        thread_id: Id of the thread `CreateRemoteThread` started.
        handle: Its Win32 handle; the caller owns it (`_pydbg.close_handle`).
        remote_base: Base of the memory allocated in the target. Still
            allocated after the call; free it when the remote thread is done.
    """

    thread_id: int
    handle: int
    remote_base: int


# name -> module that defines it. Importing any of these pulls in `_pydbg`,
# which must not happen at package import time.
_LAZY = {
    "inject_dll": ".api",
    "inject_shellcode": ".api",
    "queue_apc": ".api",
    "suspend_process": ".api",
    "resume_process": ".api",
}

__all__ = [
    "InjectionError",
    "InjectionReport",
    "inject_dll",
    "inject_shellcode",
    "queue_apc",
    "suspend_process",
    "resume_process",
]


def __getattr__(name):
    """Import one of the injection functions on first use (ADR-0001)."""
    module_name = _LAZY.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    value = getattr(importlib.import_module(module_name, __name__), name)
    globals()[name] = value          # resolve once; later lookups skip __getattr__
    return value


def __dir__():
    return sorted(set(globals()) | set(_LAZY))
