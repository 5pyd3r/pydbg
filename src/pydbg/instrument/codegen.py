"""Dynamic code generation for instrumentation payloads — LLVM backend facade."""

import re

from ..exceptions import PydbgError

# Regex: match `extern <type> <name>(<params>);`
_EXTERN_RE = re.compile(r'extern\s+[\w\s*]+?\b(\w+)\s*\([^)]*\)\s*;')

_ARCH_MAP = {'x64': 'x86_64', 'x86': 'x86'}


def _scan_externs(c_source: str) -> set:
    """Extract extern function names from C source.

    'original_func' is reserved (auto-mapped to the trampoline) and excluded.
    """
    names = set(_EXTERN_RE.findall(c_source))
    names.discard('original_func')
    return names


def _backend():
    """Lazily import the LLVM backend extension; raises PydbgError if absent."""
    try:
        from .. import _llvm_backend
        return _llvm_backend
    except ImportError:
        raise PydbgError(
            "LLVM backend not available. "
            "Rebuild with -Denable-llvm-instrument=true"
        )


def compile_payload(c_source: str, arch: str, symbols: dict, base_addr: int = 0) -> bytes:
    """Compile C source → zero-relocation machine code for the target arch.

    Validates that every extern symbol (except original_func) is resolved in
    `symbols`. base_addr is the address where the code will be loaded (used to
    rebase extern-call rel32; see Task 3 design note). Raises PydbgError on
    missing backend, unresolved externs, or compilation failure.
    """
    backend = _backend()
    llvm_arch = _ARCH_MAP.get(arch, arch)

    externs = _scan_externs(c_source)
    missing = externs - set(symbols)
    if missing:
        raise PydbgError(
            f"Unresolved external symbol(s): {', '.join(sorted(missing))}. "
            f"Add them to the symbols dict."
        )

    try:
        code = backend.compile_stub(c_source, llvm_arch, dict(symbols), base_addr)
    except RuntimeError as exc:
        raise PydbgError(f"LLVM compilation failed: {exc}")
    if not code:
        raise PydbgError("LLVM compilation produced empty machine code")
    return bytes(code)
