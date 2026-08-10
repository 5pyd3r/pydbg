"""Dynamic code generation for instrumentation payloads — LLVM backend facade.

Note: `_scan_externs` is a heuristic regex scanner, not a full C parser.
Extern declarations appearing in comments, forward declarations of functions
defined in the same TU, and externs declared with function-pointer types are
not classified reliably.
"""

import os as _os
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


def _llvm_bin_candidates():
    env = _os.environ.get("PYDBG_LLVM_BIN_DIR", "")
    if env:
        yield env
    try:
        import shutil, subprocess
        exe = shutil.which("llvm-config")
        if exe:
            out = subprocess.run([exe, "--bindir"], capture_output=True, text=True)
            if out.returncode == 0 and out.stdout.strip():
                yield out.stdout.strip()
    except Exception:
        pass
    # 后端按本机构建的 LLVM 版本链接。若 C:\Program Files\LLVM 是其他版本，
    # 其 libclang.dll 与 pyd 不兼容会在 DLL 初始化时崩溃，故构建设备路径优先。
    yield r"C:\Users\Spyder\AppData\Local\llvm-17\bin"
    yield r"C:\Program Files\LLVM\bin"


_llvm_dll_added = False


def _ensure_llvm_dlls():
    """将 LLVM bin 目录加入 DLL 搜索路径（_llvm_backend 依赖 libclang.dll）。"""
    global _llvm_dll_added
    if _llvm_dll_added:
        return
    if _os.name != "nt":
        return
    for d in _llvm_bin_candidates():
        if _os.path.isfile(_os.path.join(d, "libclang.dll")):
            try:
                _os.add_dll_directory(d)
                _llvm_dll_added = True
            except (OSError, AttributeError):
                continue
            return


def _backend():
    """Lazily import the LLVM backend extension; raises PydbgError if absent."""
    _ensure_llvm_dlls()
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

    if llvm_arch == "x86":
        # x86 cdecl 名修饰：extern 符号在对象文件的重定位表里带下划线前缀
        # （i686-pc-windows-msvc 的 _original_func 等），而 symbols 键是 C 层
        # 未修饰名。为后端补齐下划线别名，否则 applyRelocations 解析不到。
        symbols = dict(symbols)
        symbols.update({f"_{k}": v for k, v in symbols.items()
                        if not k.startswith("_")})

    try:
        code = backend.compile_stub(c_source, llvm_arch, dict(symbols), base_addr)
    except RuntimeError as exc:
        raise PydbgError(f"LLVM compilation failed: {exc}")
    if not code:
        raise PydbgError("LLVM compilation produced empty machine code")
    return bytes(code)
