"""Machine-code encoding helpers for x86/x64 instruction templates.

共享低层叶子模块：`hook` 与 `instrument` 都依赖它，但都不反向依赖对方，
避免层间循环（原先 `hook/inline.py` 直接 `from ..instrument.templates import
build_abs_jmp` 是反向依赖）。
"""

from ..exceptions import PydbgError


def build_abs_jmp(from_addr: int, to_addr: int) -> bytes:
    """5-byte near JMP (E9 rel32) from from_addr to to_addr.

    Raises PydbgError if the target is out of ±2GB range.
    """
    rel = to_addr - (from_addr + 5)
    if not (-(1 << 31) <= rel < (1 << 31)):
        raise PydbgError(
            f"JMP target 0x{to_addr:X} out of range of 0x{from_addr:X} "
            f"for a 5-byte near JMP"
        )
    return b"\xE9" + (rel & 0xFFFFFFFF).to_bytes(4, "little")
