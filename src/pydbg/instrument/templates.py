"""Instrumentation instruction templates — hardcoded x86/x64 byte templates.

Stub/trampoline 全部用硬编码字节，不依赖 keystone/capstone：
- detour stub = 5 字节近跳 E9 rel32
- trampoline  = 被覆盖的原始指令副本 + 5 字节 E9 rel32 跳回
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


def build_stub(target_addr: int, payload_addr: int) -> bytes:
    """Detour stub written at target_addr: JMP payload_addr."""
    return build_abs_jmp(target_addr, payload_addr)


def build_trampoline(original: bytes, trampoline_addr: int, target_addr: int) -> bytes:
    """Trampoline body: relocated original bytes + E9 rel32 JMP back.

    Args:
        original: exact original instruction bytes that were overwritten.
        trampoline_addr: address where the trampoline is allocated.
        target_addr: original target address; resume at target_addr + len(original).
    """
    resume = target_addr + len(original)
    jmp_from = trampoline_addr + len(original)
    return original + build_abs_jmp(jmp_from, resume)
