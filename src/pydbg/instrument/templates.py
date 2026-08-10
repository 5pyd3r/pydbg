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


def _param_names(params: str):
    """Extract parameter identifiers from 'int a, int b' → ['a', 'b']."""
    names = []
    for part in params.split(','):
        tokens = part.strip().split()
        if tokens:
            names.append(tokens[-1])
    return names


class InstrumentTemplates:
    """Preset C payload templates for common probes.

    受 C 子集约束（int 参数/返回值、函数调用、赋值、算术、if/while），
    extern 仅支持函数（不支持 extern 全局变量——C→IR 转换器当前把 VarDecl
    一律当局部变量）。计数器等需落地的状态放在目标侧，经 extern 函数访问。
    """

    @staticmethod
    def log_args(entry, params, log_symbol, externs=None):
        """Log each param via log_symbol(param), then call original and return."""
        names = _param_names(params)
        externs = dict(externs or {})
        body = ''.join(f'    {log_symbol}({n});\n' for n in names)
        src = (f'extern int original_func({params});\n'
               f'extern void {log_symbol}(int value);\n'
               f'int {entry}({params}) {{\n'
               + body +
               f'    return original_func({", ".join(names)});\n}}\n')
        return src, externs

    @staticmethod
    def call_counter(entry, params, tick_symbol, externs=None):
        """Call tick_symbol() on every invocation, then call original.

        tick_symbol 是目标侧实现的计数函数（extern void tick(void)），
        计数器内存由目标维护，pydbg 只负责调用。
        """
        names = _param_names(params)
        externs = dict(externs or {})
        src = (f'extern int original_func({params});\n'
               f'extern void {tick_symbol}(void);\n'
               f'int {entry}({params}) {{\n'
               f'    {tick_symbol}();\n'
               f'    return original_func({", ".join(names)});\n}}\n')
        return src, externs

    @staticmethod
    def modify_return(entry, params, expr, externs=None):
        """Call original, bind result to r, return (expr) applied to r."""
        names = _param_names(params)
        externs = dict(externs or {})
        src = (f'extern int original_func({params});\n'
               f'int {entry}({params}) {{\n'
               f'    int r = original_func({", ".join(names)});\n'
               f'    return ({expr});\n}}\n')
        return src, externs
