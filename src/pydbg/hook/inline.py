from dataclasses import dataclass

from ..exceptions import PydbgError


@dataclass
class Trampoline:
    addr: int
    size: int
    original_code: bytes


class InlineHook:
    """Inline detour hook with trampoline allocation."""

    def __init__(self, session):
        self._s = session
        self._hooks = {}  # target_addr -> Trampoline

    def set(self, target_addr, hook_addr):
        from ..disasm.engine import DisasmEngine
        from ..patch.assembler import Assembler
        from ..memory.manager import MemoryManager

        mem = MemoryManager(self._s)
        engine = DisasmEngine(mode="x64")
        asm = Assembler(mode="x64")

        original_bytes = self._read_min_5_bytes(mem, engine, target_addr)
        if len(original_bytes) < 5:
            raise PydbgError(
                f"Need at least 5 bytes for JMP at 0x{target_addr:X}, "
                f"got {len(original_bytes)}"
            )

        trampoline_size = len(original_bytes) + 5
        trampoline_addr = self._alloc(mem, trampoline_size)
        if trampoline_addr == 0:
            raise PydbgError("Failed to allocate trampoline memory")

        jmp_back_code = asm.assemble(
            f"jmp {target_addr + len(original_bytes)}",
            trampoline_addr + len(original_bytes)
        )
        trampoline_code = original_bytes + jmp_back_code
        mem.write(trampoline_addr, trampoline_code)

        jmp_code = asm.assemble(f"jmp {hook_addr}", target_addr)
        if len(jmp_code) != 5:
            raise PydbgError(f"Expected 5-byte JMP, got {len(jmp_code)} bytes")
        mem.write(target_addr, jmp_code)

        trampoline = Trampoline(
            addr=trampoline_addr,
            size=trampoline_size,
            original_code=original_bytes,
        )
        self._hooks[target_addr] = trampoline
        return trampoline

    def restore(self, trampoline):
        from ..memory.manager import MemoryManager

        mem = MemoryManager(self._s)
        target_addr = None
        for addr, t in self._hooks.items():
            if t is trampoline:
                target_addr = addr
                break
        if target_addr is not None:
            mem.write(target_addr, trampoline.original_code)
            self._free(mem, trampoline.addr, trampoline.size)
            del self._hooks[target_addr]

    def _read_min_5_bytes(self, mem, engine, addr):
        data = mem.read(addr, 16)
        insns = engine.disasm(addr, data)
        result = b''
        for insn in insns:
            result += insn.raw_bytes
            if len(result) >= 5:
                break
        return result

    def _alloc(self, mem, size):
        try:
            from .. import _pydbg
            result = _pydbg.virtual_alloc(
                self._s.process_handle, size,
                0x3000,  # MEM_COMMIT | MEM_RESERVE
                0x40,    # PAGE_EXECUTE_READWRITE
            )
            return result.get('base_address', 0)
        except Exception:
            return 0

    def _free(self, mem, addr, size):
        try:
            from .. import _pydbg
            _pydbg.virtual_free(self._s.process_handle, addr, size, 0x8000)
        except Exception:
            pass
