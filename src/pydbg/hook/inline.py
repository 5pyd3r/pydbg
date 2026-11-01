from dataclasses import dataclass

from ..exceptions import PydbgError

_MEM_COMMIT_RESERVE = 0x3000   # MEM_COMMIT | MEM_RESERVE
_PAGE_EXECUTE_READWRITE = 0x40
_MEM_RELEASE = 0x8000          # MEM_RELEASE 要求 dwSize==0


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
        from ..memory.manager import MemoryManager

        mem = MemoryManager(self._s)
        mode = "x64" if getattr(self._s, 'target_arch', 64) == 64 else "x86"
        engine = DisasmEngine(mode=mode)

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

        jmp_back_code = self._build_abs_jmp(
            trampoline_addr + len(original_bytes),
            target_addr + len(original_bytes),
        )
        trampoline_code = original_bytes + jmp_back_code
        mem.write(trampoline_addr, trampoline_code)

        jmp_code = self._build_abs_jmp(target_addr, hook_addr)
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
        target_addr = next(
            (addr for addr, known in self._hooks.items() if known is trampoline),
            None)
        if target_addr is None:
            # Silently doing nothing here meant a caller that restored the
            # wrong trampoline (or restored twice) believed the target had its
            # original bytes back while the E9 detour was still in place.
            raise PydbgError(
                f"trampoline at 0x{trampoline.addr:X} is not installed; "
                "restore() only accepts a Trampoline returned by set()")
        mem.write(target_addr, trampoline.original_code)
        del self._hooks[target_addr]
        self._free(mem, trampoline.addr, trampoline.size)

    @staticmethod
    def _build_abs_jmp(from_addr, to_addr):
        """Build a 5-byte near JMP (E9 rel32) to an absolute address.

        Delegates to patch.encoding.build_abs_jmp (shared hardcoded template).

        Keystone emits a short rel8 JMP when the target is within 128 bytes,
        which the hook layout does not support; building E9 explicitly keeps
        the JMP exactly 5 bytes in all cases.
        """
        from ..patch.encoding import build_abs_jmp
        return build_abs_jmp(from_addr, to_addr)

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
        from .. import _pydbg
        try:
            result = _pydbg.virtual_alloc(
                self._s.process_handle, size,
                _MEM_COMMIT_RESERVE,
                _PAGE_EXECUTE_READWRITE,
            )
        except OSError as e:
            raise PydbgError(f"cannot allocate trampoline memory: {e}") from e
        return result.get('base_address', 0)

    def _free(self, mem, addr, size):
        from .. import _pydbg
        try:
            _pydbg.virtual_free(self._s.process_handle, addr, 0, _MEM_RELEASE)
        except OSError as e:
            # The detour is already gone, so this is a leak, not a broken
            # target — but a leak the caller never hears about is the silent
            # failure this module is supposed to stop producing.
            raise PydbgError(
                f"detour removed, but trampoline memory at 0x{addr:X} "
                f"could not be released: {e}") from e
