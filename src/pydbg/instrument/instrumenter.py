"""Instrumenter — install LLVM-generated probes at target addresses."""

from dataclasses import dataclass

from ..exceptions import PydbgError


@dataclass
class InstrumentInfo:
    target_addr: int
    trampoline_addr: int
    trampoline_size: int
    stub_addr: int
    stub_size: int          # len(machine) — 实际机器码长度
    stub_alloc_size: int    # 分配缓冲大小（0x2000），restore 时按此释放
    original_bytes: bytes
    symbols: dict
    c_source: str

    def to_dict(self) -> dict:
        return {
            'target_addr': self.target_addr,
            'trampoline_addr': self.trampoline_addr,
            'trampoline_size': self.trampoline_size,
            'stub_addr': self.stub_addr,
            'stub_size': self.stub_size,
            'original_bytes': self.original_bytes,
            'symbols': dict(self.symbols) if self.symbols else {},
            'c_source': self.c_source,
        }


class Instrumenter:
    def __init__(self, session):
        self._s = session
        self._hooks = {}  # target_addr -> InstrumentInfo

    @property
    def active(self) -> dict:
        return {addr: info.to_dict() for addr, info in self._hooks.items()}

    def install(self, target_addr, c_source=None, template=None, symbols=None):
        """Install an instrumentation probe at target_addr.

        Provide exactly one of c_source (raw C) or template (InstrumentTemplates).
        symbols maps extern names → absolute addresses; 'original_func' is
        auto-mapped to the trampoline address.
        """
        if (c_source is None) == (template is None):
            raise PydbgError("install() requires exactly one of c_source or template")
        if template is not None:
            c_source, template_symbols = template
            symbols = dict(template_symbols)
        else:
            symbols = dict(symbols) if symbols else {}

        from ..disasm.engine import DisasmEngine
        from ..memory.manager import MemoryManager
        from . import codegen
        from .templates import build_stub, build_trampoline

        mem = MemoryManager(self._s)
        mode = "x64" if getattr(self._s, 'target_arch', 64) == 64 else "x86"
        engine = DisasmEngine(mode=mode)

        # 1. 读取 ≥5 字节原始代码（指令边界）
        original = self._read_min_5_bytes(mem, engine, target_addr)

        # 2. trampoline：原始指令 + E9 跳回
        tramp_size = len(original) + 5
        tramp_addr = self._alloc_rwx(mem, tramp_size)
        if tramp_addr == 0:
            raise PydbgError("Failed to allocate trampoline memory")
        tramp_code = build_trampoline(original, tramp_addr, target_addr)
        try:
            mem.write(tramp_addr, tramp_code)
        except Exception:
            self._free_rwx(mem, tramp_addr, tramp_size)
            raise

        # 3. LLVM 编译 payload；original_func → trampoline
        symbols.setdefault('original_func', tramp_addr)

        # 4. 先分配 payload 缓冲（固定 0x2000），以缓冲地址为 base_addr 编译，
        #    使 extern call 的 rel32 按真实加载地址修正（见 Task 3 设计更正）
        _STUB_ALLOC = 0x2000
        stub_addr = self._alloc_rwx(mem, _STUB_ALLOC)
        if stub_addr == 0:
            self._free_rwx(mem, tramp_addr, tramp_size)
            raise PydbgError("Failed to allocate stub memory")
        try:
            machine = codegen.compile_payload(c_source, mode, symbols,
                                              base_addr=stub_addr)
        except Exception:
            self._free_rwx(mem, tramp_addr, tramp_size)
            self._free_rwx(mem, stub_addr, _STUB_ALLOC)
            raise
        mem.write(stub_addr, machine)

        # 5. detour stub 写入 target_addr
        mem.write(target_addr, build_stub(target_addr, stub_addr))

        info = InstrumentInfo(
            target_addr=target_addr,
            trampoline_addr=tramp_addr,
            trampoline_size=tramp_size,
            stub_addr=stub_addr,
            stub_size=len(machine),
            stub_alloc_size=_STUB_ALLOC,
            original_bytes=original,
            symbols=symbols,
            c_source=c_source,
        )
        self._hooks[target_addr] = info
        return info

    def restore(self, target_addr):
        """Restore original code and free trampoline + stub memory. Idempotent."""
        info = self._hooks.pop(target_addr, None)
        if info is None:
            return
        from ..memory.manager import MemoryManager
        mem = MemoryManager(self._s)
        try:
            mem.write(target_addr, info.original_bytes)
        finally:
            self._free_rwx(mem, info.trampoline_addr, info.trampoline_size)
            self._free_rwx(mem, info.stub_addr, info.stub_alloc_size)

    # ── internal helpers ────────────────────────────────────────

    def _read_min_5_bytes(self, mem, engine, addr):
        data = mem.read(addr, 16)
        result = b''
        for insn in engine.disasm(addr, data):
            result += insn.raw_bytes
            if len(result) >= 5:
                break
        if len(result) < 5:
            raise PydbgError(
                f"Need at least 5 bytes for JMP at 0x{addr:X}, got {len(result)}")
        return result

    def _alloc_rwx(self, mem, size):
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

    def _free_rwx(self, mem, addr, size):
        try:
            from .. import _pydbg
            _pydbg.virtual_free(self._s.process_handle, addr, size, 0x8000)
        except Exception:
            pass
