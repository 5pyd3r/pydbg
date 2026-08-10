"""Instrumenter — install LLVM-generated probes at target addresses."""

from dataclasses import dataclass

from ..exceptions import PydbgError

_STUB_ALLOC = 0x2000   # payload 缓冲固定大小；以真实基址编译后写入实际机器码

# E9 rel32 detour 约束：stub / trampoline 必须与目标函数地址处于 ±2GB 内。
# 窗口取略小于 2GB，给跳转指令自身长度留余量（目标-窗口-5 仍在 INT32 范围）。
_RELOC_WINDOW = 0x7F000000
_MEM_FREE = 0x10000        # VirtualQueryEx state: MEM_FREE
_MEM_COMMIT_RESERVE = 0x3000  # MEM_COMMIT | MEM_RESERVE
_PAGE_EXECUTE_READWRITE = 0x40
_GRANULARITY = 0x10000     # VirtualAllocEx 把 lpAddress 向下取整到分配粒度 (64KB)


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
        # stub_alloc_size 刻意省略：那是内部分配缓冲大小，stub_size 才是实际机器码长度
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

        Provide exactly one of c_source (raw C) or template (a (c_source, symbols)
        tuple as returned by InstrumentTemplates methods — not the class/method
        itself). symbols maps extern names → absolute addresses; 'original_func'
        is always forced to the trampoline address.
        """
        if (c_source is None) == (template is None):
            raise PydbgError("install() requires exactly one of c_source or template")
        if template is not None:
            c_source, template_symbols = template
            symbols = dict(template_symbols)
        else:
            symbols = dict(symbols) if symbols else {}

        if target_addr in self._hooks:
            raise PydbgError(
                f"target 0x{target_addr:X} is already instrumented; restore() it first")

        from ..disasm.engine import DisasmEngine
        from ..memory.manager import MemoryManager
        from . import codegen
        from .templates import build_stub, build_trampoline

        mem = MemoryManager(self._s)
        mode = "x64" if getattr(self._s, 'target_arch', 64) == 64 else "x86"
        engine = DisasmEngine(mode=mode)

        # 1. 读取 ≥5 字节原始代码（指令边界）
        original = self._read_min_5_bytes(mem, engine, target_addr)

        # 2. trampoline：原始指令 + E9 跳回。
        #    必须在目标函数 ±2GB 内分配（E9 rel32 detour 约束），否则 VirtualAllocEx
        #    无 hint 时可能落到 >2GB 外导致跳转越界。
        tramp_size = len(original) + 5
        tramp_addr = self._alloc_rwx(mem, tramp_size, near=target_addr)
        if tramp_addr == 0:
            raise PydbgError("Failed to allocate trampoline memory")
        try:
            tramp_code = build_trampoline(original, tramp_addr, target_addr)
            mem.write(tramp_addr, tramp_code)
        except Exception:
            self._free_rwx(mem, tramp_addr, tramp_size)
            raise

        # 3. LLVM 编译 payload；original_func 强制映射到 trampoline
        symbols['original_func'] = tramp_addr

        # 4. 先分配 payload 缓冲（固定 _STUB_ALLOC），以缓冲地址为 base_addr 编译，
        #    使 extern call 的 rel32 按真实加载地址修正（见 Task 3 设计更正）。
        #    payload 内的 call original_func 也是 rel32，stub 必须与 trampoline 邻近。
        #    分配中心用 target_addr（而非 tramp_addr）：tramp 落在 target 下方首个
        #    足够大的空闲区域首部，stub 扫描同一 lo 会落在其余部紧邻 tramp；若以
        #    tramp 为中心，扫描窗口整体下移，stub 可能落到 target >2GB 外，E9 越界。
        stub_addr = self._alloc_rwx(mem, _STUB_ALLOC, near=target_addr)
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
        try:
            mem.write(stub_addr, machine)
            mem.write(target_addr, build_stub(target_addr, stub_addr))
        except Exception:
            try:
                mem.write(target_addr, original)   # 尽力恢复目标
            except Exception:
                pass
            self._free_rwx(mem, tramp_addr, tramp_size)
            self._free_rwx(mem, stub_addr, _STUB_ALLOC)
            raise

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

    def _alloc_rwx(self, mem, size, near=None):
        """分配可执行 RWX 内存。near 给出后，在 near ±2GB 内就近分配，
        保证 E9 rel32 detour 可达。返回基址或 0。"""
        try:
            from .. import _pydbg
            h = self._s.process_handle
            if near:
                return self._alloc_near(h, near, size)
            result = _pydbg.virtual_alloc(
                h, size,
                _MEM_COMMIT_RESERVE,
                _PAGE_EXECUTE_READWRITE,
            )
            return result.get('base_address', 0)
        except Exception:
            return 0

    def _alloc_near(self, h, near, size):
        """在 [near-_RELOC_WINDOW, near+_RELOC_WINDOW] 内扫描空闲区域并就近分配。

        用 VirtualQueryEx 步进区域，跳过已占用区域，在首个足够大的 MEM_FREE
        区域分配 size 字节。返回分配基址或 0。
        """
        from .. import _pydbg
        lo = (near - _RELOC_WINDOW) & ~0xFFFF
        if lo < 0x10000:
            lo = 0x10000
        hi = near + _RELOC_WINDOW
        addr = lo
        for _ in range(100000):  # 安全上限
            if addr >= hi:
                break
            try:
                info = _pydbg.virtual_query_ex(h, addr)
            except Exception:
                break
            base = info['base_address']
            rsize = info['region_size']
            if info['state'] == _MEM_FREE and rsize >= size:
                # VirtualAllocEx 把 lpAddress 向下取整到 64KB 分配粒度：若 hint
                # 落在已占用页上会失败 (ERROR_INVALID_ADDRESS=487)。故向上取整
                # 到 64KB，并保证 hint+size 不越出本空闲区域。
                hint = (base + _GRANULARITY - 1) & ~(_GRANULARITY - 1)
                if hint + size > hi:          # 窗口上界对称守卫（防御性）
                    hint = hi - size
                if hint + size <= base + rsize:
                    try:
                        result = _pydbg.virtual_alloc_ex(
                            h, hint, size, _MEM_COMMIT_RESERVE,
                            _PAGE_EXECUTE_READWRITE)
                        got = result.get('base_address', 0)
                        if got:
                            return got
                    except Exception:
                        pass
            nxt = base + rsize
            if nxt <= addr:  # 防死循环
                nxt = addr + 0x1000
            addr = nxt
        return 0

    def _free_rwx(self, mem, addr, size):
        try:
            from .. import _pydbg
            _pydbg.virtual_free(self._s.process_handle, addr, size, 0x8000)
        except Exception:
            pass
