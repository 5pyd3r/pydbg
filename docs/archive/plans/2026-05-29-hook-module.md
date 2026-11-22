# Hook Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Add IAT and inline hooking support to pydbg. IAT hook replaces import table entries;
inline hook places 5-byte JMP detours with trampoline allocation.

**Architecture:** Three-file module (`hook/__init__.py` + `hook/iat.py` + `hook/inline.py`).
Both hook classes receive DebugSession. Uses existing disasm (capstone), patch
(keystone Assembler), and memory primitives.

**Tech Stack:** Python 3.13+, existing capstone, existing keystone-engine

---

### Task 1: Create hook package files

Files: `src/pydbg/hook/__init__.py`, `src/pydbg/hook/iat.py`, `src/pydbg/hook/inline.py`

**Step 1:** Create `src/pydbg/hook/__init__.py`:
```python
from .iat import IATHook
from .inline import InlineHook, Trampoline

__all__ = ['IATHook', 'InlineHook', 'Trampoline']
```

**Step 2:** Create `src/pydbg/hook/iat.py`:
```python
from ..exceptions import PydbgError


class IATHook:
    """IAT (Import Address Table) hook manager."""

    def __init__(self, session):
        self._s = session
        self._hooks = {}  # (module_name, func_name) -> (iat_addr, original_addr)

    def set(self, module_name, func_name, new_addr):
        try:
            from ..memory.manager import MemoryManager
            from ..module.resolver import ModuleResolver
            from ..pe import PeReader
        except ImportError as e:
            raise PydbgError(f"Required module unavailable: {e}")

        mem = MemoryManager(self._s)
        modules = ModuleResolver(self._s)

        module_info = self._find_module(modules, module_name)
        if module_info is None:
            raise PydbgError(f"Module '{module_name}' not found")

        iat_addr = self._find_iat_entry(module_info, func_name, mem)
        if iat_addr is None:
            raise PydbgError(
                f"Function '{func_name}' not found in IAT of '{module_name}'"
            )

        original_addr = int.from_bytes(mem.read(iat_addr, 8), 'little')
        new_bytes = new_addr.to_bytes(8, 'little')
        mem.write(iat_addr, new_bytes)

        key = (module_name, func_name)
        self._hooks[key] = (iat_addr, original_addr)
        return original_addr

    def restore(self, module_name, func_name, original_addr=None):
        try:
            from ..memory.manager import MemoryManager
        except ImportError as e:
            raise PydbgError(f"MemoryManager unavailable: {e}")

        key = (module_name, func_name)
        if key in self._hooks:
            iat_addr, saved_original = self._hooks.pop(key)
            mem = MemoryManager(self._s)
            mem.write(iat_addr, saved_original.to_bytes(8, 'little'))
        elif original_addr is not None:
            mem = MemoryManager(self._s)
            from ..module.resolver import ModuleResolver
            modules = ModuleResolver(self._s)
            module_info = self._find_module(modules, module_name)
            if module_info is None:
                raise PydbgError(f"Module '{module_name}' not found")
            iat_addr = self._find_iat_entry(module_info, func_name, mem)
            if iat_addr is None:
                raise PydbgError(
                    f"Function '{func_name}' not found in IAT of '{module_name}'"
                )
            mem.write(iat_addr, original_addr.to_bytes(8, 'little'))

    def find(self, module_name, func_name):
        try:
            from ..memory.manager import MemoryManager
            from ..module.resolver import ModuleResolver
        except ImportError as e:
            raise PydbgError(f"Required module unavailable: {e}")

        mem = MemoryManager(self._s)
        modules = ModuleResolver(self._s)
        module_info = self._find_module(modules, module_name)
        if module_info is None:
            return None
        iat_addr = self._find_iat_entry(module_info, func_name, mem)
        if iat_addr is None:
            return None
        return int.from_bytes(mem.read(iat_addr, 8), 'little')

    def list_hooks(self):
        return dict(self._hooks)

    def _find_module(self, modules, module_name):
        name_lower = module_name.lower()
        for m in modules.enumerate():
            if m.get('name', '').lower() == name_lower:
                return m
        return None

    def _find_iat_entry(self, module_info, func_name, mem):
        base = module_info.get('base_address', 0)
        if base == 0:
            return None
        try:
            from ..pe import PeReader
            pe = PeReader.from_bytes(mem.read(base, 4096))
            imports = pe.imports()
            for imp in imports:
                if imp.name and imp.name.decode('ascii', errors='ignore').lower() == func_name.lower():
                    return imp.iat_rva + base
        except Exception:
            pass
        return None
```

**Step 3:** Create `src/pydbg/hook/inline.py`:
```python
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
        try:
            from ..disasm.engine import DisasmEngine
            from ..patch.assembler import Assembler
            from ..memory.manager import MemoryManager
        except ImportError as e:
            raise PydbgError(f"Required module unavailable: {e}")

        mem = MemoryManager(self._s)
        engine = DisasmEngine(mode="x64")
        asm = Assembler(mode="x64")

        original_bytes = self._read_instructions(mem, engine, target_addr)
        if len(original_bytes) < 5:
            raise PydbgError(
                f"Need at least 5 bytes for JMP at 0x{target_addr:X}, "
                f"got {len(original_bytes)}"
            )

        trampoline_size = len(original_bytes) + 5
        trampoline_addr = self._allocate_trampoline(mem, trampoline_size)

        jmp_back_code = asm.assemble(
            f"jmp {target_addr + len(original_bytes)}", trampoline_addr + len(original_bytes)
        )
        trampoline_code = original_bytes + jmp_back_code
        mem.write(trampoline_addr, trampoline_code)

        jmp_code = asm.assemble(f"jmp {hook_addr}", target_addr)
        mem.write(target_addr, jmp_code)

        trampoline = Trampoline(
            addr=trampoline_addr,
            size=trampoline_size,
            original_code=original_bytes,
        )
        self._hooks[target_addr] = trampoline
        return trampoline

    def restore(self, trampoline):
        try:
            from ..memory.manager import MemoryManager
        except ImportError as e:
            raise PydbgError(f"MemoryManager unavailable: {e}")

        mem = MemoryManager(self._s)
        if isinstance(trampoline, Trampoline):
            target_addr = None
            for addr, t in self._hooks.items():
                if t is trampoline:
                    target_addr = addr
                    break
            if target_addr is not None:
                mem.write(target_addr, trampoline.original_code)
                self._free_trampoline(mem, trampoline.addr, trampoline.size)
                del self._hooks[target_addr]

    def _read_instructions(self, mem, engine, addr):
        data = mem.read(addr, 16)
        insns = engine.disasm(addr, data)
        result = b''
        for insn in insns:
            result += bytes(insn.raw_bytes)
            if len(result) >= 5:
                break
        return result

    def _allocate_trampoline(self, mem, size):
        try:
            from ..cython import _memory
            result = _memory.virtual_alloc_ex(
                self._s.process_handle, 0, size,
                0x3000,  # MEM_COMMIT | MEM_RESERVE
                0x40,    # PAGE_EXECUTE_READWRITE
            )
            return result.get('base_address', 0)
        except Exception:
            return 0

    def _free_trampoline(self, mem, addr, size):
        try:
            from ..cython import _memory
            _memory.virtual_free_ex(
                self._s.process_handle, addr, size, 0x8000  # MEM_RELEASE
            )
        except Exception:
            pass
```

Commit: `feat(hook): add IATHook and InlineHook`

---

### Task 2: Integrate into Debugger and public API

Files: `src/pydbg/core/debugger.py`, `src/pydbg/__init__.py`

**Debugger changes:**
1. Add imports: `from ..hook.iat import IATHook` and `from ..hook.inline import InlineHook`
2. In `__init__`: add `self.hook_iat = IATHook(self._session)` and `self.hook_inline = InlineHook(self._session)`
3. Add methods:
```python
    def iat_hook(self, module, func, new_addr):
        return self.hook_iat.set(module, func, new_addr)

    def iat_unhook(self, module, func, original_addr=None):
        return self.hook_iat.restore(module, func, original_addr)

    def inline_hook(self, target_addr, hook_addr):
        return self.hook_inline.set(target_addr, hook_addr)

    def inline_unhook(self, trampoline):
        return self.hook_inline.restore(trampoline)
```

**__init__.py changes:**
1. Add imports: `from .hook.iat import IATHook`, `from .hook.inline import InlineHook, Trampoline`
2. Add to `__all__`: `'IATHook'`, `'InlineHook'`, `'Trampoline'`

Commit: `feat(hook): integrate hooks into Debugger and export public API`

---

### Task 3: Write tests

File: `tests/test_hook.py`

Tests focus on unit-testable logic: Trampoline dataclass, IATHook list_hooks tracking, error cases.
Inline hook disasm-based instruction reading is tested with mock session.

Commit: `test(hook): add unit tests for IAT and inline hooks`

---

### Task 4: Final verification

- Lint: `flake8 src/pydbg/hook/ tests/test_hook.py --max-line-length=120`
- Public API check
