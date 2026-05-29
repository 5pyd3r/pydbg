# Hook Module Design

## Goal

Add API hooking support (`hook/`) providing IAT (Import Address Table) hooking and inline
detour hooking. Uses existing disasm and patch modules for instruction analysis and JMP
generation. No new external dependencies.

## Scope

Three files:

- `hook/__init__.py` — package exports
- `hook/iat.py` — `IATHook`: IAT entry replacement
- `hook/inline.py` — `InlineHook`: 5-byte JMP detour with trampoline

## Architecture

```
src/pydbg/hook/
├── __init__.py       — exports IATHook, InlineHook, Trampoline
├── iat.py            — IATHook (import table patching)
└── inline.py         — InlineHook (inline detour + trampoline)
```

### Dependency Direction

```
Debugger ──uses──> hook/iat.py ──uses──> memory, module, pe
Debugger ──uses──> hook/inline.py ──uses──> disasm, patch, memory
```

Both hook classes receive `DebugSession` in constructor (same pattern as all managers).

## iat.py — IATHook

```python
class IATHook:
    def __init__(self, session):
        self._s = session

    def set(self, module_name: str, func_name: str, new_addr: int) -> int:
        """
        Replace IAT entry for func_name in module_name with new_addr.
        Returns the original address (for restore).
        Raises PydbgError if module or function not found in IAT.
        """

    def restore(self, module_name: str, func_name: str, original_addr: int):
        """Restore a previously hooked IAT entry."""

    def find(self, module_name: str, func_name: str) -> int | None:
        """Find the current IAT address for a function. Returns None if not found."""
```

**Implementation approach:**
1. Use `ModuleResolver` to enumerate modules, find target module base
2. Parse the target module's PE import directory to find IAT thunk address
3. Read current address from IAT, write new address
4. Track hooks in session for restore

## inline.py — InlineHook

```python
@dataclass
class Trampoline:
    addr: int          # trampoline address (allocated memory)
    size: int          # size of trampoline code
    original_code: bytes  # original bytes that were overwritten

class InlineHook:
    def __init__(self, session):
        self._s = session

    def set(self, target_addr: int, hook_addr: int) -> Trampoline:
        """
        Place a 5-byte JMP at target_addr jumping to hook_addr.
        Allocates a trampoline with original bytes + JMP back.
        Uses DisasmEngine to avoid splitting instructions.
        Raises PydbgError if unable to hook.
        """

    def restore(self, trampoline: Trampoline):
        """Restore original code and free trampoline memory."""
```

**Implementation approach:**
1. Disassemble instructions at target_addr until >= 5 bytes covered
2. Read original bytes (exact instruction boundary)
3. Allocate trampoline memory via VirtualAllocEx
4. Write original bytes + JMP back to trampoline
5. Generate JMP to hook_addr using Assembler, write to target_addr
6. Return Trampoline dataclass

No new external dependencies — uses existing capstone, keystone, and memory primitives.

## Integration with Debugger

```python
class Debugger:
    def __init__(self):
        ...
        self.hook_iat = IATHook(self._session)
        self.hook_inline = InlineHook(self._session)

    # Delegated methods:
    def iat_hook(self, module, func, new_addr):
        return self.hook_iat.set(module, func, new_addr)

    def iat_unhook(self, module, func, original_addr):
        return self.hook_iat.restore(module, func, original_addr)

    def inline_hook(self, target_addr, hook_addr):
        return self.hook_inline.set(target_addr, hook_addr)

    def inline_unhook(self, trampoline):
        return self.hook_inline.restore(trampoline)
```

Standalone usage:

```python
from pydbg.hook import IATHook, InlineHook
iat = IATHook(session)
iat.set("kernel32.dll", "CreateFileW", my_handler)
```

## Public API (pydbg/__init__.py additions)

```python
from .hook.iat import IATHook
from .hook.inline import InlineHook, Trampoline
# __all__: + "IATHook", "InlineHook", "Trampoline"
```

## Error Handling

- `IATHook.set()` raises `PydbgError` if module not found, function not in IAT
- `IATHook.restore()` no-op if hook not found (idempotent)
- `InlineHook.set()` raises `PydbgError` if target cannot be disassembled or memory allocation fails
- `InlineHook.restore()` raises `PydbgError` if trampoline memory free fails

## Tests

- `tests/test_iat.py` — IAT hook tests (require Windows PE with known imports)
- `tests/test_inline.py` — inline hook tests with hardcoded x64 code

## Non-goals

- Hot-patching (2-byte short JMP)
- IAT hooking of delay-loaded DLLs
- Multi-thread safety (caller's responsibility to suspend other threads)
- x86 trampoline relocation (RIP-relative instruction fixup) — future enhancement
