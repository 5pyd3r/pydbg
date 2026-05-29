# Patch Module Design

## Goal

Add a keystone-based assembly module (`patch/`) providing x86/x64 assembly-to-machine-code
conversion. Uses keystone-engine for assembly and the existing capstone disasm module for
optional round-trip verification.

## Scope

Two files:

- `patch/__init__.py` — package exports
- `patch/assembler.py` — `Assembler`: keystone wrapper with multi-line support and round-trip verification

## Architecture

```
src/pydbg/patch/
├── __init__.py       — exports Assembler
└── assembler.py      — Assembler (keystone wrapper)
```

Future: inline patching (5-byte JMP trampoline) lives in `patch/inline.py` and reuses `Assembler`.

### Dependency Direction

```
Debugger  ──uses──>  patch/assembler.py  ──uses──>  keystone
                         │
                    disasm/engine.py (optional, for verify)
```

## assembler.py — Assembler

```python
class Assembler:
    def __init__(self, mode="x64"):
        """
        mode: "x86" | "x64"
        Keystone handle created lazily on first assemble() call.
        """

    def assemble(self, code: str, addr: int = 0) -> bytes:
        """
        Assemble a string (Intel syntax) to machine code.
        Supports multiple instructions separated by newline or semicolon.
        Returns assembled bytes.
        Raises PydbgError on assembly failure.
        """

    def verify(self, code: str, addr: int = 0) -> bool:
        """
        Assemble, then disassemble with DisasmEngine, check round-trip.
        Returns True if disassembly mnemonics match input.
        Useful as a debugging aid — not meant for production validation.
        """

    def mode(self) -> str:
        """Return active mode ("x86" or "x64")."""
```

**Design notes:**
- Lazy init for keystone handle (same pattern as DisasmEngine)
- Intel syntax only (x86/x64 standard for Win32 debugging)
- `verify()` is optional — keystone must be importable but disasm is only needed when called
- Keystone errors raise `PydbgError` with the original error message
- Multi-line support: split on `\n` and `;`, strip whitespace, join with `; ` for keystone

## Integration with Debugger

```python
class Debugger:
    def __init__(self):
        ...
        self.assembler = Assembler()

    def assemble(self, code, addr=0):
        """Convenience: assemble code bytes at addr."""
        return self.assembler.assemble(code, addr)
```

`Assembler` is also importable standalone:

```python
from pydbg.patch import Assembler
asm = Assembler(mode="x64")
code = asm.assemble("ret")
```

## Public API (pydbg/__init__.py additions)

```python
from .patch.assembler import Assembler
# __all__: + "Assembler"
```

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| keystone-engine | >= 0.9.2 | x86/x64 assembly |

Keystone install: `pip install keystone-engine`. Pre-built wheels available for Windows x64.
Requires cmake for source builds on Linux. Treated as optional — `Assembler` raises `PydbgError`
if keystone is not installed and `assemble()` is called.

Capstone (disasm module) is an optional dependency for `verify()` only.

## Error Handling

- `Assembler.__init__` always succeeds (lazy init)
- `assemble()` raises `PydbgError` on keystone import failure or assembly syntax error
- `verify()` raises `PydbgError` if disasm cannot be imported, returns False on mismatch

## Tests

- `tests/test_patch.py`
- Hardcoded x64 assembly strings with known byte encodings (no live process needed)
- Test cases: single instruction, multi-line, `;` separator, x86 mode, error handling,
  `verify()` round-trip, keystone-not-installed graceful failure

## Non-goals

- Non-x86 architectures
- AT&T syntax
- Macro expansion, preprocessor
- Link-time optimization or relocation handling
