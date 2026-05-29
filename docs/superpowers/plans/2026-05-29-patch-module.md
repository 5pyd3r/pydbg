# Patch Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) to implement this plan task-by-task.

**Goal:** Add keystone-based assembly module to pydbg as Phase 2 patch module.

**Architecture:** Two-file module (`patch/__init__.py` + `patch/assembler.py`) with `Assembler` class wrapping keystone for x86/x64 assembly. Multi-line support, round-trip verification via existing disasm module. Integrated into Debugger facade.

**Tech Stack:** Python 3.13+, keystone-engine >= 0.9.2, existing capstone (for verify)

---

### Task 1: Install keystone-engine dependency

- [ ] Install: `pip install --break-system-packages 'keystone-engine'`
- [ ] On ARM64 Linux: may fail (no cmake). Accept and proceed; CI uses Windows with pre-built wheels.

---

### Task 2: Create patch package and assembler module

Files: `src/pydbg/patch/__init__.py`, `src/pydbg/patch/assembler.py`

**Step 1:** Create `src/pydbg/patch/__init__.py`:
```python
from .assembler import Assembler

__all__ = ['Assembler']
```

**Step 2:** Create `src/pydbg/patch/assembler.py`:
```python
try:
    import keystone
except ImportError:
    keystone = None

from ..exceptions import PydbgError


class Assembler:
    """Keystone-based x86/x64 assembler (Intel syntax)."""

    _KS_ARCH = 1   # KS_ARCH_X86 (hardcoded to avoid import-time dependency)

    def __init__(self, mode="x64"):
        if mode not in ("x86", "x64"):
            raise PydbgError(f"Unknown mode '{mode}'. Expected 'x86' or 'x64'.")
        self._mode = mode
        self._ks = None

    def _init_keystone(self):
        if self._ks is not None:
            return
        if keystone is None:
            raise PydbgError("keystone-engine is not installed")
        ks_mode = keystone.KS_MODE_64 if self._mode == "x64" else keystone.KS_MODE_32
        self._ks = keystone.Ks(keystone.KS_ARCH_X86, ks_mode)

    def mode(self):
        return self._mode

    def assemble(self, code, addr=0):
        """Assemble Intel-syntax code to machine bytes. Supports multi-line (\\n or ;)."""
        self._init_keystone()
        normalized = self._normalize(code)
        try:
            encoding, count = self._ks.asm(normalized, addr)
            return bytes(encoding)
        except keystone.KsError as e:
            raise PydbgError(f"Assembly error: {e}")

    def _normalize(self, code):
        """Split on newline and semicolon, join with '; ' for keystone."""
        lines = []
        for part in code.strip().split('\n'):
            for sub in part.split(';'):
                stripped = sub.strip()
                if stripped:
                    lines.append(stripped)
        return '; '.join(lines)

    def verify(self, code, addr=0):
        """Assemble then disassemble to verify round-trip."""
        try:
            from ..disasm.engine import DisasmEngine
        except ImportError:
            raise PydbgError("disasm module not available for verification")
        assembled = self.assemble(code, addr)
        engine = DisasmEngine(mode=self._mode)
        insns = engine.disasm(addr, assembled)
        if not insns:
            return False
        # Compare mnemonics (case-insensitive)
        original_mnemonics = self._normalize(code).lower().replace('; ', ';').split(';')
        roundtrip_mnemonics = [i.mnemonic.lower() for i in insns]
        return original_mnemonics == roundtrip_mnemonics
```

**Step 3:** Commit: `feat(patch): add Assembler with keystone wrapper`

---

### Task 3: Integrate into Debugger and public API

Files: `src/pydbg/core/debugger.py`, `src/pydbg/__init__.py`

**Debugger changes:**
1. Add import: `from ..patch.assembler import Assembler`
2. In `__init__`: `self.assembler = Assembler()`
3. Add method:
```python
    def assemble(self, code, addr=0):
        return self.assembler.assemble(code, addr)
```

**__init__.py changes:**
1. Add import: `from .patch.assembler import Assembler`
2. Add to `__all__`: `'Assembler'`

Commit: `feat(patch): integrate Assembler into Debugger and export public API`

---

### Task 4: Update CI (keystone dependency)

File: `.github/workflows/ci.yml`

Add `keystone-engine` to install step:
```
pip install meson meson-python ninja cython flake8 'capstone>=5.0' keystone-engine
```

---

### Task 5: Write unit tests

File: `tests/test_patch.py`

Test cases with hardcoded x64 assembly:
- `test_assemble_single` — "ret" → b'\xc3'
- `test_assemble_multi_newline` — "push rbp\nmov rbp, rsp" → check bytes
- `test_assemble_multi_semicolon` — "xor eax, eax; ret" → check bytes
- `test_assemble_with_addr` — addr parameter passed through
- `test_mode_x86` — 32-bit mode
- `test_bad_mode` — raises PydbgError
- `test_bad_syntax` — invalid assembly raises PydbgError
- `test_verify_ok` — round-trip passes for simple code
- `test_verify_fail` — mismatch detection

Also register in `tests/meson.build`.

Commit: `test(patch): add unit tests for assembler`

---

### Task 6: Final verification

- Run tests: `PYTHONPATH=src python3 -m pytest tests/test_patch.py -v`
- Lint: `flake8 src/pydbg/patch/ tests/test_patch.py --max-line-length=120`
- Public API check
- Commit lint fixes
