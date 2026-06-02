try:
    import keystone
except ImportError:
    keystone = None

from ..exceptions import PydbgError


class Assembler:
    """Keystone-based x86/x64 assembler (Intel syntax)."""

    def __init__(self, mode=None):
        if mode is None:
            import struct
            mode = "x64" if struct.calcsize("P") == 8 else "x86"
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
        self._init_keystone()
        normalized = self._normalize(code)
        if not normalized:
            return b''
        try:
            encoding, count = self._ks.asm(normalized, addr)
            return bytes(encoding)
        except keystone.KsError as e:
            raise PydbgError(f"Assembly error: {e}")

    def _normalize(self, code):
        lines = []
        for part in code.strip().split('\n'):
            for sub in part.split(';'):
                stripped = sub.strip()
                if stripped:
                    lines.append(stripped)
        return '; '.join(lines)

    def verify(self, code, addr=0):
        try:
            from ..disasm.engine import DisasmEngine
        except ImportError:
            raise PydbgError("disasm module not available for verification")
        assembled = self.assemble(code, addr)
        engine = DisasmEngine(mode=self._mode)
        insns = engine.disasm(addr, assembled)
        if not insns:
            return False
        original_mnemonics = self._normalize(code).lower().replace('; ', ';').split(';')
        roundtrip_mnemonics = [i.mnemonic.lower() for i in insns]
        return original_mnemonics == roundtrip_mnemonics
