import struct

try:
    import keystone
except ImportError:
    keystone = None

from ..exceptions import PydbgError


class Assembler:
    """Keystone-based x86/x64 assembler (Intel syntax)."""

    def __init__(self, mode=None, session=None):
        if mode is not None and mode not in ("x86", "x64"):
            raise PydbgError(f"Unknown mode '{mode}'. Expected 'x86' or 'x64'.")
        # None means "decide at each call": an explicit mode is what the caller
        # asked for, a session answers from its target, and with neither the
        # host's pointer width is the only thing left to go on.
        self._requested_mode = mode
        self._session = session
        self._ks = None
        # The engine is mode-specific, so which mode it was built for has to be
        # remembered next to it; see _init_keystone.
        self._ks_mode = None

    def _resolve_mode(self):
        """The mode to assemble in, decided now rather than when constructed.

        A Debugger builds its assembler before any target exists, so taking the
        host's pointer width in __init__ (and latching it) encoded x64 bytes for
        a WOW64 target reached later. The session is asked on every call
        instead — the rule disasm/engine.py already follows for disassembly.
        """
        if self._requested_mode is not None:
            return self._requested_mode
        if self._session is not None:
            # An absent answer is not a reason to assume the host's mode: the
            # caller asked for the target's, and a silent 64-bit guess is the
            # defect this resolution exists to remove.
            if not hasattr(self._session, 'target_arch'):
                raise PydbgError(
                    "the session cannot report target_arch; pass mode= explicitly")
            arch = self._session.target_arch
            if arch not in (32, 64):
                raise PydbgError(
                    f"the session reported target_arch={arch!r}; expected 32 or 64")
            return "x64" if arch == 64 else "x86"
        return "x64" if struct.calcsize("P") == 8 else "x86"

    def _init_keystone(self):
        mode = self._resolve_mode()
        if self._ks is not None and self._ks_mode == mode:
            return
        if keystone is None:
            raise PydbgError("keystone-engine is not installed")
        ks_mode = keystone.KS_MODE_64 if mode == "x64" else keystone.KS_MODE_32
        # Replace, never keep two: keystone's mode is fixed at construction, so
        # the engine from before a target switch cannot encode the new mode.
        # Dropping the reference is what releases the old one.
        self._ks = keystone.Ks(keystone.KS_ARCH_X86, ks_mode)
        self._ks_mode = mode

    def mode(self):
        return self._resolve_mode()

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
        """Whether assembling 'code' reproduces the mnemonics it was written as.

        The check compares mnemonics, not source text. It used to compare the
        whole statement against the disassembler's mnemonic, so any line with
        an operand — every line that does anything — answered False whether or
        not the encoding was right, and the tests only ever passed ret/nop.
        """
        try:
            from ..disasm.engine import DisasmEngine
        except ImportError:
            raise PydbgError("disasm module not available for verification")
        assembled = self.assemble(code, addr)
        engine = DisasmEngine(mode=self.mode())
        insns = engine.disasm(addr, assembled)
        if not insns:
            return False
        expected = [self._mnemonic_of(line)
                    for line in self._normalize(code).split(';')]
        roundtrip = [insn.mnemonic.lower() for insn in insns]
        return expected == roundtrip

    @staticmethod
    def _mnemonic_of(statement):
        parts = statement.split()
        return parts[0].lower() if parts else ''
