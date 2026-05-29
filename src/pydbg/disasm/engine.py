from dataclasses import dataclass, field

try:
    import capstone
except ImportError:
    capstone = None

from ..exceptions import PydbgError


@dataclass
class Instruction:
    address: int
    size: int
    mnemonic: str
    op_str: str
    raw_bytes: bytes
    is_call: bool = False
    is_jmp: bool = False
    is_ret: bool = False
    is_cond: bool = False
    groups: list = field(default_factory=list)


class DisasmEngine:
    """Capstone-based x86/x64 disassembler with auto mode detection."""

    _UNCONDITIONAL_JUMPS = {'jmp', 'ljmp'}

    def __init__(self, session=None, mode="auto"):
        self._session = session
        self._requested_mode = mode
        self._cs = None
        self._arch_mode = None

    def _init_capstone(self):
        if self._cs is not None:
            return
        if capstone is None:
            raise PydbgError("capstone is not installed")
        if self._requested_mode == "auto":
            self._arch_mode = "x64"
        elif self._requested_mode in ("x86", "x64"):
            self._arch_mode = self._requested_mode
        else:
            raise PydbgError(
                f"Unknown mode '{self._requested_mode}'. Expected 'auto', 'x86', or 'x64'."
            )
        cs_mode = capstone.CS_MODE_64 if self._arch_mode == "x64" else capstone.CS_MODE_32
        self._cs = capstone.Cs(capstone.CS_ARCH_X86, cs_mode)
        self._cs.detail = True

    def mode(self):
        if self._cs is None:
            self._init_capstone()
        return self._arch_mode

    def disasm(self, addr, data):
        self._init_capstone()
        instructions = []
        for insn in self._cs.disasm(data, addr):
            instructions.append(self._make_instruction(insn))
        return instructions

    def iter_disasm(self, addr, data):
        self._init_capstone()
        for insn in self._cs.disasm(data, addr):
            yield self._make_instruction(insn)

    def _make_instruction(self, insn):
        groups = [insn.group_name(g) for g in insn.groups]
        is_jmp = 'jump' in groups
        is_call = 'call' in groups
        is_ret = 'ret' in groups
        is_cond = is_jmp and insn.mnemonic not in self._UNCONDITIONAL_JUMPS
        return Instruction(
            address=insn.address,
            size=insn.size,
            mnemonic=insn.mnemonic,
            op_str=insn.op_str,
            raw_bytes=bytes(insn.bytes),
            is_call=is_call,
            is_jmp=is_jmp,
            is_ret=is_ret,
            is_cond=is_cond,
            groups=groups,
        )
