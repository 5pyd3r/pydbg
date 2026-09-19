from dataclasses import dataclass, field

try:
    import capstone
except ImportError:
    capstone = None

from ..exceptions import PydbgError

# Operand kinds, mirroring capstone's X86_OP_* but ours: no caller should have
# to import capstone to inspect an Instruction.
OP_REG = 1
OP_IMM = 2
OP_MEM = 3


@dataclass(frozen=True, slots=True)
class Operand:
    """One decoded operand, in plain Python types.

    Capstone's operand objects are tied to the CsInsn that produced them and
    keep the whole instruction alive; holding those would retain ~1KB per
    instruction for a large image. This is the cheap detached form, and it is
    what makes operand-level analysis possible without the caller touching
    capstone at all (`operands` used to be read and discarded).
    """

    kind: int
    size: int = 0        # operand width in bytes
    reg: int = 0         # OP_REG: capstone register id
    imm: int = 0         # OP_IMM: already sign-extended by capstone
    mem_segment: int = 0  # OP_MEM: fs/gs override, 0 when there is none
    mem_base: int = 0    # OP_MEM
    mem_index: int = 0
    mem_scale: int = 0
    mem_disp: int = 0

    @property
    def is_absolute_mem(self):
        """True for [disp] — the displacement *is* the address being used.

        Load-bearing for cross-referencing: a 64-bit build puts absolute
        addresses in exactly this form, and `mov eax, [0x401000]` must not be
        confused with `mov eax, [rbx+8]`.

        The segment check is not decoration. `mov rcx, gs:[0x60]` also has no
        base and no index, but 0x60 is an offset inside the GS segment — a TEB
        field, not an address. Measured on kernel32.dll, every "absolute"
        operand in the first 128KB of .text was one of these; without this the
        whole seed class would have pointed at low addresses that mean nothing.
        """
        return (self.kind == OP_MEM and self.mem_segment == 0
                and self.mem_base == 0 and self.mem_index == 0)

    @property
    def is_table_mem(self):
        """True for [reg*scale + disp] — the displacement is a table base.

        Switch tables compile to this shape, and the displacement is then the
        address of the table rather than of the data being loaded. Segmented
        forms are excluded for the same reason as above.
        """
        return (self.kind == OP_MEM and self.mem_segment == 0
                and self.mem_base == 0 and self.mem_index != 0)


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
    # Additive: every field below has a default, so existing constructions
    # (tests and callers build Instruction positionally and by keyword) keep
    # working unchanged.
    operands: tuple = ()     # tuple[Operand, ...]
    insn_id: int = 0         # capstone instruction id; 0 when unknown


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
            # Use session's target architecture if available, else host arch
            if self._session is not None and hasattr(self._session, 'target_arch'):
                self._arch_mode = "x64" if self._session.target_arch == 64 else "x86"
            else:
                import struct
                self._arch_mode = "x64" if struct.calcsize("P") == 8 else "x86"
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

    @staticmethod
    def _make_operand(op):
        """Detach one capstone operand into a plain Operand.

        Values are taken at full width. The prototype this is ported from
        masked both immediate and displacement to 32 bits, which is wrong twice
        over: an x64 image's addresses (0x140000000) mask to 0, and a negative
        displacement becomes 0xFFFFF000-shaped nonsense. Widening is the
        consumer's job — it knows the image base and the address window.
        """
        if op.type == capstone.x86.X86_OP_REG:
            return Operand(kind=OP_REG, size=op.size, reg=op.reg)
        if op.type == capstone.x86.X86_OP_IMM:
            return Operand(kind=OP_IMM, size=op.size, imm=op.imm)
        mem = op.mem
        return Operand(kind=OP_MEM, size=op.size, mem_segment=mem.segment,
                       mem_base=mem.base, mem_index=mem.index,
                       mem_scale=mem.scale, mem_disp=mem.disp)

    def _make_instruction(self, insn):
        groups = [insn.group_name(g) for g in insn.groups]
        is_jmp = 'jump' in groups
        is_call = 'call' in groups
        is_ret = 'ret' in groups
        is_cond = is_jmp and insn.mnemonic not in self._UNCONDITIONAL_JUMPS
        # cs.detail is already True, so operands cost a small dataclass each
        # rather than another decode pass.
        operands = tuple(self._make_operand(op) for op in insn.operands)
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
            operands=operands,
            insn_id=insn.id,
        )
