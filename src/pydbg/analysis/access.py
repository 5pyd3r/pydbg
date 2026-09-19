"""Access traces — which offsets of which base register a function touches.

The raw material for structure recovery, and the honest half of it. What this
can say is "inside function F, the register ebx is used as a base at offsets
0x8, 0xc and 0x18, the first two as 4-byte values and the third called
through". What it cannot say is "ebx is `this`, so this is class TNode's field
table" — which register holds the object is not statically determinable, and a
report that guessed would read exactly like one that knew.

So the unit here is a (function, base register) pair, not a class.
"""

from dataclasses import dataclass, field

from ..disasm.engine import ACC_WRITE, OP_MEM, DisasmEngine

# Registers whose `[... + disp]` form addresses the stack, not a structure.
# Every function has one, so counting them would make every function look like
# it had a structure at frame pointer + something.
STACK_REGISTERS = frozenset((
    "esp", "ebp",                      # 32-bit frame and stack pointers
    "rsp", "rbp", "r13",               # 64-bit, r13 often a frame pointer
    "eip", "rip",                      # instruction-relative is not a base
))

# A base register used at this many distinct offsets inside one function is
# behaving like a pointer to a structure. Two is the floor: one offset is just
# as likely to be a lone global reached through a register.
STRUCTURE_MIN_OFFSETS = 3


@dataclass(frozen=True, slots=True)
class Access:
    """One memory access through a base register."""

    rva: int             # the instruction making it
    function: int        # the function containing it, or -1
    base_reg: str        # register name, not id
    offset: int          # displacement from the base
    size: int            # bytes accessed
    is_write: bool
    called: bool = False  # the value loaded here is branched to


@dataclass
class FieldUse:
    """What one offset of one base register is used as."""

    offset: int
    size: int = 0
    reads: int = 0
    writes: int = 0
    called: bool = False

    def observe(self, access):
        self.size = max(self.size, access.size)
        if access.is_write:
            self.writes += 1
        else:
            self.reads += 1
        self.called = self.called or access.called

    @property
    def kind(self):
        """A cautious description of what this field appears to hold."""
        if self.called:
            return "function pointer"
        if self.size >= 8:
            return "64-bit value"
        if self.size == 4:
            return "32-bit value"
        if self.size == 2:
            return "16-bit value"
        if self.size == 1:
            return "byte"
        return "unknown"

    @property
    def written(self):
        return self.writes > 0


@dataclass
class StructureProfile:
    """One base register's offsets within one function."""

    function: int
    base_reg: str
    fields: dict = field(default_factory=dict)   # offset -> FieldUse
    accesses: int = 0

    def observe(self, access):
        use = self.fields.get(access.offset)
        if use is None:
            use = FieldUse(offset=access.offset)
            self.fields[access.offset] = use
        use.observe(access)
        self.accesses += 1

    @property
    def offsets(self):
        return sorted(self.fields)

    @property
    def span(self):
        """Bytes from 0 to the end of the furthest field."""
        if not self.fields:
            return 0
        return max(offset + use.size for offset, use in self.fields.items())

    @property
    def looks_like_a_structure(self):
        return len(self.fields) >= STRUCTURE_MIN_OFFSETS

    def rows(self):
        """(offset, kind, size, reads, writes) per field, ascending."""
        return [(offset, use.kind, use.size, use.reads, use.writes)
                for offset, use in sorted(self.fields.items())]


def base_relative_access(insn, stack_ids=frozenset()):
    """(register id, offset, size, access flags, is_branch) for `[reg + disp]`.

    A free function of one instruction, so the analyzer can record accesses
    during the sweep it is already doing rather than decoding everything a
    second time afterwards. What is returned is the register *id*; names need
    capstone and are resolved once at the end.

    'lea' is excluded. It reports a memory operand — and capstone marks that
    operand read — but it touches no memory: `lea eax, [ebx+0x10]` computes an
    address. Recording it as a read would say a field is read where the code
    only took its address, which is a different fact, and often the more
    interesting one.

    Only `[reg + disp]` counts. An indexed form is `[reg + reg*scale + disp]`,
    whose displacement is not a field offset but a table entry, so treating it
    as one would invent a field at every switch statement.
    """
    if insn.mnemonic == "lea":
        return None
    for operand in insn.operands:
        if operand.kind != OP_MEM or operand.mem_segment != 0:
            continue
        if operand.mem_base == 0 or operand.mem_index != 0:
            continue
        if operand.mem_base in stack_ids:
            continue
        branch = bool(insn.is_call or insn.is_jmp)
        return (operand.mem_base, operand.mem_disp, operand.size,
                operand.access, branch)
    return None


def collect_accesses(result, stack_registers=STACK_REGISTERS):
    """Every `[reg + disp]` access in the decoded code.

    Comes from what the sweep recorded, so the cost is a lookup rather than a
    second decode pass. Falls back to walking the decode when a result was
    produced with collection switched off.
    """
    engine = DisasmEngine(mode=result.image.mode)
    functions = result.functions
    recorded = getattr(result, "access_records", None)
    if recorded is None:
        recorded = _replay(result, stack_registers)

    found = []
    for rva, reg_id, offset, size, access, branch in recorded:
        name = engine.reg_name(reg_id)
        if not name or name in stack_registers:
            continue
        found.append(Access(
            rva=rva,
            function=functions.containing(rva) if functions else -1,
            base_reg=name,
            offset=offset,
            size=size,
            # A read-modify-write operand is marked both; counting it as a
            # write is the more informative reading, since a field that is
            # never written is the more unusual thing to find.
            is_write=bool(access & ACC_WRITE),
            called=branch,
        ))
    return tuple(found)


def _replay(result, stack_registers):
    """Re-derive accesses by walking the decode, when none were recorded.

    Register names are not available here, so the stack filter is applied on
    the ids instead — see stack_register_ids.
    """
    decoder = result.decoder
    ids = stack_register_ids(result.image.mode, stack_registers,
                             DisasmEngine(mode=result.image.mode))
    out = []
    for rva in decoder.decoded_rvas():
        insn = decoder.decode_one(rva)
        if insn is None:
            continue
        resolved = base_relative_access(insn, stack_ids=ids)
        if resolved is not None:
            out.append((rva,) + resolved)
    return out


def stack_register_ids(mode, names, engine=None):
    """Capstone ids for the stack registers of 'mode'."""
    engine = engine or DisasmEngine(mode=mode)
    return frozenset(reg for reg in range(1, 300)
                     if engine.reg_name(reg) in names)


def profiles(result, accesses=None, min_offsets=None):
    """(function, base register) -> StructureProfile, ascending.

    Filtered to plausible structures by default: a register touched at one or
    two offsets is a pointer to somewhere, not a structure layout.
    """
    threshold = STRUCTURE_MIN_OFFSETS if min_offsets is None else min_offsets
    grouped = {}
    for access in (accesses if accesses is not None else collect_accesses(result)):
        key = (access.function, access.base_reg)
        profile = grouped.get(key)
        if profile is None:
            profile = StructureProfile(function=access.function,
                                       base_reg=access.base_reg)
            grouped[key] = profile
        profile.observe(access)
    return {key: profile for key, profile in sorted(grouped.items())
            if len(profile.fields) >= threshold}
