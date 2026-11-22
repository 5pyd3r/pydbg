"""The decompiler's IR, and the lift from decoded instructions (S1).

One decoded instruction becomes one or more statements; anything outside the
integer subset in docs/analysis-coverage.md §7.4 becomes an `Opaque` statement
carrying its original text. Opaque is the point: a gap in the model stays
visible in the output instead of being rounded off, the same rule the coverage
report follows for undecoded bytes. Nothing is dropped silently.

Addresses in the IR are RVAs. A decoded `Instruction` speaks VAs, because
capstone derives branch targets from the base it is handed while a memory
displacement is absolute — the conversion happens once, in `branch_target` and
`AnalyzedImage.va_to_rva`, and the IR never mixes the two again.

EFLAGS are pseudo-registers (`eflags.zf`, ...). An instruction that writes flags
is declared to write all six: conservative, and honest, because the individual
flags are not modelled beyond the `jcc` condition table. A conditional branch
declares only the flags its condition actually reads.
"""

from dataclasses import dataclass

from ...disasm.engine import OP_IMM, OP_MEM, OP_REG
from ..refs import branch_target, is_indirect_branch, memory_address

# ── expressions ────────────────────────────────────────────────


class Expr:
    """Marker base for the expression tree.

    The concrete nodes are frozen dataclasses so an expression can be compared,
    hashed and rebuilt without a caller worrying that a later pass mutated the
    one it was holding.
    """


@dataclass(frozen=True)
class Const(Expr):
    """An integer literal, as written by the instruction."""

    value: int


@dataclass(frozen=True)
class Addr(Expr):
    """A code or data address that is an absolute value, rendered in hex.

    Distinct from `Const` so a reader can tell `eax = 5` from `eax = 0x401000`
    without knowing where the expression came from.
    """

    value: int


@dataclass(frozen=True)
class Reg(Expr):
    """A register name as the decoder spells it, with its operand width."""

    name: str
    width: int = 0


@dataclass(frozen=True)
class Mem(Expr):
    """A memory operand: segment, base, index, scale, displacement, width.

    A fixed-address operand (`[disp]` or `[rip + disp]`) is resolved once, in
    the lift, through `refs.memory_address` -- the analysis's single operand-to-
    RVA conversion point -- and carried as `addr`. A base/index form has no
    `addr`: its components stay symbolic because the register values are not
    known here. Keeping the two apart is what lets the renderer print an
    address without repeating the `rip + size + disp` arithmetic.
    """

    size: int = 0
    base: Expr | None = None
    index: Expr | None = None
    scale: int = 1
    disp: int = 0
    segment: str = ""
    addr: int | None = None


@dataclass(frozen=True)
class BinExpr(Expr):
    """A binary operation, already in the operator spelling the text uses."""

    op: str
    left: Expr
    right: Expr


@dataclass(frozen=True)
class UnExpr(Expr):
    """A unary operation: `-`, `~`, or the flag negation `!`."""

    op: str
    operand: Expr


# ── statements ─────────────────────────────────────────────────


class Stmt:
    """Marker base; every statement carries the RVA of its instruction.

    The RVA is how the renderer annotates a line, and how a test can check that
    every decoded instruction is still visible somewhere in the text.
    """

    rva: int


@dataclass(frozen=True)
class Assign(Stmt):
    """`dst = src`, for a register destination."""

    rva: int
    dst: str
    src: Expr


@dataclass(frozen=True)
class BinOp(Stmt):
    """`dst = left <op> right`, for an arithmetic or logical instruction.

    'flags_written' is the EFLAGS pseudo-register tuple the instruction
    defines. Arithmetic has side effects beyond its destination, so this is
    also why such a statement is never a candidate for the dead-write pass.
    """

    rva: int
    dst: str
    op: str
    left: Expr
    right: Expr
    flags_written: tuple = ()


@dataclass(frozen=True)
class UnOp(Stmt):
    """`dst = <op> operand`, for `neg` and `not`.

    `neg` writes all six flags; `not` touches none, so 'flags_written' is
    empty for it.
    """

    rva: int
    dst: str
    op: str
    operand: Expr
    flags_written: tuple = ()


@dataclass(frozen=True)
class Load(Stmt):
    """`dst = <addr>` where addr is a memory expression (`mov reg, [mem]`)."""

    rva: int
    dst: str
    addr: Expr


@dataclass(frozen=True)
class Store(Stmt):
    """`<addr> = value` (`mov [mem], reg`, `push`, arithmetic into memory)."""

    rva: int
    addr: Expr
    value: Expr
    flags_written: tuple = ()


@dataclass(frozen=True)
class Cmp(Stmt):
    """A flag-setting comparison (`cmp` / `test`).

    Kept as its own statement rather than expanded into six flag assignments:
    the flags are pseudo-registers, and the comparison is the expression the
    structure pass will want when it turns a branch into an `if`.
    """

    rva: int
    op: str
    left: Expr
    right: Expr
    flags_written: tuple = ()


@dataclass(frozen=True)
class Branch(Stmt):
    """A jump, with its condition when it has one and its target when known.

    `kind` is ``jcc``, ``jmp`` or ``indirect``. A ``jcc`` keeps `cond` as a
    flag expression; turning that into a structured `if` is the next ticket's
    job, not this one's. `target` is None for a branch whose destination the
    analysis could not resolve, which is a statement about the analysis and not
    about the instruction.

    'flags_read' is the subset of EFLAGS pseudo-registers the condition table
    says this branch's condition actually reads (`je` -> zf, `ja` -> cf+zf).
    An unconditional or indirect branch reads none.

    'comparison' is the same table's C operator for the condition (`==`, `<`,
    ...), or None when the condition has no exact C spelling. The structure
    pass folds `cmp` + branch through this field instead of re-deriving the
    operator from `cond`, so the two cannot disagree.
    """

    rva: int
    cond: Expr | None
    target: int | None
    kind: str
    text: str = ""
    flags_read: tuple = ()
    comparison: str | None = None


@dataclass(frozen=True)
class Call(Stmt):
    """A call, direct (target RVA) or indirect (`text` is the operand)."""

    rva: int
    target: int | None
    text: str = ""
    indirect: bool = False


@dataclass(frozen=True)
class Ret(Stmt):
    """A return, optionally carrying the value recovery gave it."""

    rva: int
    value: Expr | None = None


@dataclass(frozen=True)
class Opaque(Stmt):
    """An instruction outside the model, kept with its original spelling."""

    rva: int
    text: str
    mnemonic: str = ""


@dataclass(frozen=True)
class Nop(Stmt):
    """`nop`, which is in the support subset and does nothing."""

    rva: int


@dataclass(frozen=True)
class IRBlock:
    """One basic block's statements, in address order.

    `dead` holds pure register writes that a later write in the same block
    overwrote before any read. They are kept out of `stmts` -- they carry no
    meaning for a structuring pass -- but they are not discarded: the renderer
    prints them as comments, because an instruction must never leave the text.
    """

    rva: int
    stmts: tuple
    dead: tuple = ()


# ── EFLAGS as pseudo-registers ─────────────────────────────────

EFLAGS = ("cf", "pf", "af", "zf", "sf", "of")
EFLAGS_REGISTERS = tuple("eflags." + flag for flag in EFLAGS)

# Every statement that writes flags writes all six: the per-flag effects are
# not modelled, so claiming a subset would be a false precision.
ALL_FLAGS = EFLAGS_REGISTERS

# Instructions that write flags. `not` is absent on purpose: it touches no
# flags, and claiming otherwise would make a later condition look newer than it
# is. `inc`/`dec` really leave CF alone but are declared with all six, which is
# the conservative direction the spec asks for.
FLAG_WRITERS = frozenset(
    ("add", "sub", "and", "or", "xor", "imul", "inc", "dec", "neg", "cmp",
     "test")
)


def _flag(name):
    return Reg("eflags." + name, width=1)


def _not(expr):
    return UnExpr("!", expr)


def _and(left, right):
    return BinExpr("&&", left, right)


def _or(left, right):
    return BinExpr("||", left, right)


_ZF = _flag("zf")
_CF = _flag("cf")
_SF = _flag("sf")
_OF = _flag("of")
_PF = _flag("pf")

# mnemonic -> (condition expression, flags the condition reads, C operator).
#
# The spellings that share a condition are listed separately rather than
# aliased through a canonical mnemonic: capstone emits whichever spelling the
# assembler used, and a table that only knew `je` would turn `jz` into an
# unhandled instruction.
#
# The third field is the operator `structure.fold_compare` uses, and it lives
# here rather than being re-derived from the flag expression: two tables would
# drift, and the drift would silently stop folding instead of failing. Only
# relations with an exact C spelling are listed -- unsigned ones (`jb`/`ja`)
# stay None because `eax < 5` would claim a signedness the instruction did not
# state.
_CONDITIONS = {
    "je": (_ZF, ("zf",), "=="),
    "jz": (_ZF, ("zf",), "=="),
    "jne": (_not(_ZF), ("zf",), "!="),
    "jnz": (_not(_ZF), ("zf",), "!="),
    "js": (_SF, ("sf",), None),
    "jns": (_not(_SF), ("sf",), None),
    "jo": (_OF, ("of",), None),
    "jno": (_not(_OF), ("of",), None),
    "jp": (_PF, ("pf",), None),
    "jpe": (_PF, ("pf",), None),
    "jnp": (_not(_PF), ("pf",), None),
    "jpo": (_not(_PF), ("pf",), None),
    "jb": (_CF, ("cf",), None),
    "jnae": (_CF, ("cf",), None),
    "jc": (_CF, ("cf",), None),
    "jae": (_not(_CF), ("cf",), None),
    "jnb": (_not(_CF), ("cf",), None),
    "jnc": (_not(_CF), ("cf",), None),
    "jbe": (_or(_CF, _ZF), ("cf", "zf"), None),
    "jna": (_or(_CF, _ZF), ("cf", "zf"), None),
    "ja": (_and(_not(_CF), _not(_ZF)), ("cf", "zf"), None),
    "jnbe": (_and(_not(_CF), _not(_ZF)), ("cf", "zf"), None),
    "jl": (BinExpr("!=", _SF, _OF), ("sf", "of"), "<"),
    "jnge": (BinExpr("!=", _SF, _OF), ("sf", "of"), "<"),
    "jge": (BinExpr("==", _SF, _OF), ("sf", "of"), ">="),
    "jnl": (BinExpr("==", _SF, _OF), ("sf", "of"), ">="),
    "jle": (_or(_ZF, BinExpr("!=", _SF, _OF)), ("zf", "sf", "of"), "<="),
    "jng": (_or(_ZF, BinExpr("!=", _SF, _OF)), ("zf", "sf", "of"), "<="),
    "jg": (_and(_not(_ZF), BinExpr("==", _SF, _OF)), ("zf", "sf", "of"), ">"),
    "jnle": (_and(_not(_ZF), BinExpr("==", _SF, _OF)), ("zf", "sf", "of"), ">"),
}

# The count-is-zero family is not a flag condition: it compares a register with
# zero directly, so it reads no flags at all.
_COUNT_ZERO = {"jcxz": "cx", "jecxz": "ecx", "jrcxz": "rcx"}


def condition_for(mnemonic):
    """The condition `mnemonic` branches on, or None when it is not modelled.

    None is the honest answer for the loop family and anything else outside the
    condition table; the caller turns that into an Opaque statement rather than
    inventing a condition.
    """
    if mnemonic in _COUNT_ZERO:
        return BinExpr("==", Reg(_COUNT_ZERO[mnemonic]), Const(0))
    entry = _CONDITIONS.get(mnemonic)
    return entry[0] if entry is not None else None


def flags_read(mnemonic):
    """The flag pseudo-registers `mnemonic`'s condition actually reads."""
    if mnemonic in _COUNT_ZERO:
        return ()
    entry = _CONDITIONS.get(mnemonic)
    return entry[1] if entry is not None else ()


def comparison_for(mnemonic):
    """The C operator `mnemonic`'s condition means, or None when it has none.

    The third column of the same table `condition_for` and `flags_read` read:
    the structure pass folds `cmp` + branch using this answer, so the operator
    cannot drift away from the expression it came from. The count-is-zero
    family has no flag condition at all and therefore no operator either.
    """
    if mnemonic in _COUNT_ZERO:
        return None
    entry = _CONDITIONS.get(mnemonic)
    return entry[2] if entry is not None else None


def flags_written(mnemonic):
    """The flag pseudo-registers `mnemonic` writes, or () when it writes none.

    All six for every arithmetic/logic instruction, as the spec requires: the
    per-flag effects are not modelled, so claiming a subset would be a false
    precision.
    """
    return ALL_FLAGS if mnemonic in FLAG_WRITERS else ()


# ── lowering ───────────────────────────────────────────────────

_BINARY_OPS = {
    "add": "+",
    "sub": "-",
    "and": "&",
    "or": "|",
    "xor": "^",
}


def _reg(decoder, reg_id, width=0):
    return Reg(decoder.reg_name(reg_id), width)


def _mem(decoder, image, insn, op):
    """The memory expression an operand stands for.

    A fixed-address form is resolved by `refs.memory_address` and carried as
    an RVA; only the symbolic base/index form is composed here, because that
    composition is the one thing the analysis cannot resolve.
    """
    address = memory_address(insn, op, image)
    if address is not None:
        return Mem(size=op.size, addr=address)
    base = _reg(decoder, op.mem_base) if op.mem_base else None
    index = _reg(decoder, op.mem_index) if op.mem_index else None
    segment = decoder.reg_name(op.mem_segment) if op.mem_segment else ""
    return Mem(size=op.size, base=base, index=index,
               scale=op.mem_scale or 1, disp=op.mem_disp,
               segment=segment)


def _operand(decoder, image, insn, op):
    """The expression an operand stands for, reading memory as `[mem]`."""
    if op.kind == OP_REG:
        return _reg(decoder, op.reg, op.size)
    if op.kind == OP_IMM:
        return Const(op.imm)
    return _mem(decoder, image, insn, op)


def _effective_address(decoder, image, insn, op):
    """The value `lea` would put in its destination.

    A fixed-address form is the RVA `refs.memory_address` answers: that is the
    single place an operand becomes an RVA, and re-deriving `rip + size +
    disp` here would be the address-space mistake the analysis already made
    once. A base/index form stays symbolic: the decompiler does not know the
    register's value and must not pretend to.
    """
    address = memory_address(insn, op, image)
    if address is not None:
        return Addr(address)

    parts = []
    if op.mem_base:
        parts.append(_reg(decoder, op.mem_base))
    if op.mem_index:
        index = _reg(decoder, op.mem_index)
        if op.mem_scale and op.mem_scale != 1:
            index = BinExpr("*", index, Const(op.mem_scale))
        parts.append(index)
    if not parts:
        return Addr(op.mem_disp)

    expr = parts[0]
    for part in parts[1:]:
        expr = BinExpr("+", expr, part)
    if op.mem_disp:
        op_symbol, value = ("+", op.mem_disp) if op.mem_disp > 0 else ("-", -op.mem_disp)
        expr = BinExpr(op_symbol, expr, Const(value))
    return expr


def _opaque(insn, rva):
    text = insn.mnemonic
    if insn.op_str:
        text += " " + insn.op_str
    return Opaque(rva=rva, text=text, mnemonic=insn.mnemonic)


def _is_general_register(name):
    """Whether 'name' is one of the general-purpose registers the model knows.

    `expr` owns the register-alias table, but it imports this module, so the
    lookup is local to this function. A control, debug or segment register is
    not a GPR: writing one changes machine state the integer model does not
    describe, so `mov` to it must stay Opaque rather than become a statement
    the dead-write pass is free to discard.
    """
    from .expr import FAMILIES, family

    return family(name) in FAMILIES


def _lower_mov(decoder, image, insn, rva):
    ops = insn.operands
    if len(ops) != 2:
        return None
    dst, src = ops
    if dst.kind == OP_REG:
        name = decoder.reg_name(dst.reg)
        if not _is_general_register(name):
            return None
        if src.kind == OP_MEM:
            return (Load(rva=rva, dst=name, addr=_mem(decoder, image, insn, src)),)
        return (Assign(rva=rva, dst=name, src=_operand(decoder, image, insn, src)),)
    if dst.kind == OP_MEM:
        return (Store(rva=rva, addr=_mem(decoder, image, insn, dst),
                      value=_operand(decoder, image, insn, src)),)
    return None


def _lower_lea(decoder, image, insn, rva):
    ops = insn.operands
    if len(ops) != 2 or ops[0].kind != OP_REG or ops[1].kind != OP_MEM:
        return None
    return (Assign(rva=rva, dst=decoder.reg_name(ops[0].reg),
                   src=_effective_address(decoder, image, insn, ops[1])),)


def _lower_binary(decoder, image, insn, rva):
    ops = insn.operands
    if len(ops) != 2:
        return None
    dst, src = ops
    symbol = _BINARY_OPS[insn.mnemonic]
    if dst.kind == OP_REG:
        name = decoder.reg_name(dst.reg)
        return (BinOp(rva=rva, dst=name, op=symbol,
                      left=_reg(decoder, dst.reg, dst.size),
                      right=_operand(decoder, image, insn, src),
                      flags_written=flags_written(insn.mnemonic)),)
    if dst.kind == OP_MEM:
        addr = _mem(decoder, image, insn, dst)
        return (Store(rva=rva, addr=addr,
                      value=BinExpr(symbol, addr,
                                    _operand(decoder, image, insn, src)),
                      flags_written=flags_written(insn.mnemonic)),)
    return None


def _lower_imul(decoder, image, insn, rva):
    ops = insn.operands
    if len(ops) == 1:
        return None              # implicit edx:eax; not modelled
    if len(ops) == 3:
        dst, src, multiplier = ops
        if dst.kind != OP_REG:
            return None
        return (BinOp(rva=rva, dst=decoder.reg_name(dst.reg), op="*",
                      left=_operand(decoder, image, insn, src),
                      right=_operand(decoder, image, insn, multiplier),
                      flags_written=flags_written(insn.mnemonic)),)
    if len(ops) != 2:
        return None
    dst, src = ops
    if dst.kind == OP_REG:
        name = decoder.reg_name(dst.reg)
        return (BinOp(rva=rva, dst=name, op="*",
                      left=_reg(decoder, dst.reg, dst.size),
                      right=_operand(decoder, image, insn, src),
                      flags_written=flags_written(insn.mnemonic)),)
    if dst.kind == OP_MEM:
        addr = _mem(decoder, image, insn, dst)
        return (Store(rva=rva, addr=addr,
                      value=BinExpr("*", addr,
                                    _operand(decoder, image, insn, src)),
                      flags_written=flags_written(insn.mnemonic)),)
    return None


def _lower_unary(decoder, image, insn, rva):
    """`inc` / `dec` / `neg` / `not` — one operand, register or memory."""
    ops = insn.operands
    if len(ops) != 1:
        return None
    dst = ops[0]
    name = insn.mnemonic
    if name in ("inc", "dec"):
        symbol = "+" if name == "inc" else "-"
        if dst.kind == OP_REG:
            reg_name = decoder.reg_name(dst.reg)
            return (BinOp(rva=rva, dst=reg_name, op=symbol,
                          left=_reg(decoder, dst.reg, dst.size),
                          right=Const(1),
                          flags_written=flags_written(name)),)
        if dst.kind == OP_MEM:
            addr = _mem(decoder, image, insn, dst)
            return (Store(rva=rva, addr=addr,
                          value=BinExpr(symbol, addr, Const(1)),
                          flags_written=flags_written(name)),)
        return None
    symbol = "-" if name == "neg" else "~"
    if dst.kind == OP_REG:
        reg_name = decoder.reg_name(dst.reg)
        return (UnOp(rva=rva, dst=reg_name, op=symbol,
                     operand=_reg(decoder, dst.reg, dst.size),
                     flags_written=flags_written(name)),)
    if dst.kind == OP_MEM:
        addr = _mem(decoder, image, insn, dst)
        return (Store(rva=rva, addr=addr,
                      value=UnExpr(symbol, addr),
                      flags_written=flags_written(name)),)
    return None


def _lower_cmp(decoder, image, insn, rva):
    ops = insn.operands
    if len(ops) != 2:
        return None
    return (Cmp(rva=rva, op=insn.mnemonic,
                left=_operand(decoder, image, insn, ops[0]),
                right=_operand(decoder, image, insn, ops[1]),
                flags_written=flags_written(insn.mnemonic)),)


def _lower_jcc(decoder, image, insn, rva):
    cond = condition_for(insn.mnemonic)
    if cond is None:
        return None
    return (Branch(rva=rva, cond=cond,
                   target=branch_target(insn, image), kind="jcc",
                   text=insn.op_str, flags_read=flags_read(insn.mnemonic),
                   comparison=comparison_for(insn.mnemonic)),)


def _lower_jmp(decoder, image, insn, rva):
    if is_indirect_branch(insn) or branch_target(insn, image) is None:
        return (Branch(rva=rva, cond=None, target=None, kind="indirect",
                       text=insn.op_str),)
    return (Branch(rva=rva, cond=None,
                   target=branch_target(insn, image), kind="jmp",
                   text=insn.op_str),)


def _lower_call(decoder, image, insn, rva):
    target = branch_target(insn, image)
    return (Call(rva=rva, target=target, text=insn.op_str,
                 indirect=target is None),)


def _stack_pointer(image):
    """The stack pointer's spelling for this image's architecture."""
    return "rsp" if image.mode == "x64" else "esp"


def _lower_push(decoder, image, insn, rva):
    """`push x`: store below the stack pointer, then move the pointer.

    Two statements for one instruction, because the store and the pointer move
    are two effects. The stack pointer is modelled exactly here and nowhere
    else: no frame reconstruction, so a later pop still reads `[rsp]` rather
    than a named local. The width comes from the operand, so `push ax` moves
    two bytes while `push rax` moves eight.
    """
    ops = insn.operands
    if len(ops) != 1:
        return None
    slot = ops[0].size or image.slot_size
    stack = _stack_pointer(image)
    addr = Mem(size=slot, base=Reg(stack, slot), disp=-slot)
    value = _operand(decoder, image, insn, ops[0])
    return (Store(rva=rva, addr=addr, value=value),
            Assign(rva=rva, dst=stack,
                   src=BinExpr("-", Reg(stack, slot), Const(slot))))


def _lower_pop(decoder, image, insn, rva):
    ops = insn.operands
    if len(ops) != 1:
        return None
    slot = ops[0].size or image.slot_size
    stack = _stack_pointer(image)
    addr = Mem(size=slot, base=Reg(stack, slot))
    dst = ops[0]
    if dst.kind == OP_REG:
        name = decoder.reg_name(dst.reg)
        loaded = Load(rva=rva, dst=name, addr=addr)
        if name == stack:
            # `pop rsp` loads the pointer itself; adding the slot afterwards
            # would move it twice.
            return (loaded,)
    elif dst.kind == OP_MEM:
        loaded = Store(rva=rva, addr=_mem(decoder, image, insn, dst), value=addr)
    else:
        return None
    return (loaded,
            Assign(rva=rva, dst=stack,
                   src=BinExpr("+", Reg(stack, slot), Const(slot))))


def lower_instruction(decoder, image, insn):
    """The statements one decoded instruction becomes.

    Returns a tuple with at least one element: when the instruction is outside
    the support subset, or is an unsupported *form* of a supported mnemonic
    (one-operand `imul`, say), the result is an Opaque statement and never an
    empty tuple.
    """
    rva = image.va_to_rva(insn.address)
    if rva is None:
        return (Opaque(rva=insn.address,
                       text=f"instruction outside the image: {insn.mnemonic} "
                            f"{insn.op_str}",
                       mnemonic=insn.mnemonic),)

    name = insn.mnemonic
    if name in ("mov", "movabs"):
        stmts = _lower_mov(decoder, image, insn, rva)
    elif name == "lea":
        stmts = _lower_lea(decoder, image, insn, rva)
    elif name in _BINARY_OPS:
        stmts = _lower_binary(decoder, image, insn, rva)
    elif name == "imul":
        stmts = _lower_imul(decoder, image, insn, rva)
    elif name in ("inc", "dec", "neg", "not"):
        stmts = _lower_unary(decoder, image, insn, rva)
    elif name in ("cmp", "test"):
        stmts = _lower_cmp(decoder, image, insn, rva)
    elif name in _CONDITIONS or name in _COUNT_ZERO:
        stmts = _lower_jcc(decoder, image, insn, rva)
    elif name == "jmp":
        stmts = _lower_jmp(decoder, image, insn, rva)
    elif name == "call":
        stmts = _lower_call(decoder, image, insn, rva)
    elif name == "ret":
        stmts = (Ret(rva=rva),)
    elif name == "push":
        stmts = _lower_push(decoder, image, insn, rva)
    elif name == "pop":
        stmts = _lower_pop(decoder, image, insn, rva)
    elif name == "nop":
        stmts = (Nop(rva=rva),)
    else:
        stmts = None

    if not stmts:
        return (_opaque(insn, rva),)
    return stmts


def lower_block(decoder, image, block):
    """Lower one CFG block. Every instruction contributes at least one stmt."""
    stmts = []
    for rva in block.instructions:
        insn = decoder.decode_one(rva)
        if insn is None:
            # The CFG only walks decoded instructions, so this is defensive:
            # if it ever happens the address still reaches the text.
            stmts.append(Opaque(rva=rva,
                                text=f"undecodable instruction at 0x{rva:x}",
                                mnemonic=""))
            continue
        stmts.extend(lower_instruction(decoder, image, insn))
    return IRBlock(rva=block.rva, stmts=tuple(stmts))
