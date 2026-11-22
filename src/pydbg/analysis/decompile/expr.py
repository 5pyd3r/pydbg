"""S2 -- block-local expression recovery.

Straight-line blocks only. A value defined in one block is never carried into
another: at a join the honest answer is the register name, and a value-numbering
pass that guessed would produce a confident-looking expression where the
analysis actually lost track. Cross-block dataflow is a later stage with its own
semantics for "unknown".

Four transformations, applied in one pass per block:

- **sub-register aliasing**: `al`/`ax`/`eax`/`rax` name one storage family, so a
  write to any of them kills what was known about all of them. The displayed
  name stays the one the instruction used; only the dataflow is normalised.
- **copy propagation**: a register-to-register move is substituted into later
  reads in the same block, until an instruction writes either side.
- **constant propagation and folding**: a constant is substituted into later
  reads, *except* the destination of a read-modify-write. That exception is
  deliberate: `add eax, 3` keeps the spelling `eax = eax + 3`, so the update
  stays visible instead of collapsing into `eax = 8`.
- **dead assignment**: a pure register write that a later write in the same
  block overwrites before any read moves to `IRBlock.dead`. It is not dropped:
  the renderer prints it as a comment, because an instruction that disappears
  from the text is exactly the silent loss the spec forbids. Only writes with
  no other effect qualify -- arithmetic also sets flags, so it stays even when
  its register result is unused.
"""

from dataclasses import replace

from .ir import (
    Assign, BinExpr, BinOp, Branch, Call, Cmp, Const, IRBlock, Load, Mem,
    Nop, Opaque, Reg, Ret, Store, UnExpr, UnOp,
)

# name -> (storage family, width in bytes). Registers in one family alias each
# other; families are what a write actually kills.
_ALIAS_GROUPS = {
    "rax": (("rax", 8), ("eax", 4), ("ax", 2), ("al", 1), ("ah", 1)),
    "rbx": (("rbx", 8), ("ebx", 4), ("bx", 2), ("bl", 1), ("bh", 1)),
    "rcx": (("rcx", 8), ("ecx", 4), ("cx", 2), ("cl", 1), ("ch", 1)),
    "rdx": (("rdx", 8), ("edx", 4), ("dx", 2), ("dl", 1), ("dh", 1)),
    "rsi": (("rsi", 8), ("esi", 4), ("si", 2), ("sil", 1)),
    "rdi": (("rdi", 8), ("edi", 4), ("di", 2), ("dil", 1)),
    "rbp": (("rbp", 8), ("ebp", 4), ("bp", 2), ("bpl", 1)),
    "rsp": (("rsp", 8), ("esp", 4), ("sp", 2), ("spl", 1)),
    "r8": (("r8", 8), ("r8d", 4), ("r8w", 2), ("r8b", 1)),
    "r9": (("r9", 8), ("r9d", 4), ("r9w", 2), ("r9b", 1)),
    "r10": (("r10", 8), ("r10d", 4), ("r10w", 2), ("r10b", 1)),
    "r11": (("r11", 8), ("r11d", 4), ("r11w", 2), ("r11b", 1)),
    "r12": (("r12", 8), ("r12d", 4), ("r12w", 2), ("r12b", 1)),
    "r13": (("r13", 8), ("r13d", 4), ("r13w", 2), ("r13b", 1)),
    "r14": (("r14", 8), ("r14d", 4), ("r14w", 2), ("r14b", 1)),
    "r15": (("r15", 8), ("r15d", 4), ("r15w", 2), ("r15b", 1)),
}

_ALIASES = {name: (family, width)
            for family, members in _ALIAS_GROUPS.items()
            for name, width in members}

# The universe a block's liveness starts from. Every register is assumed live
# at a block's end because the successors are not consulted here: saying less is
# safe, saying more would delete a value another block still reads.
FAMILIES = frozenset(_ALIASES[name][0] for name in _ALIASES)

# The Windows x64 and x86 ABIs both return in the rax/eax family.
RETURN_FAMILY = "rax"


def family(name):
    """The storage family a register name belongs to ('rax' for 'al')."""
    return _ALIASES.get(name, (name, 0))[0]


def width(name):
    """The width in bytes of a register name, or 0 when it is not one."""
    return _ALIASES.get(name, (name, 0))[1]


def is_full_width(name):
    """Whether a write to 'name' defines the whole family.

    On x64 a 32-bit write zero-extends, so `mov eax, 5` does define `rax`; on
    both ABIs a 16- or 8-bit write leaves the upper bits in place and must not
    be treated as a definition of the family.
    """
    return width(name) >= 4


def return_register(mode):
    """The display name of the return register for an image mode."""
    return "rax" if mode == "x64" else "eax"


# ── expression helpers ─────────────────────────────────────────


def _has_memory(expr):
    if isinstance(expr, Mem):
        return True
    if isinstance(expr, BinExpr):
        return _has_memory(expr.left) or _has_memory(expr.right)
    if isinstance(expr, UnExpr):
        return _has_memory(expr.operand)
    return False


def _expr_families(expr):
    if isinstance(expr, Reg):
        return {family(expr.name)}
    if isinstance(expr, Mem):
        found = set()
        if expr.base is not None:
            found |= _expr_families(expr.base)
        if expr.index is not None:
            found |= _expr_families(expr.index)
        return found
    if isinstance(expr, BinExpr):
        return _expr_families(expr.left) | _expr_families(expr.right)
    if isinstance(expr, UnExpr):
        return _expr_families(expr.operand)
    return set()


def _eval_binary(op, left, right):
    """Fold one binary operation, or None when the operator is not folded."""
    if op == "+":
        return left + right
    if op == "-":
        return left - right
    if op == "*":
        return left * right
    if op == "&":
        return left & right
    if op == "|":
        return left | right
    if op == "^":
        return left ^ right
    if op == "<<":
        return left << right
    if op == ">>":
        return left >> right
    return None


def fold(expr):
    """Constant-fold an expression tree. Non-constant subtrees stay symbolic."""
    if isinstance(expr, BinExpr):
        left = fold(expr.left)
        right = fold(expr.right)
        if isinstance(left, Const) and isinstance(right, Const):
            value = _eval_binary(expr.op, left.value, right.value)
            if value is not None:
                return Const(value)
        if left is expr.left and right is expr.right:
            return expr
        return BinExpr(expr.op, left, right)
    if isinstance(expr, UnExpr):
        operand = fold(expr.operand)
        if isinstance(operand, Const):
            if expr.op == "-":
                return Const(-operand.value)
            if expr.op == "~":
                return Const(~operand.value)
            if expr.op == "!":
                return Const(0 if operand.value else 1)
        if operand is expr.operand:
            return expr
        return UnExpr(expr.op, operand)
    return expr


# ── the per-block pass ─────────────────────────────────────────


class _Recovery:
    def __init__(self, mode, returns_value):
        self.mode = mode
        self.returns_value = returns_value
        self.copies = {}       # exact register name -> Reg expression
        self.consts = {}       # family -> constant value
        self.return_name = None
        self.stmts = []

    def run(self, block):
        for stmt in block.stmts:
            self._step(stmt)
        live, dead = self._partition(self.stmts)
        return IRBlock(rva=block.rva, stmts=live, dead=dead)

    # ── state ──────────────────────────────────────────────

    def _kill(self, name):
        """Forget what was known about every alias of 'name'."""
        written = family(name)
        self.consts.pop(written, None)
        for key in [key for key in self.copies
                    if family(key) == written
                    or family(self.copies[key].name) == written]:
            del self.copies[key]

    def _note_return(self, name):
        if family(name) == RETURN_FAMILY and is_full_width(name):
            self.return_name = name

    def substitute(self, expr, skip_family=None, in_address=False):
        """Replace copied registers and known constants in 'expr'.

        'skip_family' keeps the destination of a read-modify-write as written:
        `add eax, 3` must not become `eax = 5 + 3`. Address components take
        register copies but never constants -- an address is not arithmetic.
        """
        if isinstance(expr, Reg):
            if skip_family is not None and family(expr.name) == skip_family:
                return expr
            copy = self.copies.get(expr.name)
            if copy is not None:
                return copy
            if not in_address:
                value = self.consts.get(family(expr.name))
                if value is not None and width(expr.name) >= 4:
                    return Const(value)
            return expr
        if isinstance(expr, Mem):
            base = expr.base
            index = expr.index
            if base is not None:
                base = self.substitute(base, skip_family, True)
            if index is not None:
                index = self.substitute(index, skip_family, True)
            if base is expr.base and index is expr.index:
                return expr
            return replace(expr, base=base, index=index)
        if isinstance(expr, BinExpr):
            left = self.substitute(expr.left, skip_family, in_address)
            right = self.substitute(expr.right, skip_family, in_address)
            if left is expr.left and right is expr.right:
                return expr
            return BinExpr(expr.op, left, right)
        if isinstance(expr, UnExpr):
            operand = self.substitute(expr.operand, skip_family, in_address)
            if operand is expr.operand:
                return expr
            return UnExpr(expr.op, operand)
        return expr

    # ── one statement ──────────────────────────────────────

    def _step(self, stmt):
        if isinstance(stmt, Assign):
            self._step_assign(stmt)
        elif isinstance(stmt, BinOp):
            self._step_binop(stmt)
        elif isinstance(stmt, UnOp):
            self._step_unop(stmt)
        elif isinstance(stmt, Load):
            self._kill(stmt.dst)
            self.stmts.append(Load(rva=stmt.rva, dst=stmt.dst,
                                   addr=self.substitute(stmt.addr)))
        elif isinstance(stmt, Store):
            self.stmts.append(Store(rva=stmt.rva,
                                    addr=self.substitute(stmt.addr),
                                    value=self.substitute(stmt.value)))
        elif isinstance(stmt, Cmp):
            self.stmts.append(Cmp(rva=stmt.rva, op=stmt.op,
                                  left=self.substitute(stmt.left),
                                  right=self.substitute(stmt.right)))
        elif isinstance(stmt, (Call, Opaque)):
            # A call returns a value in a register and may read any argument;
            # an Opaque instruction may do anything at all. Both make every
            # block-local fact unsafe, so both clear the state.
            self.copies.clear()
            self.consts.clear()
            self.stmts.append(stmt)
        elif isinstance(stmt, Ret):
            value = None
            if self.returns_value:
                value = Reg(self.return_name
                            or return_register(self.mode))
            self.stmts.append(Ret(rva=stmt.rva, value=value))
        elif isinstance(stmt, Nop):
            self.stmts.append(stmt)
        else:
            self.stmts.append(stmt)

    def _step_assign(self, stmt):
        src = self.substitute(stmt.src)
        self._kill(stmt.dst)
        self.stmts.append(Assign(rva=stmt.rva, dst=stmt.dst, src=src))
        self._note_return(stmt.dst)
        if isinstance(src, Reg):
            if family(src.name) != family(stmt.dst):
                self.copies[stmt.dst] = src
        elif isinstance(src, Const) and is_full_width(stmt.dst):
            self.consts[family(stmt.dst)] = src.value

    def _step_binop(self, stmt):
        skip = family(stmt.dst)
        left = self.substitute(stmt.left, skip)
        right = self.substitute(stmt.right, skip)
        self._kill(stmt.dst)
        expr = fold(BinExpr(stmt.op, left, right))
        self.stmts.append(_update(stmt.rva, stmt.dst, expr))
        self._note_return(stmt.dst)
        if isinstance(expr, Const) and is_full_width(stmt.dst):
            self.consts[family(stmt.dst)] = expr.value

    def _step_unop(self, stmt):
        skip = family(stmt.dst)
        operand = self.substitute(stmt.operand, skip)
        self._kill(stmt.dst)
        expr = fold(UnExpr(stmt.op, operand))
        self.stmts.append(_update(stmt.rva, stmt.dst, expr))
        self._note_return(stmt.dst)
        if isinstance(expr, Const) and is_full_width(stmt.dst):
            self.consts[family(stmt.dst)] = expr.value

    # ── dead assignments ───────────────────────────────────

    def _partition(self, stmts):
        """Split pure register writes that die in this block into `dead`."""
        live = set(FAMILIES)
        kept = []
        dead = []
        for stmt in reversed(stmts):
            dest = _pure_destination(stmt)
            if dest is not None and dest not in live:
                dead.append(stmt)
                continue
            kept.append(stmt)
            if dest is not None:
                live.discard(dest)
            live |= _read_families(stmt)
        kept.reverse()
        dead.reverse()
        return tuple(kept), tuple(dead)


def _update(rva, dst, expr):
    """The statement form that assigns 'expr' to register 'dst'."""
    if isinstance(expr, BinExpr):
        return BinOp(rva=rva, dst=dst, op=expr.op, left=expr.left,
                     right=expr.right)
    if isinstance(expr, UnExpr):
        return UnOp(rva=rva, dst=dst, op=expr.op, operand=expr.operand)
    return Assign(rva=rva, dst=dst, src=expr)


def _pure_destination(stmt):
    """The register family a statement defines, if defining it has no side effect.

    Only `mov`/`lea`-shaped assignments and `not` qualify. Arithmetic is
    excluded even when its result is unused, because every one of those
    instructions also writes EFLAGS: a later conditional branch may be reading
    the flags of a write whose register value is dead, and removing it would
    silently change which instruction the branch is about. A memory read can
    fault, so `Load` is never called dead either.
    """
    if isinstance(stmt, Assign):
        return None if _has_memory(stmt.src) else family(stmt.dst)
    if isinstance(stmt, UnOp) and stmt.op == "~":
        if _has_memory(stmt.operand):
            return None
        return family(stmt.dst)
    return None


def _read_families(stmt):
    """Register families a statement reads."""
    if isinstance(stmt, Assign):
        return _expr_families(stmt.src)
    if isinstance(stmt, BinOp):
        return _expr_families(stmt.left) | _expr_families(stmt.right)
    if isinstance(stmt, UnOp):
        return _expr_families(stmt.operand)
    if isinstance(stmt, Load):
        return _expr_families(stmt.addr)
    if isinstance(stmt, Store):
        return _expr_families(stmt.addr) | _expr_families(stmt.value)
    if isinstance(stmt, Cmp):
        return _expr_families(stmt.left) | _expr_families(stmt.right)
    if isinstance(stmt, Branch):
        return _expr_families(stmt.cond) if stmt.cond is not None else set()
    if isinstance(stmt, Ret):
        return _expr_families(stmt.value) if stmt.value is not None else set()
    if isinstance(stmt, (Call, Opaque)):
        # Unknown semantics may read anything; keeping values live is the
        # conservative direction.
        return set(FAMILIES)
    return set()


def _writes_return_register(stmt):
    if isinstance(stmt, Assign):
        name = stmt.dst
    elif isinstance(stmt, (BinOp, UnOp, Load)):
        name = stmt.dst
    else:
        return False
    return family(name) == RETURN_FAMILY and is_full_width(name)


def recover(blocks, mode):
    """Recover expressions and dead writes in every lowered block.

    'blocks' maps block RVA -> IRBlock. Returns the same shape. The
    function-wide return fact is computed first so a block that ends in `ret`
    knows whether any block established a return value.
    """
    returns_value = any(_writes_return_register(stmt)
                        for block in blocks.values()
                        for stmt in block.stmts)
    recovered = {}
    for rva in sorted(blocks):
        recovered[rva] = _Recovery(mode, returns_value).run(blocks[rva])
    return recovered
