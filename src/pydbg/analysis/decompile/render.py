"""S5 -- text for a recovered function.

C-style, with two conventions worth stating rather than discovering:

- every statement ends with an address comment `// @0x<rva>`, because an
  instruction that cannot be seen in the output cannot be checked against the
  decode. The same annotation appears on control-transfer lines;
- data values and offsets are decimal, code addresses are hex (`sub_<hex>`,
  `L_<hex>`, `0x...`). Mixing the two would make `[rcx + 0x8]` and `L_1008`
  look like the same kind of number.

The control flow is rendered from the CFG's successors, not from the terminal
statement alone. That is what lets an unmodelled terminator (a `loop`, say)
still show the edges the analysis knows about, and it keeps a block's fall
through implicit: a `goto` appears exactly where control does *not* fall into
the next block in address order.
"""

from ..cfg import FALL, INDIRECT, JCC, JMP, RET
from .ir import (
    Addr, Assign, BinExpr, BinOp, Branch, Call, Cmp, Const, Load, Mem, Nop,
    Opaque, Reg, Ret, Store, UnExpr, UnOp,
)

# C precedence, enough of it for the operators the lift can produce.
_PRECEDENCE = {
    "||": 1,
    "&&": 2,
    "|": 3,
    "^": 4,
    "&": 5,
    "==": 6,
    "!=": 6,
    "<": 7,
    ">": 7,
    "<=": 7,
    ">=": 7,
    "<<": 8,
    ">>": 8,
    "+": 9,
    "-": 9,
    "*": 10,
    "/": 10,
    "%": 10,
}
_UNARY = 11
_ATOM = 12

# A right-hand operand at the same precedence needs brackets for these; for the
# associative ones it does not, and adding them would only be noise.
_NON_ASSOCIATIVE = frozenset(("-", "/", "%", "<<", ">>", "==", "!=",
                              "<", ">", "<=", ">="))


def _at(rva):
    """Address annotation for a code line."""
    return f"// @0x{rva:x}"


def _at_comment(rva):
    """Address annotation for a line that already ends in a comment."""
    return f"@0x{rva:x}"


def render_expr(expr, parent_prec=0, side="left"):
    """An expression as C-ish text, bracketed only where precedence needs it."""
    if isinstance(expr, Const):
        return str(expr.value)
    if isinstance(expr, Addr):
        return f"0x{expr.value:x}" if expr.value >= 0 else f"-0x{-expr.value:x}"
    if isinstance(expr, Reg):
        return expr.name
    if isinstance(expr, Mem):
        return _render_mem(expr)
    if isinstance(expr, UnExpr):
        operand = render_expr(expr.operand, _UNARY, "right")
        text = expr.op + operand
        return f"({text})" if _UNARY < parent_prec else text
    if isinstance(expr, BinExpr):
        precedence = _PRECEDENCE.get(expr.op, _ATOM)
        left = render_expr(expr.left, precedence, "left")
        right = render_expr(expr.right, precedence, "right")
        text = f"{left} {expr.op} {right}"
        bracketed = precedence < parent_prec or (
            precedence == parent_prec and side == "right"
            and expr.op in _NON_ASSOCIATIVE)
        return f"({text})" if bracketed else text
    return "?"


def _render_mem(mem):
    parts = []
    if mem.base is not None:
        parts.append(render_expr(mem.base))
    if mem.index is not None:
        index = render_expr(mem.index)
        if mem.scale != 1:
            index = f"{index}*{mem.scale}"
        parts.append(index)

    if parts:
        text = parts[0]
        for part in parts[1:]:
            text += " + " + part
        if mem.disp > 0:
            text += f" + {mem.disp}"
        elif mem.disp < 0:
            text += f" - {-mem.disp}"
    elif mem.disp:
        text = f"0x{mem.disp:x}" if mem.disp >= 0 else f"-0x{-mem.disp:x}"
    else:
        text = "0"

    prefix = f"{mem.segment}:" if mem.segment else ""
    return f"{prefix}[{text}]"


def _statement_lines(stmt):
    """Lines for one statement, or none for the control-transfer forms.

    `Branch` and `Ret` are rendered by `_edge_lines`, which owns the CFG's
    successors; rendering them here as well would print every jump twice.
    """
    at = _at(stmt.rva)
    if isinstance(stmt, Assign):
        return [f"  {stmt.dst} = {render_expr(stmt.src)};  {at}"]
    if isinstance(stmt, BinOp):
        expr = BinExpr(stmt.op, stmt.left, stmt.right)
        return [f"  {stmt.dst} = {render_expr(expr)};  {at}"]
    if isinstance(stmt, UnOp):
        expr = UnExpr(stmt.op, stmt.operand)
        return [f"  {stmt.dst} = {render_expr(expr)};  {at}"]
    if isinstance(stmt, Load):
        return [f"  {stmt.dst} = {render_expr(stmt.addr)};  {at}"]
    if isinstance(stmt, Store):
        return [f"  {render_expr(stmt.addr)} = {render_expr(stmt.value)};  "
                f"{at}"]
    if isinstance(stmt, Cmp):
        return [f"  eflags = {stmt.op}({render_expr(stmt.left)}, "
                f"{render_expr(stmt.right)});  {at}"]
    if isinstance(stmt, Call):
        if stmt.target is not None:
            return [f"  sub_{stmt.target:x}();  {at}"]
        operand = stmt.text or "?"
        return [f"  (*{operand})();  {at}"]
    if isinstance(stmt, Nop):
        return [f"  nop;  {at}"]
    if isinstance(stmt, Opaque):
        return [f"  // unhandled: {stmt.text}  {_at_comment(stmt.rva)}"]
    return []


def _terminator(block):
    for stmt in reversed(block.stmts):
        if isinstance(stmt, (Branch, Ret)):
            return stmt
    return None


def _block_end(block):
    if block.stmts:
        return block.stmts[-1].rva
    return block.rva


def _label(rva, entry):
    """The label a goto should use: the entry block is named `sub_<hex>`."""
    return f"sub_{rva:x}" if rva == entry else f"L_{rva:x}"


def _edge_lines(block, successors, next_rva, entry):
    terminator = _terminator(block)
    lines = []
    for kind, target in successors:
        if kind == RET:
            ret = terminator if isinstance(terminator, Ret) else None
            rva = ret.rva if ret is not None else _block_end(block)
            if ret is not None and ret.value is not None:
                lines.append(f"  return {render_expr(ret.value)};  "
                             f"{_at(rva)}")
            else:
                lines.append(f"  return;  {_at(rva)}")
            continue

        if kind == FALL:
            if target is None:
                lines.append("  // falls through past the decoded "
                             f"instructions  {_at_comment(_block_end(block))}")
            elif target != next_rva:
                # The fallthrough is not the next block in address order, so
                # the layout cannot imply it and it must be written down.
                lines.append(f"  goto {_label(target, entry)};  "
                             f"{_at(_edge_rva(terminator, block))}")
            continue

        if kind == JCC:
            rva = _edge_rva(terminator, block)
            cond = (terminator.cond
                    if isinstance(terminator, Branch)
                    and terminator.kind == "jcc" else None)
            if target is None:
                lines.append(f"  // conditional edge: target unknown  "
                             f"{_at_comment(rva)}")
            elif cond is not None:
                lines.append(f"  if ({render_expr(cond)}) goto "
                             f"{_label(target, entry)};  {_at(rva)}")
            else:
                lines.append(f"  // conditional edge to {_label(target, entry)}: "
                             f"condition not modeled  {_at_comment(rva)}")
            continue

        if kind == JMP:
            rva = _edge_rva(terminator, block)
            if target is None:
                lines.append(f"  // jump target unknown  {_at_comment(rva)}")
            else:
                lines.append(f"  goto {_label(target, entry)};  {_at(rva)}")
            continue

        if kind == INDIRECT:
            rva = _edge_rva(terminator, block)
            operand = (terminator.text
                       if isinstance(terminator, Branch) else "")
            operand = operand or "?"
            lines.append(f"  goto *{operand};  // indirect jump, target "
                         f"unknown  {_at_comment(rva)}")
    return lines


def _edge_rva(terminator, block):
    return terminator.rva if terminator is not None else _block_end(block)


def render_function(entry, blocks, successors, truncated=False):
    """Render a recovered function as labelled pseudo-C.

    'blocks' maps RVA -> IRBlock; 'successors' maps RVA -> the CFG block's
    successor tuple. Both are read in sorted RVA order, which is the only order
    used anywhere here -- no set iteration reaches the text, so two calls with
    the same input produce the same bytes.

    'truncated' appends a closing note when the CFG stopped at its block limit.
    Without it a `goto` can point at a label that was never rendered, which
    looks like a bug in the text rather than the honest boundary it is.
    """
    ordered = sorted(blocks)
    next_rva = {rva: (ordered[index + 1] if index + 1 < len(ordered) else None)
                for index, rva in enumerate(ordered)}

    lines = [f"sub_{entry:x}:"]
    for rva in ordered:
        block = blocks[rva]
        if rva != entry:
            lines.append(f"L_{rva:x}:")
        for stmt in block.stmts:
            lines.extend(_statement_lines(stmt))
        for stmt in block.dead:
            for line in _statement_lines(stmt):
                body = line.strip().replace("  // @", "  @", 1)
                lines.append(f"  // dead: {body}")
        lines.extend(_edge_lines(block, successors.get(rva, ()),
                                 next_rva[rva], entry))
    if truncated:
        lines.append("// truncated: the block limit stopped the CFG; "
                     "referenced labels may be missing")
    return "\n".join(lines) + "\n"
