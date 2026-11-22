"""S5 -- text for a recovered function.

C-style, with two conventions worth stating rather than discovering:

- every statement ends with an address comment `// @0x<rva>`, because an
  instruction that cannot be seen in the output cannot be checked against the
  decode. The same annotation appears on control-transfer lines, and a
  structured construct carries the addresses of every branch it consumed;
- data values and offsets are decimal, code addresses are hex (`sub_<hex>`,
  `L_<hex>`, `0x...`). Mixing the two would make `[rcx + 0x8]` and `L_1008`
  look like the same kind of number.

The tree comes from `structure`; this module only prints it. Two rendering
forms coexist on purpose. A structured node (`if`/`while`/`do`/`switch`) prints
its branches itself. A `Flat` node is the P5 form -- statements followed by the
CFG's edges -- and is what a shape the structurer does not recognise falls back
to. Inside a `Flat` node the fall-through stays implicit when it targets the
block emitted next, which is what keeps `goto` meaning "control does not just
continue here".
"""

from ..cfg import FALL, INDIRECT, JCC, JMP, RET
from . import structure
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


def _indent(depth):
    return "  " * depth


def _at_many(rvas):
    """One comment naming several instruction addresses, in the given order."""
    seen = []
    for rva in rvas:
        if rva not in seen:
            seen.append(rva)
    if not seen:
        return ""
    return "// " + ", ".join(f"@0x{rva:x}" for rva in seen)


def _annotate(code, rvas):
    comment = _at_many(rvas)
    return f"{code}  {comment}" if comment else code


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


def _statement_lines(stmt, indent="  "):
    """Lines for one statement, or none for the control-transfer forms.

    `Branch` and `Ret` are rendered by `_edge_lines` (a `Flat` block) or by the
    enclosing construct, which owns the edges; rendering them here as well
    would print every jump twice.
    """
    at = _at(stmt.rva)
    if isinstance(stmt, Assign):
        return [f"{indent}{stmt.dst} = {render_expr(stmt.src)};  {at}"]
    if isinstance(stmt, BinOp):
        expr = BinExpr(stmt.op, stmt.left, stmt.right)
        return [f"{indent}{stmt.dst} = {render_expr(expr)};  {at}"]
    if isinstance(stmt, UnOp):
        expr = UnExpr(stmt.op, stmt.operand)
        return [f"{indent}{stmt.dst} = {render_expr(expr)};  {at}"]
    if isinstance(stmt, Load):
        return [f"{indent}{stmt.dst} = {render_expr(stmt.addr)};  {at}"]
    if isinstance(stmt, Store):
        return [f"{indent}{render_expr(stmt.addr)} = "
                f"{render_expr(stmt.value)};  {at}"]
    if isinstance(stmt, Cmp):
        return [f"{indent}eflags = {stmt.op}({render_expr(stmt.left)}, "
                f"{render_expr(stmt.right)});  {at}"]
    if isinstance(stmt, Call):
        if stmt.target is not None:
            return [f"{indent}sub_{stmt.target:x}();  {at}"]
        operand = stmt.text or "?"
        return [f"{indent}(*{operand})();  {at}"]
    if isinstance(stmt, Nop):
        return [f"{indent}nop;  {at}"]
    if isinstance(stmt, Opaque):
        return [f"{indent}// unhandled: {stmt.text}  {_at_comment(stmt.rva)}"]
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


def _edge_lines(block, successors, next_rva, entry, indent="  "):
    terminator = _terminator(block)
    lines = []
    for kind, target in successors:
        if kind == RET:
            ret = terminator if isinstance(terminator, Ret) else None
            rva = ret.rva if ret is not None else _block_end(block)
            if ret is not None and ret.value is not None:
                lines.append(f"{indent}return {render_expr(ret.value)};  "
                             f"{_at(rva)}")
            else:
                lines.append(f"{indent}return;  {_at(rva)}")
            continue

        if kind == FALL:
            if target is None:
                lines.append(f"{indent}// falls through past the decoded "
                             f"instructions  {_at_comment(_block_end(block))}")
            elif target != next_rva:
                # The fallthrough is not the block emitted next, so the layout
                # cannot imply it and it must be written down.
                lines.append(f"{indent}goto {_label(target, entry)};  "
                             f"{_at(_edge_rva(terminator, block))}")
            continue

        if kind == JCC:
            rva = _edge_rva(terminator, block)
            cond = (terminator.cond
                    if isinstance(terminator, Branch)
                    and terminator.kind == "jcc" else None)
            if target is None:
                lines.append(f"{indent}// conditional edge: target unknown  "
                             f"{_at_comment(rva)}")
            elif cond is not None:
                lines.append(f"{indent}if ({render_expr(cond)}) goto "
                             f"{_label(target, entry)};  {_at(rva)}")
            else:
                lines.append(f"{indent}// conditional edge to "
                             f"{_label(target, entry)}: condition not "
                             f"modeled  {_at_comment(rva)}")
            continue

        if kind == JMP:
            rva = _edge_rva(terminator, block)
            if target is None:
                lines.append(f"{indent}// jump target unknown  "
                             f"{_at_comment(rva)}")
            else:
                lines.append(f"{indent}goto {_label(target, entry)};  "
                             f"{_at(rva)}")
            continue

        if kind == INDIRECT:
            rva = _edge_rva(terminator, block)
            operand = terminator.text if isinstance(terminator, Branch) else ""
            operand = operand or "?"
            lines.append(f"{indent}goto *{operand};  // indirect jump, target "
                         f"unknown  {_at_comment(rva)}")
    return lines


def _edge_rva(terminator, block):
    return terminator.rva if terminator is not None else _block_end(block)


def _iter_nodes(node):
    """Every node in the tree below 'node', depth-first."""
    if isinstance(node, structure.Seq):
        for item in node.items:
            yield from _iter_nodes(item)
        return
    yield node
    if isinstance(node, structure.If):
        yield from _iter_nodes(node.header)
        yield from _iter_nodes(node.then)
        if node.orelse is not None:
            yield from _iter_nodes(node.orelse)
    elif isinstance(node, structure.While):
        yield from _iter_nodes(node.header)
        yield from _iter_nodes(node.body)
    elif isinstance(node, structure.DoWhile):
        yield from _iter_nodes(node.body)
    elif isinstance(node, structure.Switch):
        yield from _iter_nodes(node.header)
        for _, body in node.cases:
            yield from _iter_nodes(body)
        if node.default is not None:
            yield from _iter_nodes(node.default)


def _referenced_targets(nodes, successors):
    """Block RVAs a `goto` in the tree names.

    Computed before rendering so a label can be printed even when its block is
    emitted after the jump that needs it. Only the flat form produces gotos
    from edges; structured constructs consume theirs.
    """
    targets = set()
    for node in _iter_nodes(structure.Seq(tuple(nodes))):
        if isinstance(node, structure.Flat):
            for kind, target in successors.get(node.block.rva, ()):
                if target is None or kind in (RET, INDIRECT):
                    continue
                if kind == FALL and target == node.next_rva:
                    continue
                targets.add(target)
    return targets


def _render_block(node, lines, depth, entry, successors, referenced):
    indent = _indent(depth)
    block = node.block
    if block.rva != entry and block.rva in referenced:
        lines.append(f"{indent}L_{block.rva:x}:")
    folded = getattr(node, "folded", ())
    for stmt in block.stmts:
        if stmt.rva in folded:
            continue
        lines.extend(_statement_lines(stmt, indent))
    for stmt in block.dead:
        for line in _statement_lines(stmt, indent):
            body = line.strip().replace("  // @", "  @", 1)
            lines.append(f"{indent}// dead: {body}")
    if isinstance(node, structure.Flat):
        lines.extend(_edge_lines(block, successors.get(block.rva, ()),
                                 node.next_rva, entry, indent))


def _render_node(node, lines, depth, entry, successors, referenced):
    indent = _indent(depth)
    if isinstance(node, structure.Seq):
        for item in node.items:
            _render_node(item, lines, depth, entry, successors, referenced)
        return
    if isinstance(node, (structure.Statements, structure.Flat)):
        _render_block(node, lines, depth, entry, successors, referenced)
        return
    if isinstance(node, structure.Break):
        lines.append(f"{indent}break;  {_at(node.rva)}")
        return
    if isinstance(node, structure.Continue):
        lines.append(f"{indent}continue;  {_at(node.rva)}")
        return
    if isinstance(node, structure.If):
        _render_block(node.header, lines, depth, entry, successors, referenced)
        lines.append(_annotate(
            f"{indent}if ({render_expr(node.condition)}) {{", node.rvas))
        _render_node(node.then, lines, depth + 1, entry, successors,
                     referenced)
        if node.orelse is not None:
            lines.append(f"{indent}}} else {{")
            _render_node(node.orelse, lines, depth + 1, entry, successors,
                         referenced)
        lines.append(f"{indent}}}")
        return
    if isinstance(node, structure.While):
        _render_block(node.header, lines, depth, entry, successors, referenced)
        lines.append(_annotate(
            f"{indent}while ({render_expr(node.condition)}) {{", node.rvas))
        _render_node(node.body, lines, depth + 1, entry, successors,
                     referenced)
        lines.append(f"{indent}}}")
        return
    if isinstance(node, structure.DoWhile):
        lines.append(f"{indent}do {{")
        _render_node(node.body, lines, depth + 1, entry, successors,
                     referenced)
        lines.append(_annotate(
            f"{indent}}} while ({render_expr(node.condition)});", node.rvas))
        return
    if isinstance(node, structure.Switch):
        _render_block(node.header, lines, depth, entry, successors, referenced)
        lines.append(_annotate(
            f"{indent}switch ({render_expr(node.index)}) {{", node.rvas))
        for label, body in node.cases:
            lines.append(f"{indent}  case {label}:")
            _render_node(body, lines, depth + 2, entry, successors,
                         referenced)
        if node.default is not None:
            lines.append(f"{indent}  default:")
            _render_node(node.default, lines, depth + 2, entry, successors,
                         referenced)
        lines.append(f"{indent}}}")
        return
    raise TypeError(f"unknown structured node: {node!r}")


def render_function(entry, structured, successors, truncated=False):
    """Render a structured function as labelled pseudo-C.

    'structured' is a `structure.Structured`; 'successors' is the CFG's
    successor map, needed only by the flat fallback. Nothing iterates a set
    into the text: the nodes are ordered by construction and the lookup tables
    are read by key, so two calls with the same input produce the same bytes.
    """
    nodes = structured.nodes
    referenced = _referenced_targets(nodes, successors)
    lines = [f"sub_{entry:x}:"]
    for node in nodes:
        _render_node(node, lines, 1, entry, successors, referenced)
    if truncated:
        lines.append("// truncated: the block limit stopped the CFG; "
                     "referenced labels may be missing")
    return "\n".join(lines) + "\n"
