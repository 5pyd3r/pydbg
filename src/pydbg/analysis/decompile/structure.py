"""S4 -- turn a function's CFG into structured pseudo-C, or say why not.

The input is the recovered IR (S1/S2) plus the CFG's successor tuples; the
output is a small AST that `render` prints. Structuring is deliberately
conservative: every construct below is emitted only when the graph has the
canonical shape for it, and anything else falls back to the flat
label/`goto` form P5 already produced. A confident-looking `if` over a graph
that is not one would hide the very thing a decompiler is supposed to expose.

What is recognised:

- **Dominators** by the Cooper-Harvey-Kennedy iterative algorithm (immediate
  dominators over reverse postorder).
- **Natural loops** from back edges -- an edge whose target dominates its
  source. The header is the target. A loop is a ``while`` when its latch jumps
  back unconditionally and the header tests at the top; it is a ``do-while``
  when the latch itself is the conditional branch back to the header, because
  then the test is at the bottom by construction.
- **if/else** from the nearest common post-dominator of the two successors.
  The fall-through successor is the *then* arm (that is how the layout reads),
  so the printed condition is the negation of the branch's: `jne L1` with the
  fall-through body first becomes `if (==)`.
- **break/continue** for branches inside a loop that target its exit or its
  condition block instead of an enclosing merge.
- **switch** only when a `SlotTable` from the analysis names a table whose
  entries all land on blocks of this function *and* an immediate-dominator
  chain of pure `cmp`+`jcc` bounds checks leads to the indirect jump. The case
  labels are the table's slot indices, not reconstructed source values: the
  analysis knows the table's order, not the original `case` constants.
- **Irreducible regions** -- a strongly connected component with more than one
  node that no natural loop covers -- are left flat (labels and `goto`) and
  reported as ``irreducible``.

Two honesty rules are carried over from P5 and are the reason for several
details below:

- every decoded instruction must remain visible. A branch that a construct
  consumes has its address folded into that construct's line comment; a block
  whose terminator merely falls into the next emitted block has no line of its
  own to lose.
- a conditional that cannot be structured stays a flat conditional with its
  `eflags.*` condition. Condition folding is limited to comparisons whose
  operator is unambiguous (`==`, `!=` and the signed relations) and only when
  the `cmp` is the statement immediately before the branch in the same block.

Blocks themselves are normalised first. `build_function_cfg` deliberately
re-decodes across a later block's start (its blocks overlap), which is harmless
for a flat listing and fatal for nesting: a loop header would appear twice. The
normalisation splits a block at the next known start and turns its tail into a
fall-through edge.
"""

from dataclasses import dataclass

from ..cfg import CFGBlock, FALL, INDIRECT, JCC, JMP
from .expr import family
from .ir import BinExpr, Branch, Cmp, Const, Reg, UnExpr

# A virtual exit node for the post-dominator dataflow. Every block whose flow
# leaves the function (a return, an unresolved indirect edge) points here.
EXIT = -1

# ── normalisation ──────────────────────────────────────────────


def normalize_blocks(blocks):
    """Split overlapping CFG blocks at known block starts.

    `build_function_cfg` walks a run until a branch instead of stopping at a
    start it has already discovered, so the block at the entry can contain the
    instructions of a later block. That is fine for "which bytes are decoded"
    and wrong for nesting, where the later block must own its instructions
    once. The split keeps the union of instructions identical; the tail
    becomes an explicit fall-through edge to the start it was cut at.
    """
    starts = set(blocks)
    normalised = {}
    for rva in sorted(blocks):
        block = blocks[rva]
        kept = []
        split_at = None
        for addr in block.instructions:
            if addr != rva and addr in starts:
                split_at = addr
                break
            kept.append(addr)
        if split_at is None or not kept:
            normalised[rva] = block
        else:
            normalised[rva] = CFGBlock(rva=rva, instructions=tuple(kept),
                                       successors=((FALL, split_at),))
    return normalised


# ── AST ────────────────────────────────────────────────────────


class Node:
    """Marker base for the structured tree."""


@dataclass(frozen=True)
class Statements(Node):
    """A block's statements, without any control-flow line of its own.

    Used for a header whose branch a parent construct represents, and for the
    last block of a region whose jump is implied by where the region ends.
    'folded' names statement RVAs a parent condition already displays.
    """

    block: object
    folded: tuple = ()


@dataclass(frozen=True)
class Flat(Node):
    """A block rendered exactly as P5 did: statements then CFG edge lines."""

    block: object
    next_rva: int | None = None


@dataclass(frozen=True)
class Seq(Node):
    items: tuple


@dataclass(frozen=True)
class If(Node):
    header: Statements
    condition: object
    rvas: tuple
    then: Seq
    orelse: Seq | None = None


@dataclass(frozen=True)
class While(Node):
    header: Statements
    condition: object
    rvas: tuple
    body: Seq


@dataclass(frozen=True)
class DoWhile(Node):
    body: Seq
    condition: object
    rvas: tuple


@dataclass(frozen=True)
class Switch(Node):
    header: Statements
    index: object
    rvas: tuple
    cases: tuple          # ((slot_index, Seq), ...) in table order
    default: Seq | None = None


@dataclass(frozen=True)
class Break(Node):
    rva: int


@dataclass(frozen=True)
class Continue(Node):
    rva: int


@dataclass(frozen=True)
class Structured:
    """What the structuring pass produces: a tree and what it could not do."""

    nodes: tuple
    warnings: tuple


# ── condition knowledge ────────────────────────────────────────

_ZF = Reg("eflags.zf", 1)
_SF = Reg("eflags.sf", 1)
_OF = Reg("eflags.of", 1)


def _comparison_op(condition):
    """The C operator a `jcc` condition means, or None when it is not folded.

    Only the sign/zero relations with an exact C spelling are listed. Unsigned
    relations (`jb`/`ja`/...) are deliberately absent: `eax < 5` would silently
    claim a signedness the instruction did not state, and the `eflags.*` form
    P5 prints does not have that problem.
    """
    if condition == _ZF:
        return "=="
    if condition == UnExpr("!", _ZF):
        return "!="
    if condition == BinExpr("!=", _SF, _OF):
        return "<"
    if condition == BinExpr("==", _SF, _OF):
        return ">="
    if condition == BinExpr("||", _ZF, BinExpr("!=", _SF, _OF)):
        return "<="
    if condition == BinExpr("&&", UnExpr("!", _ZF), BinExpr("==", _SF, _OF)):
        return ">"
    return None


_INVERT = {"==": "!=", "!=": "==", "<": ">=", ">=": "<", ">": "<=", "<=": ">"}


def negate(condition):
    """The logical negation of a condition, as an expression."""
    if isinstance(condition, BinExpr) and condition.op in _INVERT:
        return BinExpr(_INVERT[condition.op], condition.left, condition.right)
    if isinstance(condition, UnExpr) and condition.op == "!":
        return condition.operand
    return UnExpr("!", condition)


def fold_compare(cmp_stmt, condition):
    """Fold a `cmp`/`test` statement into an `if`-style condition, or None.

    'condition' is the branch's flag expression. The fold is only attempted
    when the branch means an operator with an exact C spelling, so a folded
    condition never says more than the flags said.
    """
    if not isinstance(cmp_stmt, Cmp) or condition is None:
        return None
    op = _comparison_op(condition)
    if op is None:
        return None
    if cmp_stmt.op == "cmp":
        return BinExpr(op, cmp_stmt.left, cmp_stmt.right)
    if cmp_stmt.op == "test":
        if op not in ("==", "!="):
            return None
        if cmp_stmt.left == cmp_stmt.right:
            return BinExpr(op, cmp_stmt.left, Const(0))
        return BinExpr(op, BinExpr("&", cmp_stmt.left, cmp_stmt.right),
                       Const(0))
    return None


# ── graph facts ────────────────────────────────────────────────


@dataclass
class _Loop:
    header: int
    body: frozenset
    latches: frozenset
    done: bool = False


@dataclass(frozen=True)
class _LoopContext:
    """Where a branch inside a loop is really going."""

    header: int
    exit: int | None
    latches: frozenset
    body: frozenset
    continue_target: int
    break_target: int | None


@dataclass(frozen=True)
class _SwitchPlan:
    start: int
    chain: tuple          # bounds-check blocks, top of the chain first
    dispatch: int
    index: object
    rvas: tuple
    cases: tuple          # ((slot_index, target_rva), ...)
    default: int | None
    merge: int | None


def _block_end(block):
    """The RVA of a block's last statement (its first address when empty)."""
    return block.stmts[-1].rva if block.stmts else block.rva


def _block_addresses(block):
    """Instruction RVAs of a block, for a CFGBlock or a lowered IRBlock."""
    if hasattr(block, "instructions"):
        return block.instructions
    addresses = {stmt.rva for stmt in block.stmts}
    addresses.update(stmt.rva for stmt in block.dead)
    return tuple(sorted(addresses))


class _Builder:
    def __init__(self, entry, blocks, successors, slot_tables=(), decoder=None,
                 image=None):
        self.entry = entry
        self.blocks = blocks
        self.successors = successors
        self.slot_tables = tuple(slot_tables or ())
        self.decoder = decoder
        self.image = image
        self.order = sorted(blocks)
        self.warnings = set()
        self.preds = {rva: [] for rva in self.order}
        for rva in self.order:
            for kind, target in successors.get(rva, ()):
                if target is not None and target in self.preds:
                    self.preds[target].append(rva)
        for rva in self.order:
            self.preds[rva] = sorted(set(self.preds[rva]))
        self.owner_of_instruction = {
            addr: rva for rva in self.order
            for addr in _block_addresses(self.blocks[rva])
        }
        self._compute_dominators()
        self._compute_postdominators()
        self.loops = self._natural_loops()
        self.loop_at = {loop.header: loop for loop in self.loops}
        self.force_flat = set()
        self._find_irreducible()
        self.switch_plans = {}
        self.switch_consumed = set()
        self._find_switches()
        self.done = set()

    # ── successor queries ──────────────────────────────────────

    def _succ_targets(self, rva):
        return tuple(sorted({target
                             for kind, target in self.successors.get(rva, ())
                             if target is not None and target in self.blocks}))

    def _post_succs(self, rva):
        targets = sorted({target
                          for kind, target in self.successors.get(rva, ())
                          if target is not None and target in self.blocks})
        return tuple(targets) or (EXIT,)

    def _conditional(self, rva):
        """(taken_target, fall_through) for a conditional branch block."""
        taken = None
        fall = None
        for kind, target in self.successors.get(rva, ()):
            if kind == JCC:
                taken = target
            elif kind == FALL:
                fall = target
        if taken is None:
            return None
        return (taken, fall)

    def _jump_target(self, rva):
        for kind, target in self.successors.get(rva, ()):
            if kind == JMP:
                return target
        return None

    def _fall(self, rva):
        for kind, target in self.successors.get(rva, ()):
            if kind == FALL:
                return target
        return None

    def _branch_rva(self, block):
        for stmt in reversed(block.stmts):
            if isinstance(stmt, Branch):
                return stmt.rva
        return block.stmts[-1].rva if block.stmts else block.rva

    def _has_indirect(self, rva):
        return any(kind == INDIRECT for kind, _ in self.successors.get(rva, ()))

    @staticmethod
    def _outside_loop(ctx, target):
        """Whether 'target' is an edge cross out of the current loop.

        Exits and the two sanctioned back edges (`break`/`continue`) are not
        cross edges. Anything else leaves the region sideways, which a
        structured `break` cannot express (a jump out of two loops, say), so it
        stays a `goto` and the text says why.
        """
        if ctx is None or target is None:
            return False
        if target in ctx.body:
            return False
        return target not in (ctx.break_target, ctx.continue_target, ctx.exit)

    # ── dominators (Cooper-Harvey-Kennedy) ─────────────────────

    def _compute_dominators(self):
        order = []
        seen = set()
        stack = [(self.entry, iter(self._succ_targets(self.entry)))]
        seen.add(self.entry)
        while stack:
            node, children = stack[-1]
            for child in children:
                if child not in seen:
                    seen.add(child)
                    stack.append((child, iter(self._succ_targets(child))))
                    break
            else:
                order.append(node)
                stack.pop()
        order.reverse()                       # reverse postorder
        self.rpo = order
        # Postorder numbers: the entry is highest, so the intersect walk climbs
        # by decreasing number.
        dfn = {rva: len(order) - index for index, rva in enumerate(order)}

        idom = {self.entry: self.entry}
        for rva in order[1:]:
            idom[rva] = None
        changed = True
        while changed:
            changed = False
            for rva in order[1:]:
                preds = [pred for pred in self.preds[rva] if idom.get(pred)]
                if not preds:
                    continue
                candidate = preds[0]
                for pred in preds[1:]:
                    candidate = self._intersect(candidate, pred, idom, dfn)
                if idom.get(rva) != candidate:
                    idom[rva] = candidate
                    changed = True
        for rva in self.order:
            idom.setdefault(rva, rva)
            if idom[rva] is None:
                idom[rva] = rva          # unreachable: its own dominator
        self.idom = idom

    @staticmethod
    def _intersect(left, right, idom, dfn):
        while left != right:
            while dfn[left] < dfn[right]:
                left = idom[left]
            while dfn[right] < dfn[left]:
                right = idom[right]
        return left

    def _dominates(self, dominator, node):
        """Whether 'dominator' dominates 'node' (a node dominates itself)."""
        current = node
        while True:
            if current == dominator:
                return True
            parent = self.idom.get(current)
            if parent is None or parent == current:
                return False
            current = parent

    # ── post-dominators ────────────────────────────────────────

    def _compute_postdominators(self):
        universe = set(self.order) | {EXIT}
        post = {rva: set(universe) for rva in self.order}
        post[EXIT] = {EXIT}
        changed = True
        while changed:
            changed = False
            for rva in reversed(self.order):
                common = set(universe)
                for succ in self._post_succs(rva):
                    common &= post.get(succ, {succ})
                new = {rva} | common
                if new != post[rva]:
                    post[rva] = new
                    changed = True
        self.postdom = post

        self.ipdom = {}
        for rva in self.order:
            candidates = post[rva] - {rva}
            if EXIT in candidates:
                self.ipdom[rva] = EXIT
            elif candidates:
                # The immediate post-dominator is the proper post-dominator
                # with the largest set: ancestors get smaller as you climb.
                self.ipdom[rva] = max(candidates,
                                      key=lambda node: (len(post[node]), -node))
            else:
                self.ipdom[rva] = None
        self.postdom_depth = {EXIT: 0}
        for rva in self.order:
            depth = 0
            current = rva
            seen = set()
            while current != EXIT and current is not None and current not in seen:
                seen.add(current)
                current = self.ipdom.get(current)
                depth += 1
            self.postdom_depth[rva] = depth

    def _common_postdom(self, nodes):
        """Nearest common post-dominator inside the function, or None."""
        nodes = [node for node in nodes if node is not None]
        if not nodes:
            return None
        common = set(self.postdom.get(nodes[0], ()))
        for node in nodes[1:]:
            common &= self.postdom.get(node, set())
        common.discard(EXIT)
        if not common:
            return None
        return max(common, key=lambda node: (self.postdom_depth.get(node, -1),
                                             -node))

    # ── natural loops ──────────────────────────────────────────

    def _natural_loops(self):
        loops = {}
        for rva in self.order:
            for kind, target in self.successors.get(rva, ()):
                if target is None or target not in self.blocks:
                    continue
                if not self._dominates(target, rva):
                    continue
                body = self._loop_body(target, rva)
                if target in loops:
                    loops[target].body |= body
                    loops[target].latches |= {rva}
                else:
                    loops[target] = _Loop(header=target, body=frozenset(body),
                                          latches=frozenset((rva,)))
        return [loops[header] for header in sorted(loops)]

    def _loop_body(self, header, latch):
        """Header plus every block dominated by it that can reach the latch."""
        body = {header}
        stack = [latch]
        while stack:
            node = stack.pop()
            if node in body:
                continue
            body.add(node)
            for pred in self.preds.get(node, ()):
                if pred in body:
                    continue
                if pred == header or self._dominates(header, pred):
                    stack.append(pred)
        return body

    # ── irreducibility ─────────────────────────────────────────

    def _find_irreducible(self):
        covered = set()
        for loop in self.loops:
            covered |= loop.body
        for component in self._strongly_connected():
            if len(component) <= 1:
                continue
            if component <= covered:
                continue
            self.force_flat |= component
            self.warnings.add("irreducible")

    def _strongly_connected(self):
        """Kosaraju's SCCs, iteratively and in a deterministic order."""
        seen = set()
        finish = []
        for start in self.order:
            if start in seen:
                continue
            seen.add(start)
            stack = [(start, iter(self._succ_targets(start)))]
            while stack:
                node, children = stack[-1]
                for child in children:
                    if child not in seen:
                        seen.add(child)
                        stack.append((child, iter(self._succ_targets(child))))
                        break
                else:
                    finish.append(node)
                    stack.pop()

        reverse = {rva: [] for rva in self.order}
        for rva in self.order:
            for target in self._succ_targets(rva):
                reverse[target].append(rva)

        components = []
        assigned = set()
        for node in reversed(finish):
            if node in assigned:
                continue
            assigned.add(node)
            component = []
            stack = [node]
            while stack:
                current = stack.pop()
                component.append(current)
                for pred in reverse[current]:
                    if pred not in assigned:
                        assigned.add(pred)
                        stack.append(pred)
            components.append(set(component))
        return components

    # ── switch recognition ─────────────────────────────────────

    def _find_switches(self):
        for table in self.slot_tables:
            referrer = getattr(table, "referrer", None)
            if referrer is None:
                continue
            dispatch = self.owner_of_instruction.get(referrer)
            if dispatch is None or not self._has_indirect(dispatch):
                continue
            plan = self._make_switch_plan(table, dispatch)
            if plan is None:
                self.warnings.add("unmatched jump table")
                continue
            if plan.start in self.switch_plans:
                continue
            self.switch_plans[plan.start] = plan
            self.switch_consumed.update(plan.chain)
            self.switch_consumed.add(plan.dispatch)
        # A table-shaped indirect jump with no table behind it is still worth
        # a warning: the flat `goto *...` is honest but the reader should know
        # a switch was possible.
        for rva in self.order:
            if rva in self.switch_consumed or not self._has_indirect(rva):
                continue
            if self._table_shaped(rva):
                self.warnings.add("unmatched jump table")

    def _table_shaped(self, rva):
        if self.decoder is None:
            return False
        block = self.blocks[rva]
        insn = self.decoder.decode_one(self._branch_rva(block))
        if insn is None:
            return False
        return any(operand.is_table_mem for operand in insn.operands)

    def _make_switch_plan(self, table, dispatch):
        if self.decoder is None or self.image is None:
            return None
        if table.count < 2:
            return None

        cases = []
        for index in range(table.count):
            value = self.image.read_pointer(table.base + index * table.stride)
            target = None if value is None else self.image.va_to_rva(value)
            if target is None or target not in self.blocks:
                return None
            cases.append((index, target))
        if len({target for _, target in cases}) != len(cases):
            # Two slots sharing one body: keep the flat form rather than
            # invent a case label for it.
            return None
        # The dispatch instruction itself names the index register.
        insn = self.decoder.decode_one(table.referrer)
        if insn is None:
            return None
        index_name = None
        for operand in insn.operands:
            if operand.is_table_mem and operand.mem_index:
                index_name = self.decoder.reg_name(operand.mem_index)
                break
        if index_name is None:
            return None
        # The dispatch block must contain nothing but its branch: skipping a
        # statement here would silently drop an instruction's effect.
        dispatch_block = self.blocks[dispatch]
        if dispatch_block.dead or any(not isinstance(stmt, Branch)
                                      for stmt in dispatch_block.stmts):
            return None

        case_set = {target for _, target in cases}
        chain = []
        current = dispatch
        while True:
            parent = self.idom.get(current, current)
            if parent == current or parent in chain:
                break
            if not self._pure_bounds_check(parent, current):
                break
            chain.append(parent)
            current = parent
        if not chain:
            return None
        chain.reverse()

        index_expr = None
        default = None
        rvas = []
        for position, rva in enumerate(chain):
            cmp_stmt = self._pure_compare_cmp(rva)
            if cmp_stmt is None:
                return None
            if index_expr is None:
                index_expr = self._index_operand(cmp_stmt)
            expected_fall = (chain[position + 1] if position + 1 < len(chain)
                             else dispatch)
            conditional = self._conditional(rva)
            if conditional is None or conditional[1] != expected_fall:
                return None
            taken = conditional[0]
            if taken in case_set:
                pass
            elif taken in self.blocks and default is None and taken != dispatch:
                default = taken
            else:
                return None
            branch = self._branch_rva(self.blocks[rva])
            rvas.extend((cmp_stmt.rva, branch))
        if index_expr is None or not isinstance(index_expr, Reg):
            return None
        if family(index_expr.name) != family(index_name):
            return None

        merge = self._common_postdom(
            tuple(target for _, target in cases)
            + ((default,) if default is not None else ()))
        if merge is not None and (merge in case_set or merge == dispatch):
            return None
        rvas.append(self._branch_rva(self.blocks[dispatch]))
        return _SwitchPlan(start=chain[0], chain=tuple(chain),
                           dispatch=dispatch, index=index_expr,
                           rvas=tuple(rvas), cases=tuple(cases),
                           default=default, merge=merge)

    def _pure_compare_cmp(self, rva):
        """The Cmp of a `cmp/branch` block with nothing else, or None.

        `dead` must be empty too: a dead register write is still an instruction
        and a switch that skipped it would leave its address out of the text.
        """
        block = self.blocks[rva]
        stmts = block.stmts
        if block.dead:
            return None
        if len(stmts) < 2 or not isinstance(stmts[-1], Branch):
            return None
        if stmts[-1].kind != "jcc":
            return None
        if len(stmts) != 2 or not isinstance(stmts[0], Cmp):
            return None
        return stmts[0]

    def _pure_bounds_check(self, rva, falls_to):
        cmp_stmt = self._pure_compare_cmp(rva)
        if cmp_stmt is None:
            return False
        conditional = self._conditional(rva)
        return conditional is not None and conditional[1] == falls_to

    @staticmethod
    def _index_operand(cmp_stmt):
        if isinstance(cmp_stmt.left, Reg):
            return cmp_stmt.left
        if isinstance(cmp_stmt.right, Reg):
            return cmp_stmt.right
        return None

    # ── conditions and statements ──────────────────────────────

    def _condition(self, block):
        """(header_statements, condition_expr, address_rvas) for a branch."""
        stmts = block.stmts
        branch = stmts[-1] if stmts and isinstance(stmts[-1], Branch) else None
        condition = branch.cond if branch is not None else None
        cmp_stmt = None
        if (branch is not None and len(stmts) >= 2
                and isinstance(stmts[-2], Cmp)):
            cmp_stmt = stmts[-2]
        folded = fold_compare(cmp_stmt, condition)
        if folded is not None:
            return (Statements(block, folded=(cmp_stmt.rva,)), folded,
                    (cmp_stmt.rva, branch.rva))
        return (Statements(block), condition,
                (branch.rva,) if branch is not None else ())

    # ── the region parser ──────────────────────────────────────

    def build(self):
        nodes, _, _ = self._region(self.entry, frozenset(), None)
        for rva in self.order:
            if rva in self.done or rva in self.switch_consumed:
                continue
            extra, _, _ = self._region(rva, frozenset(), None)
            nodes = tuple(nodes) + tuple(extra)
        return Structured(nodes=nodes,
                          warnings=tuple(sorted(self.warnings)))

    def _region(self, start, stop, ctx):
        """Structure from 'start' until a block in 'stop' or a dead end.

        Returns (items, next_block, elided_branch_rvas). The elided branches
        are terminators whose effect the enclosing construct already states
        (`jmp merge` at the end of an if arm); the caller folds their addresses
        into its own line comment so no instruction leaves the text.
        """
        items = []
        elided = []
        cur = start
        while cur is not None:
            if cur not in self.blocks:
                # A known branch target the CFG never built (the block limit
                # stopped it). The flat edge already named it; there is no
                # block here to structure.
                break
            if cur in stop or cur in self.done:
                break
            plan = self.switch_plans.get(cur)
            if plan is not None:
                node, after, consumed = self._build_switch(plan, stop, ctx)
                items.append(node)
                elided.extend(consumed)
                cur = after
                continue
            if cur in self.force_flat:
                items.append(Flat(self.blocks[cur], None))
                self.done.add(cur)
                break
            loop = self.loop_at.get(cur)
            if loop is not None and not loop.done:
                built = self._build_loop(loop, stop, ctx)
                if built is None:
                    nxt = self._fall(cur)
                    items.append(Flat(self.blocks[cur],
                                      nxt if nxt in self.blocks else None))
                    self.done.add(cur)
                    cur = nxt
                    continue
                node, after, consumed = built
                items.append(node)
                elided.extend(consumed)
                cur = after
                continue

            block = self.blocks[cur]
            conditional = self._conditional(cur)
            jump = self._jump_target(cur)
            if conditional is not None:
                target, fall = conditional
                if self._condition(block)[1] is None:
                    # The terminator branches conditionally, but the lift did
                    # not model its condition (`loop`, say). There is no truth
                    # value to put in an `if`, and inventing one would print
                    # `if (!?)` while the result still claimed completeness.
                    self.warnings.add("condition not modeled")
                    items.append(Flat(block,
                                      fall if fall in self.blocks else None))
                    self.done.add(cur)
                    cur = fall
                    continue
                rva = self._branch_rva(block)
                if (ctx is not None and target == ctx.break_target
                        and fall != ctx.break_target):
                    header, expression, rvas = self._condition(block)
                    items.append(If(header, expression, rvas,
                                    Seq((Break(rva),))))
                    self.done.add(cur)
                    cur = fall
                    continue
                if (ctx is not None and fall == ctx.break_target
                        and target != ctx.break_target):
                    header, expression, rvas = self._condition(block)
                    items.append(If(header, negate(expression), rvas,
                                    Seq((Break(rva),))))
                    self.done.add(cur)
                    cur = target
                    continue
                if (ctx is not None and target == ctx.continue_target
                        and fall != ctx.continue_target):
                    header, expression, rvas = self._condition(block)
                    items.append(If(header, expression, rvas,
                                    Seq((Continue(rva),))))
                    self.done.add(cur)
                    cur = fall
                    continue
                if (ctx is not None and fall == ctx.continue_target
                        and target != ctx.continue_target):
                    header, expression, rvas = self._condition(block)
                    items.append(If(header, negate(expression), rvas,
                                    Seq((Continue(rva),))))
                    self.done.add(cur)
                    cur = target
                    continue
                if ctx is not None and (self._outside_loop(ctx, target)
                                        or self._outside_loop(ctx, fall)):
                    self.warnings.add("irreducible")
                    items.append(Flat(block,
                                      fall if fall in self.blocks else None))
                    self.done.add(cur)
                    cur = fall
                    continue
                built = self._build_if(block, target, fall, stop, ctx)
                if built is not None:
                    node, after, consumed = built
                    items.append(node)
                    elided.extend(consumed)
                    self.done.add(cur)
                    cur = after
                    continue
                items.append(Flat(block, fall if fall in self.blocks else None))
                self.done.add(cur)
                cur = fall
                continue

            if jump is not None:
                rva = self._branch_rva(block)
                if (ctx is not None and jump == ctx.continue_target
                        and cur not in ctx.latches):
                    items.append(Statements(block))
                    elided.append(rva)
                    self.done.add(cur)
                    break
                if ctx is not None and jump == ctx.break_target:
                    items.append(Statements(block))
                    elided.append(rva)
                    self.done.add(cur)
                    break
                if ctx is not None and self._outside_loop(ctx, jump):
                    self.warnings.add("irreducible")
                    items.append(Flat(block, None))
                    self.done.add(cur)
                    break
                if jump in self.done:
                    items.append(Flat(block, None))
                    self.done.add(cur)
                    break
                if jump in stop:
                    items.append(Statements(block))
                    elided.append(rva)
                    self.done.add(cur)
                    cur = jump
                    break
                items.append(Flat(block, jump if jump in self.blocks else None))
                self.done.add(cur)
                cur = jump
                continue

            fall = self._fall(cur)
            if fall is not None:
                if fall not in self.blocks:
                    items.append(Flat(block, None))
                    self.done.add(cur)
                    cur = fall
                    break
                if fall in self.done:
                    items.append(Flat(block, None))
                    self.done.add(cur)
                    cur = fall
                    break
                items.append(Statements(block))
                self.done.add(cur)
                cur = fall
                continue

            # Returns, unresolved indirect jumps and undecoded fall-throughs.
            items.append(Flat(block, None))
            self.done.add(cur)
            break
        return tuple(items), cur, tuple(elided)

    def _build_if(self, block, target, fall, stop, ctx):
        if target is None or fall is None or target == fall:
            return None
        if target not in self.blocks or fall not in self.blocks:
            return None
        if target in self.force_flat or fall in self.force_flat:
            return None
        if target in stop and fall in stop:
            return None
        header, expression, rvas = self._condition(block)
        if expression is None:
            # A conditional with no modelled condition has no `if` to build.
            # Returning None leaves the flat form, which names the edge and
            # says the condition is not modeled; the warning carries the same
            # statement out of the text.
            self.warnings.add("condition not modeled")
            return None

        if target in stop:
            body, after, elided = self._region(fall, stop, ctx)
            return (If(header, negate(expression), rvas + elided,
                       Seq(body)), target, ())
        if fall in stop:
            body, after, elided = self._region(target, stop, ctx)
            return (If(header, expression, rvas + elided,
                       Seq(body)), fall, ())

        merge = self._common_postdom((target, fall))
        if merge is None or merge in self.force_flat or merge == fall:
            return None
        if merge == target:
            body, after, elided = self._region(fall, stop | {merge}, ctx)
            return (If(header, negate(expression), rvas + elided,
                       Seq(body)), merge, ())

        then_items, _, then_elided = self._region(fall, stop | {merge}, ctx)
        else_items, _, else_elided = self._region(target, stop | {merge}, ctx)
        node = If(header, negate(expression), rvas + then_elided + else_elided,
                  Seq(then_items), Seq(else_items))
        return node, merge, ()

    def _build_loop(self, loop, stop, ctx):
        header = loop.header
        conditional = self._conditional(header)
        if conditional is None:
            return None

        do_while_latch = None
        for latch in sorted(loop.latches):
            latch_conditional = self._conditional(latch)
            if (latch_conditional is not None
                    and latch_conditional[0] == header):
                # A conditional back edge whose fall-through stays inside the
                # body is a `continue`, not a bottom test: the loop can still
                # be a top-tested `while`.
                if latch_conditional[1] not in loop.body:
                    if do_while_latch is not None:
                        return None            # more than one bottom test
                    do_while_latch = latch
            elif self._jump_target(latch) != header:
                return None
        if do_while_latch is not None:
            if len(loop.latches) != 1:
                return None
            return self._build_do_while(loop, do_while_latch, stop, ctx)

        target, fall = conditional
        if target in loop.body and fall not in loop.body:
            # The branch repeats; the fall-through leaves.
            exit_rva = fall
            body_start = target
            jcc_exits = False
        elif fall in loop.body and target not in loop.body:
            # The branch leaves; falling through repeats.
            exit_rva = target
            body_start = fall
            jcc_exits = True
        else:
            return None                    # no single visible exit
        if exit_rva is None:
            return None

        header_statements, expression, rvas = self._condition(
            self.blocks[header])
        if not header_statements.folded:
            # A header that needs statements before its test is not a `while`:
            # printing them outside the loop would move work out of it.
            return None
        if jcc_exits:
            expression = negate(expression)
        loop_ctx = _LoopContext(header=header, exit=exit_rva,
                                latches=loop.latches, body=loop.body,
                                continue_target=header,
                                break_target=exit_rva)
        body, _, elided = self._region(body_start, stop | {header}, loop_ctx)
        loop.done = True
        self.done.add(header)
        return (While(header_statements, expression, rvas + elided,
                      Seq(body)), exit_rva, ())

    def _build_do_while(self, loop, latch, stop, ctx):
        conditional = self._conditional(latch)
        if conditional is None or conditional[0] != loop.header:
            return None
        exit_rva = conditional[1]
        if exit_rva is None or exit_rva in loop.body:
            return None
        latch_block = self.blocks[latch]
        latch_statements, expression, rvas = self._condition(latch_block)
        if not latch_statements.folded:
            return None
        loop_ctx = _LoopContext(header=loop.header, exit=exit_rva,
                                latches=loop.latches, body=loop.body,
                                continue_target=latch, break_target=exit_rva)
        body, _, elided = self._region(loop.header, stop | {latch}, loop_ctx)
        loop.done = True
        self.done.add(loop.header)
        self.done.add(latch)
        items = tuple(body) + (latch_statements,)
        return (DoWhile(Seq(items), expression, rvas + elided), exit_rva, ())

    def _case_exit(self, body, merge):
        """A `break;` when a case body leaves through a jump to the merge.

        In C a `case` label does not stop execution: a body that ends without
        `break` falls into the next label, which is *not* the CFG's jump to the
        merge. The jump's address moves from the switch line to the `break`
        line, so the instruction is still visible exactly once.
        """
        if merge is None or not body:
            return None
        last = body[-1]
        if not isinstance(last, Statements):
            return None
        for kind, target in self.successors.get(last.block.rva, ()):
            if target != merge:
                continue
            if kind == JMP:
                return Break(self._branch_rva(last.block))
            if kind == FALL:
                return Break(_block_end(last.block))
        return None

    @staticmethod
    def _last_rva(body):
        """The address of the last instruction a case body rendered."""
        if not body:
            return None
        last = body[-1]
        if isinstance(last, (Statements, Flat)):
            return _block_end(last.block)
        if isinstance(last, (Break, Continue)):
            return last.rva
        rvas = getattr(last, "rvas", ())
        return rvas[-1] if rvas else None

    def _build_switch(self, plan, stop, ctx):
        for rva in plan.chain:
            self.done.add(rva)
        base_stop = set(stop)
        if plan.merge is not None:
            base_stop.add(plan.merge)
        case_targets = {target for _, target in plan.cases}

        cases = []
        elided = []
        for label, target in plan.cases:
            case_stop = frozenset(base_stop | (case_targets - {target}))
            body, after, consumed = self._region(target, case_stop, ctx)
            items = list(body)
            leave = self._case_exit(tuple(items), plan.merge)
            if leave is not None:
                items.append(leave)
                consumed = tuple(rva for rva in consumed
                                 if rva != leave.rva)
            elif items and plan.merge is not None and after == plan.merge:
                # The body was structured but still leaves through the merge:
                # C would fall into the next `case` label without a break.
                rva = self._last_rva(items)
                if rva is not None:
                    items.append(Break(rva))
            elided.extend(consumed)
            cases.append((label, Seq(tuple(items))))
        default = None
        if plan.default is not None:
            default_stop = frozenset(base_stop | case_targets)
            body, _, consumed = self._region(plan.default, default_stop, ctx)
            elided.extend(consumed)
            default = Seq(body)

        self.done.add(plan.dispatch)
        node = Switch(Statements(self.blocks[plan.dispatch]), plan.index,
                      plan.rvas + tuple(elided), tuple(cases), default)
        return node, plan.merge, ()


def build(entry, blocks, successors, slot_tables=(), decoder=None, image=None):
    """Structure one function. 'blocks' maps RVA -> IRBlock (recovered).

    The blocks are expected to be already normalised (see `normalize_blocks`);
    a mapping of raw `CFGBlock`s is normalised here as a convenience. The
    caller that lowered the blocks owns the successor map, so the split edges
    must come from the same normalisation it did.
    """
    sample = next(iter(blocks.values()), None)
    if sample is not None and hasattr(sample, "instructions"):
        blocks = normalize_blocks(blocks)
    builder = _Builder(entry, blocks, successors,
                       slot_tables=slot_tables, decoder=decoder, image=image)
    return builder.build()


def jump_table_targets(blocks, successors, slot_tables, decoder=None,
                       image=None):
    """RVAs a jump table in this function names, for case blocks not yet in
    the CFG.

    `build_function_cfg` cannot follow an indirect edge, so a switch whose
    cases are reached only through the table leaves them out of the CFG. The
    table is the analysis's own statement of where they are, which makes them
    part of this function rather than a guess. The caller builds blocks for
    these addresses and structures the switch over them; the flat form is
    still used when any target is missing from the rebuilt blocks.
    """
    if decoder is None or image is None:
        return ()
    owners = {}
    for rva in sorted(blocks):
        for addr in _block_addresses(blocks[rva]):
            owners[addr] = rva
    targets = set()
    for table in slot_tables or ():
        referrer = getattr(table, "referrer", None)
        if referrer is None:
            continue
        dispatch = owners.get(referrer)
        if dispatch is None:
            continue
        if not any(kind == INDIRECT
                   for kind, _ in successors.get(dispatch, ())):
            continue
        for index in range(table.count):
            value = image.read_pointer(table.base + index * table.stride)
            target = None if value is None else image.va_to_rva(value)
            if target is not None and image.is_exec(target):
                targets.add(target)
    return tuple(sorted(targets))
