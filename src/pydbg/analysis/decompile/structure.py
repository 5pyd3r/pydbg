"""S4 -- turn a function's CFG into structured pseudo-C, or say why not.

The input is the recovered IR (S1/S2) plus the CFG's successor tuples; the
output is a small AST (`ast`) that `render` prints. Structuring is deliberately
conservative: every construct below is emitted only when the graph has the
canonical shape for it, and anything else falls back to the flat label/`goto`
form P5 already produced. A confident-looking `if` over a graph that is not one
would hide the very thing a decompiler is supposed to expose.

This module owns the decision of how blocks nest. The facts it reads come from
`graph` (successors, dominators, post-dominators, natural loops, irreducible
regions) and `switch` (which indirect jumps are switches, and their cases);
normalisation comes from `blocks`, and a condition's spelling from
`conditions`.

What is recognised here:

- **if/else** from the nearest common post-dominator of the two successors.
  The fall-through successor is the *then* arm (that is how the layout reads),
  so the printed condition is the negation of the branch's: `jne L1` with the
  fall-through body first becomes `if (==)`.
- **break/continue** for branches inside a loop that target its exit or its
  condition block instead of an enclosing merge.
- **while** when a natural loop's latch jumps back unconditionally and the
  header tests at the top; **do-while** when the latch itself is the
  conditional branch back to the header, because then the test is at the bottom
  by construction. The loop set itself is `graph`'s answer.
- **switch** when `switch` has a plan for the block: its case bodies are parsed
  as sub-regions, and a `break` is added where C would otherwise fall into the
  next label.

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
"""

from dataclasses import dataclass

from ..cfg import FALL, JMP
from .ast import (
    Break, Continue, DoWhile, Flat, If, Seq, Statements, Structured, Switch,
    While,
)
from .blocks import _block_addresses, _block_end
from .conditions import fold_compare, negate
from .graph import GraphFacts
from .ir import Branch, Cmp
from .switch import SwitchRecognition

# Recursion budget for the region parser. Each nesting level costs a `_region`
# call made from `_build_if`/`_build_loop`/`_build_switch`, i.e. a few Python
# frames per level; the interpreter's default limit is about 1000, and a few
# hundred nested constructs therefore raise RecursionError out of the public
# `decompile_function`, whose failures are supposed to be return values. 64
# keeps the worst case near 200 frames while leaving real functions structured;
# past it the flat label/goto form and a warning are the honest answer.
_MAX_REGION_DEPTH = 64


@dataclass(frozen=True)
class _LoopContext:
    """Where a branch inside a loop is really going."""

    header: int
    exit: int | None
    latches: frozenset
    body: frozenset
    continue_target: int
    break_target: int | None


class _Builder(GraphFacts, SwitchRecognition):
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
        self._compute_graph_facts()
        self.switch_plans = {}
        self.switch_consumed = set()
        self._find_switches()
        self.done = set()
        self.depth = 0                 # live `_region` nesting level

    # ── loop context ───────────────────────────────────────────

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
        comparison = branch.comparison if branch is not None else None
        folded = fold_compare(cmp_stmt, comparison)
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
        """Bounded entry point for the recursive region parser.

        The budget is per call stack, not per block: `_region_body` recurses
        through `_build_if` and the loop forms once per nesting level, so an
        unbounded walk would escape `decompile_function` as RecursionError
        instead of the warning its contract promises.
        """
        if self.depth >= _MAX_REGION_DEPTH:
            self.warnings.add("region depth limit")
            return self._flat_region(start, stop)
        self.depth += 1
        try:
            return self._region_body(start, stop, ctx)
        finally:
            self.depth -= 1

    def _flat_region(self, start, stop):
        """Flat label/goto form for a region past the depth budget.

        Iterative by construction: this is the path that must not consume any
        more stack, so it cannot call `_region` again. It follows the chain the
        structured walk would have followed and lets the renderer print the
        edges, which is the P5 form `_region_body` already falls back to for
        shapes it does not recognise.
        """
        items = []
        cur = start
        while cur is not None and cur in self.blocks:
            if cur in stop or cur in self.done:
                break
            block = self.blocks[cur]
            conditional = self._conditional(cur)
            jump = self._jump_target(cur)
            if conditional is not None:
                after = conditional[1]
                items.append(Flat(block,
                                  after if after in self.blocks else None))
            elif jump is not None:
                after = jump
                items.append(Flat(block, jump if jump in self.blocks else None))
            else:
                after = self._fall(cur)
                items.append(Flat(block, None))
            self.done.add(cur)
            cur = after
        return tuple(items), cur, ()

    def _region_body(self, start, stop, ctx):
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

    The blocks must already be normalised (see `normalize_blocks`). The caller
    that lowered them owns the successor map, and the split edges in that map
    must come from the same normalisation; normalising a raw `CFGBlock` mapping
    here would produce edges the caller never built.
    """
    builder = _Builder(entry, blocks, successors,
                       slot_tables=slot_tables, decoder=decoder, image=image)
    return builder.build()
