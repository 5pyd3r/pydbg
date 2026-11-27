"""Jump tables: reading one, and recognising a `switch` over it.

- **switch** only when a `SlotTable` from the analysis names a table whose
  entries all land on blocks of this function *and* an immediate-dominator
  chain of pure `cmp`+`jcc` bounds checks leads to the indirect jump. The case
  labels are the table's slot indices, not reconstructed source values: the
  analysis knows the table's order, not the original `case` constants.

The table is read in exactly one place, `_slot_targets`: switch recognition and
`jump_table_targets` (the extra-block discovery S0 uses) must decode the slots
the same way, and one loop is what keeps two copies of the stride arithmetic
from drifting.

`SwitchRecognition` is a mixin of the structuring pass, for the same reason
`graph.GraphFacts` is: what it recognises is asked for and consumed in place by
the region parser, which then decides how to nest the case bodies.
"""

from dataclasses import dataclass

from ..cfg import INDIRECT, JCC
from .blocks import _block_addresses
from .expr import family
from .ir import Branch, Cmp, Reg


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


def _slot_targets(table, image):
    """(slot index, target RVA or None) for every slot a jump table names.

    Both readers of a SlotTable -- switch recognition here and the extra-block
    discovery in `jump_table_targets` -- must decode the slots the same way.
    Sharing the loop is what keeps two copies of the stride arithmetic from
    drifting; the target stays None when a slot does not hold an RVA.
    """
    for index in range(table.count):
        value = image.read_pointer(table.base + index * table.stride)
        yield index, None if value is None else image.va_to_rva(value)


class SwitchRecognition:
    """Which indirect jumps are switches, and on which table.

    The attributes below belong to the subclass: it sets them before calling
    `_find_switches`, which fills `switch_plans` and `switch_consumed` with the
    plans the region parser then builds. Reading the structurer's own CFG facts
    in place is what keeps this a move rather than a rewrite of every call.
    """

    slot_tables: tuple
    blocks: dict
    successors: dict
    decoder: object
    image: object
    owner_of_instruction: dict
    warnings: set
    switch_plans: dict
    switch_consumed: set
    order: list
    idom: dict

    # ── switch recognition ─────────────────────────────────────

    def _find_switches(self):
        considered = set()      # dispatch blocks a SlotTable named
        for table in self.slot_tables:
            referrer = getattr(table, "referrer", None)
            if referrer is None:
                continue
            dispatch = self.owner_of_instruction.get(referrer)
            if dispatch is None or not self._has_indirect(dispatch):
                continue
            considered.add(dispatch)
            plan = self._make_switch_plan(table, dispatch)
            if plan is None:
                # `_make_switch_plan` records the more specific reason when
                # it refuses a truncated table; "unmatched" would be wrong
                # there, because the table does match the dispatch.
                if not getattr(table, "truncated", False):
                    self.warnings.add("unmatched jump table")
                continue
            if plan.start in self.switch_plans:
                continue
            self.switch_plans[plan.start] = plan
            self.switch_consumed.update(plan.chain)
            self.switch_consumed.add(plan.dispatch)
        # A table-shaped indirect jump with no table behind it is still worth
        # a warning: the flat `goto *...` is honest but the reader should know
        # a switch was possible. A dispatch whose SlotTable was considered
        # above has already been answered (or refused with its own warning).
        for rva in self.order:
            if (rva in considered or rva in self.switch_consumed
                    or not self._has_indirect(rva)):
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
        if getattr(table, "truncated", False):
            # model.SlotTable.truncated means the reader stopped at its entry
            # budget: `count` is a lower bound on the cases, not the table's
            # size. A switch built from it would print a prefix as if it were
            # the whole case set ("512 entries" for "at least 512"), the same
            # silent-completeness defect the model's own contract forbids.
            # Keep the flat `goto *...` form and name the reason.
            self.warnings.add("truncated jump table")
            return None

        cases = []
        for index, target in _slot_targets(table, self.image):
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
        if stmts[-1].kind != JCC:
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
        for _, target in _slot_targets(table, image):
            if target is not None and image.is_exec(target):
                targets.add(target)
    return tuple(sorted(targets))
