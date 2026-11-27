"""The CFG facts the structuring pass reads: successors, dominators, loops.

- **Dominators** by the Cooper-Harvey-Kennedy iterative algorithm (immediate
  dominators over reverse postorder).
- **Natural loops** from back edges -- an edge whose target dominates its
  source. The header is the target.
- **Irreducible regions** -- a strongly connected component with more than one
  node that no natural loop covers -- are left flat (labels and `goto`) and
  reported as ``irreducible``.

`GraphFacts` is a mixin of the structuring pass, not an object it owns: the
region parser and the switch recogniser ask these questions in place
(`self.idom`, `self.loop_at`), so a separate object would add a hop to every
question without making any answer clearer. The subclass sets `entry`,
`blocks`, `successors`, `order`, `preds` and `warnings`, then calls
`_compute_graph_facts`. Nothing here imports the region parser or the switch
recogniser, so the dependency runs one way.
"""

from dataclasses import dataclass

from ..cfg import FALL, INDIRECT, JCC, JMP
from .ir import Branch

# A virtual exit node for the post-dominator dataflow. Every block whose flow
# leaves the function (a return, an unresolved indirect edge) points here.
EXIT = -1


@dataclass
class _Loop:
    header: int
    body: frozenset
    latches: frozenset
    done: bool = False


class GraphFacts:
    """Dominators, post-dominators, loops and SCCs over one function's CFG.

    The attributes below belong to the subclass: it sets them before calling
    `_compute_graph_facts`, which adds `idom`, `postdom`, `ipdom`, `loops`,
    `loop_at` and `force_flat` here. Keeping the algorithms as methods on the
    structurer is what lets a body like `self._dominates(target, rva)` read the
    same as it did when this was one module.
    """

    entry: int
    blocks: dict
    successors: dict
    order: list
    preds: dict
    warnings: set

    def _compute_graph_facts(self):
        self._compute_dominators()
        self._compute_postdominators()
        self.loops = self._natural_loops()
        self.loop_at = {loop.header: loop for loop in self.loops}
        self.force_flat = set()
        self._find_irreducible()

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
