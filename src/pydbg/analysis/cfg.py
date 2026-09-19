"""FunctionCFG — one function's control flow, with its gaps shown.

The graph pydbg already had (disasm/analysis.py) drops edges it cannot resolve
and models calls as though the callee were part of the caller. Both make it
look complete when it is not, and an incomplete graph that says so is worth
more than one that reads as total.
"""

from dataclasses import dataclass, field

from .refs import branch_target, is_indirect_branch

# Successor kinds. The two that carry None are the point: they name what the
# analysis could not resolve instead of leaving a hole where an edge should be.
FALL = "fall"            # ordinary fallthrough, including after a call
JCC = "jcc"              # conditional branch taken
JMP = "jmp"              # unconditional branch to a known target
INDIRECT = "indirect"    # branch through a register or memory: target unknown
RET = "ret"              # returns to the caller


@dataclass(frozen=True)
class CFGBlock:
    """A straight-line run of instructions and where it can go next."""

    rva: int
    instructions: tuple          # RVAs, ascending
    successors: tuple            # tuple[(kind, target_or_None), ...]

    @property
    def end(self):
        return self.instructions[-1] if self.instructions else self.rva

    def targets(self):
        """Successor RVAs that are known."""
        return tuple(t for _, t in self.successors if t is not None)


@dataclass
class FunctionCFG:
    """A function's blocks, and an honest statement of what is missing."""

    entry: int
    blocks: dict = field(default_factory=dict)
    # False when some branch in this function goes somewhere the analysis could
    # not resolve. Callers that walk the graph need to know the difference
    # between "this function has one exit" and "one exit is all we found".
    complete: bool = True
    # Instructions that call through a register or memory. They do not affect
    # the flow *within* this function — a call returns — but they are edges the
    # call graph is missing, which is why they are reported rather than folded
    # into the successors.
    indirect_calls: tuple = ()
    truncated: bool = False      # hit the block limit before finishing

    def __len__(self):
        return len(self.blocks)

    def edges(self):
        """(src, kind, dst) for every edge whose destination is known."""
        return tuple((block.rva, kind, target)
                     for block in self.blocks.values()
                     for kind, target in block.successors if target is not None)

    def unresolved(self):
        """(src, kind) for every edge whose destination is unknown.

        A `ret` has no destination and is not unknown — we know exactly what it
        does. Only edges that genuinely go somewhere unstated are listed, so an
        empty result means the graph is complete rather than merely quiet.
        """
        return tuple((block.rva, kind)
                     for block in self.blocks.values()
                     for kind, target in block.successors
                     if target is None and kind != RET)


def build_function_cfg(decoder, image, functions, entry, max_blocks=4096):
    """Build the CFG of the function at 'entry'.

    Takes the decoder rather than an analyzer because that is all it needs; the
    function table supplies the extent and nothing else is consulted.

    Walks decoded instructions only: the analyzer has already decoded this
    function, so a byte with no recorded size is either outside it or a
    misaligned seed, and following it would invent flow that does not exist.
    Running out of decoded instructions is reported as an unresolved
    fallthrough rather than silently ending the block.
    """
    extent = functions.extent_of(entry)
    limit = entry + extent if extent else None

    cfg = FunctionCFG(entry=entry)
    indirect_calls = set()
    pending = [entry]
    visited = set()

    while pending:
        start = pending.pop()
        if start in visited or start in cfg.blocks:
            continue
        if len(cfg.blocks) >= max_blocks:
            cfg.truncated = True
            cfg.complete = False
            break
        visited.add(start)

        instructions = []
        successors = []
        addr = start
        while True:
            insn = decoder.decode_one(addr)
            if insn is None or (limit is not None and addr >= limit):
                # The run continues past what was decoded: say so rather than
                # ending the block as though that were the end of the function.
                successors.append((FALL, None))
                cfg.complete = False
                break

            instructions.append(addr)

            if insn.is_call and is_indirect_branch(insn):
                indirect_calls.add(addr)

            if insn.is_ret:
                successors.append((RET, None))
                break

            if insn.is_jmp:
                if is_indirect_branch(insn):
                    successors.append((INDIRECT, None))
                    cfg.complete = False
                    break
                target = branch_target(insn, image)
                if target is None:
                    successors.append((INDIRECT, None))
                    cfg.complete = False
                    break
                if insn.is_cond:
                    successors.append((JCC, target))
                    pending.append(target)
                    successors.append((FALL, addr + insn.size))
                    pending.append(addr + insn.size)
                else:
                    successors.append((JMP, target))
                    pending.append(target)
                break

            addr += insn.size

        cfg.blocks[start] = CFGBlock(rva=start,
                                     instructions=tuple(instructions),
                                     successors=tuple(successors))

    cfg.indirect_calls = tuple(sorted(indirect_calls))
    return cfg


def cfg_to_dot(cfg, name=None):
    """Render a CFG as Graphviz source.

    Unresolved edges become a node named after what is unknown, so a reader of
    the picture sees the gap rather than a graph that merely looks small.
    """
    label = name or f"sub_{cfg.entry:x}"
    lines = [f'digraph "{label}" {{', '  rankdir=TB;']
    lines.append('  node [shape=box, fontname="monospace"];')

    for rva, block in sorted(cfg.blocks.items()):
        text = "\\l".join(f"{addr:x}" for addr in block.instructions[:8])
        if len(block.instructions) > 8:
            text += "\\l..."
        lines.append(f'  b{rva:x} [label="{text}\\l"];')

    missing = set()
    for rva, block in sorted(cfg.blocks.items()):
        for kind, target in block.successors:
            if target is None:
                missing.add(kind)
                lines.append(f'  {kind}_{rva:x} [shape=ellipse, label="{kind}?"];')
                lines.append(f'  b{rva:x} -> {kind}_{rva:x} [style=dashed];')
            else:
                lines.append(f'  b{rva:x} -> b{target:x} [label="{kind}"];')
    del missing
    lines.append("}")
    return "\n".join(lines)
