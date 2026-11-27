"""One instruction, one owning block: normalisation and block-level helpers.

Blocks themselves are normalised first. `build_function_cfg` deliberately
re-decodes across a later block's start (its blocks overlap), which is harmless
for a flat listing and fatal for nesting: a loop header would appear twice. The
normalisation splits a block at the next known start and turns its tail into a
fall-through edge.

The two helpers answer "which instruction addresses does a block own", for both
a `CFGBlock` and a lowered `IRBlock`. The switch reader maps a table's referrer
back to the block that owns it and the region parser needs an instruction's
address to keep every line visible, so both must answer the same for either
kind of block.
"""

from ..cfg import CFGBlock, FALL


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
