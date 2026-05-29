from dataclasses import dataclass, field


@dataclass
class BasicBlock:
    start_addr: int
    end_addr: int
    instructions: list
    successors: list = field(default_factory=list)


@dataclass
class CFGEdge:
    src: int
    dst: int
    type: str  # "fallthrough", "branch", "call", "indirect"


@dataclass
class ControlFlowGraph:
    entry: int
    blocks: dict  # start_addr -> BasicBlock
    edges: list = field(default_factory=list)


def _resolve_direct_target(insn) -> int | None:
    """Extract immediate target address from instruction op_str."""
    if insn is None:
        return None
    op = insn.op_str.strip()
    if not op:
        return None
    # Capstone format: "0x401000" or "0x401000, ..." for memory operands
    first = op.split(',')[0].strip()
    try:
        if first.lower().startswith('0x'):
            return int(first, 16)
        if first.lower().endswith('h'):
            return int(first[:-1], 16)
        return None
    except (ValueError, TypeError):
        return None


def _compute_successors(last_insn) -> list[int]:
    """Determine successor addresses from a block's last instruction."""
    if last_insn is None:
        return []
    successors = []
    next_addr = last_insn.address + last_insn.size
    if last_insn.is_ret:
        return successors  # no successors
    if last_insn.is_cond:
        target = _resolve_direct_target(last_insn)
        if target is not None:
            successors.append(target)
        successors.append(next_addr)  # fallthrough
    elif last_insn.is_jmp:
        target = _resolve_direct_target(last_insn)
        if target is not None:
            successors.append(target)
        # unconditional jmp has no fallthrough
    elif last_insn.is_call:
        target = _resolve_direct_target(last_insn)
        if target is not None:
            successors.append(target)
        successors.append(next_addr)  # call returns
    else:
        successors.append(next_addr)  # regular fallthrough
    return successors


def build_blocks(instructions: list) -> list[BasicBlock]:
    """Split a linear instruction list into basic blocks."""
    if not instructions:
        return []

    leaders = {instructions[0].address}
    insn_map = {i.address: i for i in instructions}

    for insn in instructions:
        if insn.is_jmp or insn.is_call or insn.is_ret:
            next_addr = insn.address + insn.size
            if next_addr in insn_map:
                leaders.add(next_addr)
        target = _resolve_direct_target(insn)
        if target is not None and target in insn_map:
            leaders.add(target)

    sorted_leaders = sorted(leaders)
    blocks = []
    for i, start in enumerate(sorted_leaders):
        end = sorted_leaders[i + 1] - 1 if i + 1 < len(sorted_leaders) else instructions[-1].address
        block_insns = []
        for insn in instructions:
            if start <= insn.address <= end:
                block_insns.append(insn)
        last = block_insns[-1] if block_insns else None
        successors = _compute_successors(last)
        blocks.append(BasicBlock(
            start_addr=start,
            end_addr=last.address if last else start,
            instructions=block_insns,
            successors=successors,
        ))
    return blocks


def _edge_type(last_insn, target: int) -> str:
    if last_insn is None:
        return "fallthrough"
    resolved = _resolve_direct_target(last_insn)
    if resolved is not None:
        if last_insn.is_call and resolved == target:
            return "call"
        if last_insn.is_cond and resolved == target:
            return "branch"
        if last_insn.is_jmp and resolved == target:
            return "branch"
    if target == last_insn.address + last_insn.size:
        return "fallthrough"
    return "indirect"


def build_cfg(blocks: list[BasicBlock], entry_addr: int | None = None) -> ControlFlowGraph:
    """Build CFG from basic blocks using recursive descent."""
    if not blocks:
        return ControlFlowGraph(entry=0, blocks={}, edges=[])

    if entry_addr is None:
        entry_addr = blocks[0].start_addr

    block_map = {b.start_addr: b for b in blocks}
    visited = set()
    edges = []

    def visit(addr):
        if addr in visited or addr not in block_map:
            return
        visited.add(addr)
        block = block_map[addr]
        last_insn = block.instructions[-1] if block.instructions else None
        for succ in block.successors:
            edge = CFGEdge(src=addr, dst=succ, type=_edge_type(last_insn, succ))
            edges.append(edge)
            visit(succ)

    visit(entry_addr)

    return ControlFlowGraph(
        entry=entry_addr,
        blocks={a: block_map[a] for a in visited},
        edges=edges,
    )
