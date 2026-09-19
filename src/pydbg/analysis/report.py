"""Text rendering for analysis results.

Plain text with stable ordering, so two runs can be compared with diff rather
than read. That is the whole reason this exists as a module: the reference
numbers these get checked against come from a separate prototype, and
eyeballing two tables is not a comparison.
"""

from .model import RefKind

_KIND_NAMES = {
    RefKind.BRANCH: "branch",
    RefKind.IMM: "imm",
    RefKind.MEM: "mem",
    RefKind.TABLE: "table",
    RefKind.DATA: "data",
}


def _kind_name(kind):
    try:
        return _KIND_NAMES[RefKind(kind)]
    except (ValueError, KeyError):
        return str(kind)


def render_stats(result):
    """One line per counter, sorted for stable diffs."""
    stats = result.stats.as_dict()
    return "\n".join(f"{key:24s} {stats[key]}" for key in sorted(stats))


def render_coverage(result):
    """Per-section coverage, with the overlap that qualifies it.

    The overlap is printed alongside rather than hidden: a coverage figure
    whose decode has drifted reads high, so the number that says how much of it
    is suspect belongs on the same line.
    """
    lines = [f"{'section':10s} {'covered':>9s} {'total':>9s} {'ratio':>7s}  overlap"]
    for name in sorted(result.coverage):
        report = result.coverage[name]
        lines.append(f"{name:10s} {report.covered:9d} {report.total:9d} "
                     f"{report.ratio * 100:6.1f}%  {report.overlap_bytes}")
    return "\n".join(lines)


def render_names(result, workspace=None, limit=None, source=None):
    """The name table, with provenance.

    Provenance is shown because it is the only thing that says how much to
    trust a name: an export is the linker's own statement, an import thunk
    name is exact, and `sub_401000` is this analysis admitting it does not
    know. They must not look alike in the output.
    """
    table = result.names(workspace)
    rows = sorted(table.items())
    if source is not None:
        rows = [(rva, name) for rva, name in rows if name.source == source]
    if limit is not None:
        rows = rows[:limit]
    lines = [f"{'rva':>10s}  {'source':9s} name"]
    for rva, name in rows:
        lines.append(f"{rva:#010x}  {name.source:9s} {name.text}")
    return "\n".join(lines)


def render_functions(result, limit=None, workspace=None, names=True):
    """Recovered functions, ascending, with confidence and names."""
    functions = result.functions.functions()
    if limit is not None:
        functions = functions[:limit]
    table = result.names(workspace) if names else None

    lines = [f"{'rva':>10s} {'size':>6s}  conf  name"]
    for function in functions:
        shown = table.label(function.rva) if table is not None else ""
        lines.append(f"{function.rva:#010x} {function.size:6d}  "
                     f"{'yes' if function.confident else 'no'}   {shown}")
    if limit is not None and len(result.functions) > limit:
        lines.append(f"... {len(result.functions) - limit} more")
    return "\n".join(lines)


def render_xrefs(result, target=None, limit=8):
    """Cross-references, grouped by target.

    Kinds are kept apart in the output for the same reason they are kept apart
    in the index: a branch is exact and a data pointer is a guess, and a reader
    deciding whether to trust a reference needs to see which it is.
    """
    lines = []
    targets = [target] if target is not None else sorted(result.xrefs)
    for rva in targets:
        refs = result.xrefs.get(rva)
        if not refs:
            continue
        lines.append(f"{rva:#010x}")
        by_kind = {}
        for ref in refs:
            by_kind.setdefault(_kind_name(ref.kind), []).append(ref.source)
        for kind in sorted(by_kind):
            sources = sorted(set(by_kind[kind]))
            shown = ", ".join(f"{s:#x}" for s in sources[:limit])
            more = f" (+{len(sources) - limit})" if len(sources) > limit else ""
            lines.append(f"    {kind:7s} {shown}{more}")
    return "\n".join(lines) if lines else "(no cross-references)"


def render_listing(image, rva, size, engine=None, names=None, comments=None):
    """Disassembly of a range, annotated with references, names and comments.

    Branch targets are shown as names where one is known: `call 0x4012f0` and
    `call CreateFileW` are the same instruction, and only one of them can be
    read.
    """
    from ..disasm.engine import DisasmEngine
    from .refs import classify_refs

    engine = engine or DisasmEngine(mode=image.mode)
    # Decode at the VA, as the analyzer does, so branch targets are absolute.
    # read_code_bytes rather than read_rva: asking for 64 bytes near the end of
    # a section is normal, and a short read there is not "unreadable".
    data = image.read_code_bytes(rva, size)
    if not data:
        return f"{rva:#x}: unreadable"

    def describe(target_rva):
        text = f"{target_rva:#x}"
        if names is not None:
            found = names.name_of(target_rva)
            if found:
                text = f"{found} ({target_rva:#x})"
        return text

    lines = []
    for insn in engine.disasm(image.rva_to_va(rva), data):
        insn_rva = image.va_to_rva(insn.address)
        refs = classify_refs(insn, image)
        annotation = ""
        if refs:
            annotation = "  ; " + ", ".join(
                f"{_kind_name(kind)}->{describe(target)}"
                for target, kind in refs)
        if comments and insn_rva in comments:
            annotation += f"   ; {comments[insn_rva]}"
        if names is not None and insn_rva is not None:
            found = names.name_of(insn_rva)
            if found and found != f"sub_{insn_rva:06x}":
                lines.append(f"; {found}:")
        raw = insn.raw_bytes.hex()
        lines.append(f"{insn.address:#010x}  {raw:20s} "
                     f"{insn.mnemonic} {insn.op_str}{annotation}")
    return "\n".join(lines) if lines else "(nothing decoded)"


def render_cfg(cfg):
    """A CFG as text, with unresolved edges named."""
    lines = [f"entry {cfg.entry:#x}  blocks {len(cfg.blocks)}  "
             f"complete {'yes' if cfg.complete else 'NO'}"]
    if cfg.truncated:
        lines.append("(truncated at the block limit)")
    for rva in sorted(cfg.blocks):
        block = cfg.blocks[rva]
        lines.append(f"{rva:#010x}  {len(block.instructions)} insns")
        for kind, target in block.successors:
            where = "?" if target is None else f"{target:#x}"
            lines.append(f"    -> {kind:8s} {where}")
    if cfg.indirect_calls:
        lines.append("indirect calls (edges the call graph is missing):")
        for rva in cfg.indirect_calls:
            lines.append(f"    {rva:#010x}")
    return "\n".join(lines)


def render_attribution(attribution, limit=10):
    """What the uncovered and overlapping bytes actually are.

    Printed beside the coverage it explains: a percentage without this is not
    actionable, because padding nobody can decode, a jump table, and code no
    seed reached call for three different pieces of work and look identical in
    the total.
    """
    lines = ["uncovered bytes by cause"]
    for name in sorted(attribution.sections):
        breakdown = attribution.sections[name]
        total = breakdown.total
        if not total:
            continue
        lines.append(
            f"  {name:10s} {total:7d}  padding {breakdown.padding:7d} "
            f"({100 * breakdown.padding / total:4.1f}%)  "
            f"data {breakdown.data:6d} ({100 * breakdown.data / total:4.1f}%)  "
            f"code {breakdown.code:6d} ({100 * breakdown.code / total:4.1f}%)  "
            f"unknown {breakdown.unknown:6d} ({100 * breakdown.unknown / total:4.1f}%)")

    biggest = attribution.worst_unknown(limit)
    if biggest:
        lines.append("")
        lines.append("largest unattributed runs (the part worth looking at)")
        for name, start, end in biggest:
            lines.append(f"  {name:10s} {start:#010x}-{end:#010x}  {end - start} bytes")

    if attribution.overlap_by_origin:
        lines.append("")
        lines.append("overlap bytes by cause (existing <- new)")
        for (existing, new), count in list(attribution.overlap_by_origin.items())[:limit]:
            lines.append(f"  {existing:24s} <- {new:24s} {count}")
    return "\n".join(lines)


def render_indirect_sites(result, limit=40, calls_only=True):
    """Branches whose target was not resolved.

    This is the footnote to `callers_of`. A function reached only through one
    of these has no recorded callers, and without this list that is
    indistinguishable from having none.
    """
    sites = (result.indirect_call_sites() if calls_only
             else result.indirect_sites)
    header = ("indirect call sites (call graph is incomplete through these)"
              if calls_only else "unresolved indirect branches")
    lines = [header]
    for site in sites[:limit]:
        lines.append(f"{site.rva:#010x}  {'call' if site.is_call else 'jmp '}"
                     f"  {site.text}")
    if len(sites) > limit:
        lines.append(f"... {len(sites) - limit} more")
    if not sites:
        lines.append("(none)")
    return "\n".join(lines)


def render_summary(result):
    """The one-screen overview: what was found and how much to trust it."""
    stats = result.stats
    lines = [
        f"image            {result.image.mode} base {result.image.image_base:#x}",
        f"instructions     {stats.insns}",
        f"functions        {stats.func_starts} "
        f"({stats.func_starts_confident} confident)",
        f"cross-references {stats.xrefs} over {stats.xref_targets} targets",
        f"undecodable      {len(result.undecodable)}",
        # Both halves of the indirect story on one line. The resolved count
        # alone reads as progress even while most sites stay unknown.
        f"indirect branches {stats.indirect_resolved} resolved, "
        f"{stats.indirect_unknown} unresolved"
        f"{'' if result.call_graph_is_complete() else '  <- call graph incomplete'}",
        "",
        render_coverage(result),
    ]
    return "\n".join(lines)
