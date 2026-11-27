"""Decompile one function into structured pseudo-C (S0, S1, S2, S4, S5).

The pipeline is deliberately shallow, and each stage is a separate module so it
can be read and tested on its own:

- **S0** -- `decompile_function` takes the extent and blocks from the analysis
  package (`build_function_cfg`). It does not re-walk bytes: the decoder already
  decided what is code, and a second traversal that disagreed with it would be a
  second answer to one question.
- **S1** -- `ir.lower_block` turns decoded instructions into statements, with
  anything outside the support subset kept as `Opaque`.
- **S2** -- `expr.recover` does block-local copy/constant propagation and moves
  dead register writes aside without losing their addresses.
- **S4** -- `structure` turns the CFG into `if`/`while`/`do`/`switch`, keeping
  the label/`goto` form for shapes it cannot prove and for irreducible regions.
- **S5** -- `render.render_function` writes the labelled text.

One thing happens between S0 and S1 that is worth naming. The CFG cannot follow
an indirect edge, so a switch's case blocks are absent from it even though the
analysis decoded them; `structure.jump_table_targets` reads the `SlotTable` the
analysis already produced and S0 grows blocks for those targets. That is not a
guess: the table is the image's own statement of where the cases begin, and the
structurer only emits a `switch` when every entry lands on one of those blocks.

Failure is a return value, not an exception: a function that is not in the
function table, or that has no decodable instructions, yields None. An
incomplete CFG yields a result whose `complete` is False and whose `warnings`
say why -- a decompilation that reads as total when it is not is worse than one
that admits its edge cases.
"""

from dataclasses import dataclass

from ..cfg import RET, build_function_cfg
from . import expr, render, structure
from .ir import Opaque, lower_block


@dataclass(frozen=True, slots=True)
class DecompiledFunction:
    """One function's text, together with what it could not cover.

    'blocks' is exactly the CFG's own block starts, ascending: what
    `build_function_cfg` built. A switch's case blocks are *not* in it, because
    the CFG cannot follow an indirect edge and never built them; the jump
    table names them, and they are reported separately in 'extra_blocks'
    (ascending). Keeping the two apart is what lets a caller compare the text
    against the CFG without the comparison quietly being true by construction;
    when 'extra_blocks' is non-empty the warnings say `jump-table blocks`.

    'unhandled' names each instruction that fell outside the model as
    (rva, mnemonic); its length is the number of `// unhandled:` lines those
    instructions produce. 'complete' is False when the CFG had an unresolved
    edge or was truncated, or when the renderer met a statement kind it has no
    form for (that line is still printed, as `// unhandled: statement <kind>`).
    'warnings' names the reason (`unresolved edges`, `truncated`,
    `jump-table blocks`, `irreducible`, `unmatched jump table`,
    `truncated jump table`, `region depth limit`, `unhandled statement`).
    """

    rva: int
    text: str
    blocks: tuple
    extra_blocks: tuple
    complete: bool
    unhandled: tuple
    warnings: tuple


def _unresolved(successors):
    """Whether any block has an edge whose destination the analysis lacks."""
    return any(target is None and kind != RET
               for block_successors in successors.values()
               for kind, target in block_successors)


def _with_jump_table_targets(blocks, slot_tables, result, max_blocks,
                             end=None):
    """Grow 'blocks' with the case bodies a jump table names.

    Returns (merged, extra_starts). 'blocks' itself is the CFG's; the starts
    that only the jump table revealed are returned separately so the caller
    can report them as such instead of presenting them as CFG blocks.
    `build_function_cfg` is reused for each target rather than re-implementing
    a walk: the case body is ordinary code and must be decoded the same way
    the rest of the function was.

    'end' is the containing function's end, passed to `build_function_cfg` as
    the bound for a target that is not itself a function entry. A case body
    that falls through must stop at its function's end rather than decode the
    padding after it or the next function.
    """
    merged = dict(blocks)
    extra_starts = []
    successors = {rva: block.successors for rva, block in merged.items()}
    targets = structure.jump_table_targets(
        merged, successors, slot_tables, result.decoder, result.image)
    for target in targets:
        if target in merged:
            continue
        extra = build_function_cfg(result.decoder, result.image,
                                   result.functions, target,
                                   max_blocks=max_blocks, end=end)
        for block_rva, block in extra.blocks.items():
            if block_rva in merged:
                continue
            merged[block_rva] = block
            extra_starts.append(block_rva)
    return merged, tuple(sorted(extra_starts))


def decompile_function(result, rva, max_blocks=4096):
    """Decompile the function starting at 'rva', or None when there is none.

    'rva' must be a function start recorded by the analysis: the function
    table's extents are what make the CFG stop at the right place, and
    decompiling "the function containing this address" would silently use a
    different start from the one the caller named.
    """
    if result is None or getattr(result, "decoder", None) is None:
        return None
    if rva is None or rva not in result.functions:
        return None

    cfg = build_function_cfg(result.decoder, result.image, result.functions,
                             rva, max_blocks=max_blocks)
    if not any(block.instructions for block in cfg.blocks.values()):
        return None

    slot_tables = tuple(getattr(result, "slot_tables", ()) or ())
    extent = result.functions.extent_of(rva)
    function_end = rva + extent if extent else None
    blocks, extra_blocks = _with_jump_table_targets(
        cfg.blocks, slot_tables, result, max_blocks, end=function_end)
    blocks = structure.normalize_blocks(blocks)
    successors = {block_rva: block.successors
                  for block_rva, block in blocks.items()}

    lowered = {block_rva: lower_block(result.decoder, result.image, block)
               for block_rva, block in blocks.items()}
    recovered = expr.recover(lowered, result.image.mode)
    structured = structure.build(
        rva, recovered, successors, slot_tables=slot_tables,
        decoder=result.decoder, image=result.image)
    text = render.render_function(rva, structured, successors,
                                  truncated=cfg.truncated)

    unhandled = tuple(
        (stmt.rva, stmt.mnemonic)
        for block_rva in sorted(recovered)
        for stmt in recovered[block_rva].stmts
        if isinstance(stmt, Opaque)
    )
    # A statement kind the renderer has no form for is printed as an
    # `// unhandled: statement ...` line rather than dropped, but a line that
    # states a gap must also stop the result from claiming completeness.
    unrendered = tuple(
        (stmt.rva, type(stmt).__name__)
        for block_rva in sorted(recovered)
        for stmt in recovered[block_rva].stmts
        if not render.is_rendered(stmt)
    )

    warnings = []
    if _unresolved(successors):
        warnings.append("unresolved edges")
    if cfg.truncated:
        warnings.append("truncated")
    if extra_blocks:
        warnings.append("jump-table blocks")
    if unrendered:
        warnings.append("unhandled statement")
    warnings.extend(structured.warnings)
    complete = (bool(cfg.complete) and not cfg.truncated
                and not _unresolved(successors) and not unrendered)

    return DecompiledFunction(
        rva=rva,
        text=text,
        blocks=tuple(sorted(cfg.blocks)),
        extra_blocks=extra_blocks,
        complete=complete,
        unhandled=unhandled,
        warnings=tuple(warnings),
    )
