"""Decompile one function into labelled pseudo-C (S0, S1, S2, S5).

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
- **S5** -- `render.render_function` writes the labelled text.

There is no structuring stage here: control flow is shown with labels and
`goto`, which is what the spec asks this ticket for. Turning the branches into
`if`/`while` is the next ticket's job, and the `Branch` statements keep their
condition expressions for it.

Failure is a return value, not an exception: a function that is not in the
function table, or that has no decodable instructions, yields None. An
incomplete CFG yields a result whose `complete` is False and whose `warnings`
say why -- a decompilation that reads as total when it is not is worse than one
that admits its edge cases.
"""

from dataclasses import dataclass

from ..cfg import build_function_cfg
from . import expr, render
from .ir import Opaque, lower_block


@dataclass(frozen=True, slots=True)
class DecompiledFunction:
    """One function's text, together with what it could not cover.

    'blocks' is every CFG block start, ascending. 'unhandled' names each
    instruction that fell outside the model as (rva, mnemonic); its length is
    the number of `// unhandled:` lines in the text. 'complete' is False when
    the CFG had an unresolved edge or was truncated, and 'warnings' names the
    reason (`unresolved edges`, `truncated`).
    """

    rva: int
    text: str
    blocks: tuple
    complete: bool
    unhandled: tuple
    warnings: tuple


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

    lowered = {block_rva: lower_block(result.decoder, result.image, block)
               for block_rva, block in cfg.blocks.items()}
    recovered = expr.recover(lowered, result.image.mode)
    successors = {block_rva: block.successors
                  for block_rva, block in cfg.blocks.items()}
    text = render.render_function(rva, recovered, successors,
                                  truncated=cfg.truncated)

    unhandled = tuple(
        (stmt.rva, stmt.mnemonic)
        for block_rva in sorted(recovered)
        for stmt in recovered[block_rva].stmts
        if isinstance(stmt, Opaque)
    )

    warnings = []
    if cfg.unresolved():
        warnings.append("unresolved edges")
    if cfg.truncated:
        warnings.append("truncated")
    complete = bool(cfg.complete) and not cfg.truncated

    return DecompiledFunction(
        rva=rva,
        text=text,
        blocks=tuple(sorted(recovered)),
        complete=complete,
        unhandled=unhandled,
        warnings=tuple(warnings),
    )
