"""Condition knowledge: negating one, and folding a `cmp` into an `if`.

This is the only place that decides what a branch's condition reads as when it
is printed. Negation inverts a comparison it knows and wraps anything else in
`!`; folding takes the C operator from the branch's own `comparison` field --
laid down by the lift from `ir`'s single condition table -- rather than
re-deriving it from the flag expression. A second copy of that table would
drift, and the drift would silently stop folding instead of failing.

`fold_compare` refuses what it cannot state exactly: an unsigned relation has
no C spelling in the table, so it never becomes a folded condition.
"""

from .ir import BinExpr, Cmp, Const, UnExpr

_INVERT = {"==": "!=", "!=": "==", "<": ">=", ">=": "<", ">": "<=", "<=": ">"}


def negate(condition):
    """The logical negation of a condition, as an expression."""
    if isinstance(condition, BinExpr) and condition.op in _INVERT:
        return BinExpr(_INVERT[condition.op], condition.left, condition.right)
    if isinstance(condition, UnExpr) and condition.op == "!":
        return condition.operand
    return UnExpr("!", condition)


def fold_compare(cmp_stmt, comparison):
    """Fold a `cmp`/`test` statement into an `if`-style condition, or None.

    'comparison' is the branch's C operator as the lift recorded it from the
    condition table (`None` when the condition has no exact C spelling). Using
    that field instead of comparing flag expressions keeps this pass from
    re-deriving a second copy of the table, which would silently stop folding
    whenever the first copy changed. A folded condition never says more than
    the flags did: unsigned relations are not in the table at all.
    """
    if not isinstance(cmp_stmt, Cmp) or comparison is None:
        return None
    op = comparison
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
