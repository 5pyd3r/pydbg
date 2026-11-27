"""The structured tree S4 builds and S5 prints.

Every node is a frozen dataclass, so a parsing decision can be compared, hashed
and carried without a later pass mutating the one it was holding. A node says
only what was recognised; the addresses of the instructions a construct
consumed travel with it, because an instruction that cannot be found in the
text cannot be checked against the decode.

Blocks are wrapped, not merged: `Statements` and `Flat` hold one block each and
the rest nest them. `render` switches on exactly these types.
"""

from dataclasses import dataclass


class Node:
    """Marker base for the structured tree."""


@dataclass(frozen=True)
class Statements(Node):
    """A block's statements, without any control-flow line of its own.

    Used for a header whose branch a parent construct represents, and for the
    last block of a region whose jump is implied by where the region ends.
    'folded' names statement RVAs a parent condition already displays.
    """

    block: object
    folded: tuple = ()


@dataclass(frozen=True)
class Flat(Node):
    """A block rendered exactly as P5 did: statements then CFG edge lines."""

    block: object
    next_rva: int | None = None


@dataclass(frozen=True)
class Seq(Node):
    items: tuple


@dataclass(frozen=True)
class If(Node):
    header: Statements
    condition: object
    rvas: tuple
    then: Seq
    orelse: Seq | None = None


@dataclass(frozen=True)
class While(Node):
    header: Statements
    condition: object
    rvas: tuple
    body: Seq


@dataclass(frozen=True)
class DoWhile(Node):
    body: Seq
    condition: object
    rvas: tuple


@dataclass(frozen=True)
class Switch(Node):
    header: Statements
    index: object
    rvas: tuple
    cases: tuple          # ((slot_index, Seq), ...) in table order
    default: Seq | None = None


@dataclass(frozen=True)
class Break(Node):
    rva: int


@dataclass(frozen=True)
class Continue(Node):
    rva: int


@dataclass(frozen=True)
class Structured:
    """What the structuring pass produces: a tree and what it could not do."""

    nodes: tuple
    warnings: tuple
