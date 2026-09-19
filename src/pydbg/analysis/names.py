"""Names for addresses — recovered, supplied, and made up on demand.

A list of hex addresses is not a description of a program. This attaches names
to them from whatever evidence exists, and — more importantly — gives every
address a *stable* name even when nothing names it, so that a name written by
hand last week still resolves today and can be shared.

Provenance is kept for every name. "This is called CreateFileW" means different
things depending on whether a symbol table said so, an export table said so, or
a person decided it, and merging the three into one string loses the only thing
that tells a reader how much to trust it.
"""

from dataclasses import dataclass

# Where a name came from, most to least authoritative. Kept as strings rather
# than an enum so a workspace file stays readable and forward-compatible.
SOURCE_USER = "user"
SOURCE_SYMBOL = "symbol"
SOURCE_EXPORT = "export"
SOURCE_IMPORT = "import"
SOURCE_DERIVED = "derived"      # from a structure this analysis recovered
SOURCE_AUTO = "auto"            # a made-up label: sub_401000

# Ordering for conflict resolution: the first source that claims an address
# wins, and a person always wins.
_PRECEDENCE = (SOURCE_USER, SOURCE_SYMBOL, SOURCE_EXPORT, SOURCE_IMPORT,
               SOURCE_DERIVED, SOURCE_AUTO)


@dataclass(frozen=True)
class Name:
    """One address's name, and where it came from."""

    rva: int
    text: str
    source: str

    def __str__(self):
        return self.text


class NameTable:
    """Address -> name, with precedence and provenance."""

    def __init__(self):
        self._by_rva = {}

    def __len__(self):
        return len(self._by_rva)

    def __contains__(self, rva):
        return rva in self._by_rva

    def add(self, rva, text, source=SOURCE_USER):
        """Attach a name, keeping the more authoritative one on conflict.

        Returns True when this name displaced what was there. Refusing to let
        an auto-generated label overwrite a real one is the point: the pass
        that makes up `sub_401000` runs over everything, and it must not be
        able to erase what the export table already said.
        """
        if rva is None or not text:
            return False
        existing = self._by_rva.get(rva)
        if existing is not None and not self._outranks(source, existing.source):
            return False
        self._by_rva[rva] = Name(rva=rva, text=text, source=source)
        return True

    @staticmethod
    def _outranks(source, other):
        try:
            return _PRECEDENCE.index(source) < _PRECEDENCE.index(other)
        except ValueError:
            return False

    def get(self, rva):
        return self._by_rva.get(rva)

    def name_of(self, rva):
        """The name for 'rva', or None if it has none."""
        found = self._by_rva.get(rva)
        return found.text if found else None

    def label(self, rva):
        """A name for 'rva', inventing `sub_`/`loc_` when nothing named it.

        Every address gets a stable, shareable label. An analysis full of hex
        cannot be talked about — "the function at 0x401234" does not survive
        being written down in a comment or compared between two runs.
        """
        found = self._by_rva.get(rva)
        if found is not None:
            return found.text
        return f"loc_{rva:06x}"

    def items(self):
        return self._by_rva.items()

    def to_dict(self):
        """Serialisable form, sorted for a stable diff."""
        return {f"{rva:#x}": {"text": name.text, "source": name.source}
                for rva, name in sorted(self._by_rva.items())}

    @classmethod
    def from_dict(cls, raw):
        table = cls()
        for key, value in (raw or {}).items():
            rva = int(key, 0)
            if isinstance(value, str):          # a plain str -> name mapping
                table.add(rva, value, SOURCE_USER)
            else:
                table.add(rva, value.get("text"), value.get("source", SOURCE_USER))
        return table


def import_names(image):
    """IAT slot RVA -> `dll!Function` for every imported function."""
    names = {}
    for entry in image.pe.imports:
        if not entry.rva:
            continue
        if entry.name:
            text = f"{entry.dll_name}!{entry.name}" if entry.dll_name else entry.name
        else:
            text = f"{entry.dll_name}!{entry.ordinal}"
        names[entry.rva] = text
    return names


def auto_names(result, function_starts=True):
    """Names the image's own metadata can supply.

    Three sources, in the order they are applied — which matters, because the
    fallback pass names everything and would otherwise bury the two that are
    evidence:

      - exports, which are the linker's own statement about what an address is;
      - import thunks, which turn `sub_401234` into `CreateFileW` for any
        binary that imports it, and need no symbols at all;
      - `sub_<rva>` for every other recovered function start, so nothing is
        left without a name to refer to it by.
    """
    table = NameTable()

    for export in result.image.pe.exports:
        if export.rva:
            table.add(export.rva, export.name or f"ordinal_{export.ordinal}",
                      SOURCE_EXPORT)

    slots = import_names(result.image)
    for thunk_rva, slot_rva in getattr(result, "import_thunks", {}).items():
        text = slots.get(slot_rva)
        if text:
            table.add(thunk_rva, text, SOURCE_IMPORT)

    if function_starts:
        for rva in result.functions.starts:
            if rva not in table:
                table.add(rva, f"sub_{rva:06x}", SOURCE_AUTO)

    return table


def resolve(result, names=None):
    """The table to report with: recovered names, plus any supplied ones.

    Supplied names are added last so that they win — a person overriding an
    export is a deliberate act, not a conflict to be resolved silently.
    """
    table = auto_names(result)
    for rva, name in (names or {}).items():
        if isinstance(name, Name):
            table.add(rva, name.text, name.source)
        else:
            table.add(rva, name, SOURCE_USER)
    return table
