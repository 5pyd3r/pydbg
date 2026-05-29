# PE Module Three-Layer Architecture

## Goal

Refactor `pe.py` into Source/View/Parse layers to support multiple byte sources
(file, process memory, dump) and PE states (file state, loaded state).

## Architecture

```
Source (read bytes) → Parse (headers + sections)
    → View (RVA → source offset strategy)
    → Parse (exports, imports via View)
    → PE (facade)
```

## Layer 1: Source

`read(offset, size) -> bytes` — random-access byte provider.

- **FileSource** — reads from disk
- **BytesSource** — reads from in-memory buffer
- **MemorySource** — future, reads from process memory via debugger
- **DumpSource** — future, reads from memory dump

## Layer 2: View

`rva_to_source_offset(rva) -> int | None` — address translation strategy.

- **FileView** — RVA → file offset via section headers
- **LoadedView** — RVA = source offset (Source at module base)

View is constructed from parsed sections (two-pass parsing).

## Layer 3: Parse

Consumes Source + View. Two-pass:
1. Headers + sections (no View needed)
2. Exports + imports (uses View for RVA translation)

## File Layout

```
src/pydbg/pe/
  __init__.py — public API re-exports
  types.py   — dataclasses (DosHeader, FileHeader, SectionHeader, ...)
  source.py  — Source ABC, FileSource, BytesSource
  view.py    — View ABC, FileView, LoadedView
  parser.py  — PEParser (binary parsing)
```

`pe.py` remains as backward-compatible facade.
