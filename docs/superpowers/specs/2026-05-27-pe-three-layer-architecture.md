# PE Module Three-Layer Architecture Design

## Goal

Refactor `pe.py` into a three-layer architecture (Source → View → Parse) to support multiple data sources (file, process memory, dump) and PE states (file state, loaded state).

## Architecture

```
Source (read bytes)
  ↓
Parse (binary structure → headers + sections)
  ↓
View (RVA → source offset strategy)
  ↓
Parse (exports, imports, using View for address translation)
  ↓
PE (structured dataclass output)
```

## Layer 1: Source

**Interface:** `read(offset, size) -> bytes`

Random-access byte provider. Abstracts over where bytes come from.

**What it does:**
- Provide bytes at given offset and size
- Abstract over different byte origins

**What it does NOT:**
- Know PE format
- Translate addresses (that's View's job)
- Cache (implementation detail, transparent to consumers)

**Implementations:**
- `FileSource` — reads from PE file on disk
- `MemorySource` — reads from process memory via MemoryManager (constructed with process_handle + module_base, adds base to offset)
- `DumpSource` — reads from memory dump file (minidump or raw dump)

**File layout:** `src/pydbg/pe/source.py`

## Layer 2: View

**Interface:** `rva_to_source_offset(rva) -> int`

Address translation strategy. Converts PE-relative virtual addresses to Source offsets.

**What it does:**
- Know whether PE is in file state or loaded state
- Map RVA to Source offset using section headers

**What it does NOT:**
- Read bytes (delegates to Source)
- Parse PE structures (Parse does that)

**How View is created:**
Parse first extracts section headers (fixed PE format regardless of state).
View is then constructed from those sections.

**Implementations:**
- `FileView(sections)` — RVA → section lookup → pointer_to_raw_data + (RVA - virtual_address)
- `LoadedView(sections)` — RVA → identity (RVA is the source offset; Source already handles module base)

**File layout:** `src/pydbg/pe/view.py`

## Layer 3: Parse

Consumes Source + View. Produces structured `PE` dataclass output.

**What it does:**
- Parse DOS header, NT headers, section headers from raw bytes
- Parse exports and imports using View for RVA translation
- Produce dataclass instances (DosHeader, FileHeader, etc.)

**What it does NOT:**
- Read bytes directly (uses Source)
- Know byte origin or address translation strategy

**Two-pass parsing:**
1. First pass: headers + sections (no View needed — sections at fixed offsets in PE format)
2. Build View from parsed sections
3. Second pass: exports/imports (uses View.rva_to_source_offset)

**File layout:**
- `src/pydbg/pe/types.py` — dataclasses (existing, moved from pe.py)
- `src/pydbg/pe/parser.py` — PE parser class
- `src/pydbg/pe/__init__.py` — public API, re-exports

## File Layout

```
src/pydbg/pe/
├── __init__.py    — public API (PE class, dataclasses, Source/View types)
├── types.py       — DosHeader, FileHeader, OptionalHeader, SectionHeader,
│                    DataDirectory, ExportEntry, ImportEntry
├── source.py      — Source ABC, FileSource, MemorySource, DumpSource
├── view.py        — View ABC, FileView, LoadedView
└── parser.py      — PEParser class (headers, sections, exports, imports)
```

## PE Class (Public API)

```python
class PE:
    """PE format parser. Public API — all layers hidden internally."""

    def __init__(self, source: Source, view: View | None = None):
        # If view not provided, PE is treated as file state by default
        ...

    @staticmethod
    def from_file(path: str) -> PE: ...

    @staticmethod
    def from_process(memory: MemoryManager, module_base: int) -> PE: ...

    @staticmethod
    def from_dump(path: str) -> PE: ...

    # All existing parsed data attributes remain:
    # dos_header, file_header, optional_header, sections, exports, imports
```

## Backward Compatibility

- `PE(data: bytes)` — changed to use Source internally: `PE(ByteSource(data))`
- `PE.from_file(path)` — same API, uses `FileSource` internally
- Existing dataclass names unchanged
- `rva_to_offset()` moves to `FileView`, PE delegates

## Migration Plan

1. Create `pe/` package directory
2. Move dataclasses to `types.py` — no behavior change
3. Create `source.py` with `Source` ABC and `FileSource`
4. Create `view.py` with `View` ABC and `FileView`
5. Create `parser.py` — move existing PE parsing logic
6. Create `pe/__init__.py` — PE facade with factory methods
7. Keep old `pe.py` as deprecated re-export shim for one release cycle, then remove

## Testing

- Existing tests should pass without changes (API compatibility)
- New tests for MemorySource, LoadedView (requires real process / mock)
- New tests for DumpSource (requires minidump sample data)
