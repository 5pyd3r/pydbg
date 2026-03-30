# PE Parser Design Spec

Date: 2026-03-30
Status: Draft

## Goal

Add PE (Portable Executable) format parsing to pydbg, enabling extraction of DLL information during LOAD_DLL debug events and from arbitrary byte sources (files, process memory).

## Requirements

- Pure-Python PE parser that operates on `bytes` input
- Parse DOS header, NT headers (PE32/PE32+), section headers
- Parse export directory (exported function names, ordinals, RVAs, forwarders)
- Parse import directory (imported DLL names, function names, ordinals, RVAs)
- Integrate with LOAD_DLL debug event: Cython layer reads DLL data from `hFile`, passes raw bytes in event dict
- No external dependencies beyond Python stdlib (`struct`)

## Architecture

### New file: `pydbg/pe.py`

Single module containing the `PE` class and supporting types.

```
pydbg/
  pe.py              ← NEW
  debugger.py        ← MODIFIED: add DebugEvent.dll_data, convenience method
  cython/
    _process.pyx     ← MODIFIED: read hFile data during LOAD_DLL event
    _win32types.pxd  ← MODIFIED: add ReadFile, GetFileSize, CreateFileA declarations
```

### Class: `PE`

```python
class PE:
    """PE format parser. Takes raw bytes and parses headers, sections, exports, imports."""

    def __init__(self, data: bytes):
        self._data = data
        self.dos_header: DosHeader       # e_magic, e_lfanew
        self.nt_headers: NtHeaders       # signature, file_header, optional_header
        self.file_header: FileHeader     # machine, time_date_stamp, number_of_sections, characteristics
        self.optional_header: OptionalHeader  # magic, entry_point, image_base, section_alignment, ...
        self.sections: list[SectionHeader]
        self.exports: list[ExportEntry]
        self.imports: list[ImportEntry]
        self._parse()
```

### Supporting types

```python
@dataclass
class DosHeader:
    e_magic: int        # 0x5A4D = "MZ"
    e_lfanew: int       # Offset to PE signature

@dataclass
class FileHeader:
    machine: int              # 0x14C = i386, 0x8664 = AMD64
    time_date_stamp: int
    number_of_sections: int
    characteristics: int

@dataclass
class OptionalHeader:
    magic: int               # 0x10B = PE32, 0x20B = PE32+
    major_linker_version: int
    minor_linker_version: int
    size_of_code: int
    entry_point_rva: int
    base_of_code: int
    image_base: int
    section_alignment: int
    file_alignment: int
    size_of_image: int
    size_of_headers: int
    checksum: int
    subsystem: int
    number_of_rva_and_sizes: int
    data_directories: dict[int, DataDirectory]  # index -> DataDirectory

@dataclass
class DataDirectory:
    virtual_address: int
    size: int

@dataclass
class SectionHeader:
    name: str
    virtual_size: int
    virtual_address: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    characteristics: int

@dataclass
class ExportEntry:
    name: str | None     # None if exported by ordinal only
    ordinal: int
    rva: int
    forwarder: str | None  # DLLName.ProcName if forwarded, None otherwise

@dataclass
class ImportEntry:
    dll_name: str
    name: str | None     # None if imported by ordinal only
    ordinal: int | None  # None if imported by name
    rva: int             # RVA of the IAT entry (thunk)
```

### PE Format Parsing Details

#### 1. DOS Header

Read at offset 0:
- `e_magic` (2 bytes): must be 0x5A4D ("MZ")
- `e_lfanew` (4 bytes at offset 0x3C): offset to PE signature

Validate `e_magic` is "MZ". Raise `ValueError` if not.

#### 2. NT Headers at `e_lfanew`

- PE Signature (4 bytes): must be 0x00004550 ("PE\0\0")
- `IMAGE_FILE_HEADER` (20 bytes): machine, time_date_stamp, number_of_sections, etc.
- `IMAGE_OPTIONAL_HEADER`: size depends on PE32 (224 bytes) vs PE32+ (240 bytes), determined by `magic` field at offset 0x18 from start of optional header

Key differences between PE32 and PE32+:
- PE32: `magic=0x10B`, image_base is 4 bytes, has `base_of_data` field
- PE32+: `magic=0x20B`, image_base is 8 bytes, no `base_of_data` field

Data directories follow the optional header static fields. Count = `number_of_rva_and_sizes`.

Important data directory indices:
- 0 = Export
- 1 = Import
- 2 = Resource
- 5 = Base Relocation
- 11 = Import Address Table (IAT)

#### 3. Section Headers

Follow immediately after data directories. Each is 40 bytes:
- Name (8 bytes, null-padded ASCII)
- VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData
- Characteristics

#### 4. Export Directory Parsing

From `DataDirectories[0]`:
1. Convert RVA to file offset using section headers
2. Read IMAGE_EXPORT_DIRECTORY (40 bytes)
3. Read name (dll name RVA -> string)
4. Read export name table (AddressOfNames), ordinal table (AddressOfNameOrdinals), address table (AddressOfFunctions)
5. Each address entry: if RVA falls within export directory range -> it's a forwarder string; otherwise -> it's a function RVA

#### 5. Import Directory Parsing

From `DataDirectories[1]`:
1. Convert RVA to file offset
2. Read IMAGE_IMPORT_DESCRIPTOR entries (20 bytes each, terminated by null entry)
3. Each descriptor has: OriginalFirstThunk (ILT RVA), Name (DLL name RVA), FirstThunk (IAT RVA)
4. Read ILT entries: each is 8 bytes (PE32+) or 4 bytes (PE32)
   - Ordinal flag: highest bit set -> lower bits are ordinal
   - Otherwise -> RVA to IMAGE_IMPORT_BY_NAME (hint + name string)

#### 6. RVA to File Offset Conversion

```python
def rva_to_offset(self, rva: int) -> int | None:
    """Convert RVA to file offset using section headers."""
    for section in self.sections:
        if section.virtual_address <= rva < section.virtual_address + section.virtual_size:
            return rva - section.virtual_address + section.pointer_to_raw_data
    return None
```

### Integration with LOAD_DLL Event

#### `_process.pyx` changes

When `code == LOAD_DLL_DEBUG_EVENT`:

1. Get `hFile = de.u.LoadDll.hFile`
2. Get file size via `GetFileSize(hFile, NULL)`
3. Allocate buffer, `ReadFile(hFile, buf, size, &bytes_read, NULL)`
4. Close the file handle (it's no longer needed after `ContinueDebugEvent`)
5. Add `'dll_data': bytes` to event dict
6. Also extract `lpImageName` and `fUnicode` to get DLL name (optional, may be NULL for some DLLs)

#### `DebugEvent` changes

Add `dll_data` slot:
```python
__slots__ = ('type', 'pid', 'tid', 'exception_code', 'exception_addr',
             'first_chance', 'exception_name', 'exception_info', 'raw',
             'dll_base', 'dll_data')
```

In `__init__`:
```python
self.dll_base = event_dict.get('dll_base')
self.dll_data = event_dict.get('dll_data')
```

#### `_win32types.pxd` additions

```c
DWORD GetFileSize(HANDLE hFile, DWORD* lpFileSizeHigh);
BOOL ReadFile(HANDLE hFile, void* lpBuffer, DWORD nNumberOfBytesToRead,
              DWORD* lpNumberOfBytesRead, void* lpOverlapped);
BOOL CloseHandle(HANDLE hObject);  // already declared
```

### Debugger Convenience Method

```python
def parse_loaded_dll(self, event: DebugEvent) -> PE | None:
    """Parse PE from a LOAD_DLL event's dll_data.

    Returns PE object or None if no dll_data available.
    """
    if event.dll_data is None:
        return None
    return PE(event.dll_data)
```

Also add a static method for arbitrary sources:

```python
@staticmethod
def from_file(path: str) -> PE:
    """Parse PE from a file on disk."""
    with open(path, 'rb') as f:
        return PE(f.read())

@staticmethod
def from_memory(dbg: Debugger, base: int, size: int) -> PE:
    """Parse PE from process memory."""
    return PE(dbg.read_memory(base, size))
```

These convenience methods go on the `PE` class, not `Debugger`.

### Error Handling

- `PE.__init__` raises `ValueError` for invalid PE data (bad MZ signature, bad PE signature, truncated headers)
- Malformed export/import tables: return partial results (empty lists) rather than crashing
- RVA conversion failures: skip the entry, log warning

### `__init__.py` Changes

Export `PE` and data types:
```python
from .pe import PE, DosHeader, FileHeader, OptionalHeader, SectionHeader, ExportEntry, ImportEntry, DataDirectory
```

## Test Plan

### Unit tests: `tests/test_pe.py`

All tests use synthetic bytes (crafted PE headers), no real DLL required.

#### TestSyntheticPE
Build minimal PE32+ image in memory, feed to `PE()`:

1. `test_parse_dos_header` — verify e_magic, e_lfanew
2. `test_parse_file_header` — verify machine=AMD64, section count
3. `test_parse_optional_header_pe32plus` — verify magic, entry_point, image_base
4. `test_parse_sections` — verify .text, .rdata sections parsed correctly
5. `test_invalid_dos_signature` — `ValueError` for non-MZ bytes
6. `test_invalid_pe_signature` — `ValueError` for bad PE signature
7. `test_truncated_data` — `ValueError` for too-short data

#### TestExportParsing
8. `test_parse_exports` — synthetic export directory, verify name/ordinal/rva
9. `test_parse_forwarded_export` — forwarder string parsed correctly
10. `test_no_exports` — empty export directory returns empty list

#### TestImportParsing
11. `test_parse_imports` — synthetic import directory, verify dll_name/name/rva
12. `test_import_by_ordinal` — ordinal-only import parsed correctly
13. `test_no_imports` — empty import directory returns empty list

#### TestRvaConversion
14. `test_rva_to_offset` — RVA within .text section converts correctly
15. `test_rva_outside_sections` — returns None

#### TestRealDLL (integration)
16. `test_parse_kernel32` — parse kernel32.dll from System32, verify exports exist
17. `test_parse_from_process_memory` — use Debugger.read_memory to read a DLL base, parse it

## Files to Create/Modify

| File | Action |
|------|--------|
| `pydbg/pe.py` | CREATE — PE parser class |
| `pydbg/__init__.py` | MODIFY — export PE and data types |
| `pydbg/debugger.py` | MODIFY — add dll_base/dll_data to DebugEvent, add parse_loaded_dll() |
| `pydbg/cython/_process.pyx` | MODIFY — read hFile bytes during LOAD_DLL event |
| `pydbg/cython/_win32types.pxd` | MODIFY — add GetFileSize, ReadFile declarations |
| `tests/test_pe.py` | CREATE — PE parser tests |
