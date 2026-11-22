# PE Parser Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a pure-Python PE format parser that can parse headers, sections, exports, and imports from raw `bytes`, and integrate it with LOAD_DLL debug events.

**Architecture:** A standalone `pydbg/pe.py` module with the `PE` class and dataclass types. Cython layer reads DLL data from `hFile` during LOAD_DLL events and passes raw bytes in the event dict. `DebugEvent` exposes `dll_base` and `dll_data` attributes.

**Tech Stack:** Python stdlib only (`struct`, `dataclasses`). No external dependencies.

---

## File Structure

| File | Responsibility |
|------|---------------|
| `pydbg/pe.py` | PE parser class + all dataclass types. Pure Python, no Win32 dependency. |
| `pydbg/debugger.py` | Add `dll_base`, `dll_data` to `DebugEvent`. Add `parse_loaded_dll()` convenience. |
| `pydbg/cython/_process.pyx` | Read `hFile` bytes during LOAD_DLL event, add `dll_data` to event dict. |
| `pydbg/cython/_win32types.pxd` | Declare `GetFileSize`, `ReadFile` Win32 functions. |
| `pydbg/__init__.py` | Export `PE` and dataclass types. |
| `tests/test_pe.py` | Unit tests with synthetic PE bytes. Integration test with real DLL. |
| `tests/meson.build` | Register `pe` test suite. |

---

### Task 1: Create dataclass types in `pydbg/pe.py`

**Files:**
- Create: `pydbg/pe.py`

- [ ] **Step 1: Write the dataclass types**

```python
"""PE (Portable Executable) format parser.

Parses PE32 and PE32+ binaries from raw bytes. No external dependencies.
"""

import struct
from dataclasses import dataclass


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
    data_directories: dict     # index -> DataDirectory


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

- [ ] **Step 2: Verify file is valid Python**

Run: `python -c "import ast; ast.parse(open('pydbg/pe.py').read()); print('OK')"`
Expected: OK

---

### Task 2: Implement PE._parse_dos_header

**Files:**
- Modify: `pydbg/pe.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_pe.py
import unittest
import struct


def build_minimal_pe32plus():
    """Build minimal synthetic PE32+ bytes for testing."""
    # DOS header: 64 bytes
    dos_header = struct.pack('<2s58xI',
        b'MZ',        # e_magic
        0x80)         # e_lfanew -> offset 128
    # Pad to 128 bytes (dos header + padding)
    dos_header += b'\x00' * (0x80 - len(dos_header))

    # PE signature
    pe_sig = struct.pack('<I', 0x00004550)  # "PE\0\0"

    # IMAGE_FILE_HEADER (20 bytes)
    file_header = struct.pack('<HHIIIHH',
        0x8664,       # machine: AMD64
        2,            # number_of_sections
        0x5A000000,   # time_date_stamp
        0,            # PointerToSymbolTable
        0,            # NumberOfSymbols
        0xF0,         # SizeOfOptionalHeader (PE32+)
        0x22)         # characteristics

    # IMAGE_OPTIONAL_HEADER64 (PE32+ static fields: 112 bytes before data dirs)
    # Fields: Magic(2), MajorLinkerVersion(1), MinorLinkerVersion(1),
    #         SizeOfCode(4), SizeOfInitializedData(4), SizeOfUninitializedData(4),
    #         AddressOfEntryPoint(4), BaseOfCode(4), ImageBase(8),
    #         SectionAlignment(4), FileAlignment(4), ...
    opt_header = struct.pack('<HBB',
        0x20B,        # magic: PE32+
        14,           # major linker version
        0)            # minor linker version
    opt_header += struct.pack('<III',
        0x1000,       # SizeOfCode
        0,            # SizeOfInitializedData
        0)            # SizeOfUninitializedData
    opt_header += struct.pack('<II',
        0x1000,       # AddressOfEntryPoint
        0x1000)       # BaseOfCode
    opt_header += struct.pack('<Q',
        0x140000000)  # ImageBase
    opt_header += struct.pack('<II',
        0x1000,       # SectionAlignment
        0x200)        # FileAlignment
    # ... skip to NumberOfRvaAndSizes at offset 92 from start of optional header
    # Fill zeros for OS/Loader/Subsystem versions and other fields
    # Current position: 2+1+1+4+4+4+4+4+8+4+4 = 40 bytes
    # Need to reach offset 92: 92 - 40 = 52 bytes of padding
    opt_header += b'\x00' * 52
    # Now at offset 92: NumberOfRvaAndSizes (4 bytes)
    opt_header += struct.pack('<I', 2)  # 2 data directories

    # Data directories: 2 entries * 8 bytes = 16 bytes
    # Entry 0 (Export): RVA=0x3000, Size=0x100
    # Entry 1 (Import): RVA=0x4000, Size=0x100
    data_dirs = struct.pack('<IIII',
        0x3000, 0x100,   # Export
        0x4000, 0x100)   # Import

    # Section headers: 2 * 40 bytes
    # .text section
    text_section = struct.pack('<8sIIIIIIHHI',
        b'.text\x00\x00\x00',  # Name
        0xE00,            # VirtualSize
        0x1000,           # VirtualAddress
        0x1000,           # SizeOfRawData
        0x400,            # PointerToRawData
        0, 0, 0, 0,
        0x60000020)       # Characteristics: CODE|EXECUTE|READ
    # .rdata section
    rdata_section = struct.pack('<8sIIIIIIHHI',
        b'.rdata\x00\x00',  # Name
        0xA00,            # VirtualSize
        0x2000,           # VirtualAddress
        0xC00,            # SizeOfRawData
        0x1400,           # PointerToRawData
        0, 0, 0, 0,
        0x40000040)       # Characteristics: DATA|READ

    data = dos_header + pe_sig + file_header + opt_header + data_dirs + text_section + rdata_section

    # Pad to at least 0x4200 bytes so export/import RVAs are within file
    if len(data) < 0x4200:
        data += b'\x00' * (0x4200 - len(data))

    return data


class TestSyntheticPE(unittest.TestCase):
    """Tests for PE parser with synthetic data."""

    def test_parse_dos_header(self):
        from pydbg.pe import PE
        data = build_minimal_pe32plus()
        pe = PE(data)
        self.assertEqual(pe.dos_header.e_magic, 0x5A4D)
        self.assertEqual(pe.dos_header.e_lfanew, 0x80)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_pe -v`
Expected: FAIL with `ModuleNotFoundError` or `ImportError` (PE class not yet defined)

- [ ] **Step 3: Implement PE class with _parse_dos_header**

Add to `pydbg/pe.py`:

```python
class PE:
    """PE format parser. Takes raw bytes and parses headers, sections, exports, imports."""

    def __init__(self, data: bytes):
        self._data = data
        self.dos_header = None
        self.file_header = None
        self.optional_header = None
        self.sections = []
        self.exports = []
        self.imports = []
        self._parse()

    def _parse(self):
        self._parse_dos_header()
        self._parse_nt_headers()

    def _parse_dos_header(self):
        if len(self._data) < 64:
            raise ValueError("Data too short for DOS header")
        magic = struct.unpack_from('<2s', self._data, 0)[0]
        if magic != b'MZ':
            raise ValueError(f"Invalid DOS signature: {magic!r}")
        e_lfanew = struct.unpack_from('<I', self._data, 0x3C)[0]
        self.dos_header = DosHeader(e_magic=0x5A4D, e_lfanew=e_lfanew)

    def _parse_nt_headers(self):
        pass  # placeholder
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_pe.TestSyntheticPE.test_parse_dos_header -v`
Expected: PASS

---

### Task 3: Implement PE._parse_nt_headers (FileHeader + OptionalHeader)

**Files:**
- Modify: `pydbg/pe.py`
- Modify: `tests/test_pe.py`

- [ ] **Step 1: Write the failing test**

```python
# Add to tests/test_pe.py in TestSyntheticPE class:

    def test_parse_file_header(self):
        from pydbg.pe import PE
        data = build_minimal_pe32plus()
        pe = PE(data)
        self.assertEqual(pe.file_header.machine, 0x8664)
        self.assertEqual(pe.file_header.number_of_sections, 2)
        self.assertEqual(pe.file_header.characteristics, 0x22)

    def test_parse_optional_header_pe32plus(self):
        from pydbg.pe import PE
        data = build_minimal_pe32plus()
        pe = PE(data)
        self.assertEqual(pe.optional_header.magic, 0x20B)
        self.assertEqual(pe.optional_header.entry_point_rva, 0x1000)
        self.assertEqual(pe.optional_header.image_base, 0x140000000)
        self.assertEqual(pe.optional_header.number_of_rva_and_sizes, 2)
        self.assertIn(0, pe.optional_header.data_directories)
        self.assertIn(1, pe.optional_header.data_directories)
        self.assertEqual(pe.optional_header.data_directories[0].virtual_address, 0x3000)
        self.assertEqual(pe.optional_header.data_directories[1].virtual_address, 0x4000)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_pe.TestSyntheticPE.test_parse_file_header tests.test_pe.TestSyntheticPE.test_parse_optional_header_pe32plus -v`
Expected: FAIL with `_parse_nt_headers is empty`

- [ ] **Step 3: Implement _parse_nt_headers**

Replace the `_parse_nt_headers` placeholder in `pydbg/pe.py`:

```python
def _parse_nt_headers(self):
    e_lfanew = self.dos_header.e_lfanew
    if e_lfanew + 24 > len(self._data):
        raise ValueError("Data too short for NT headers")

    # PE signature
    sig = struct.unpack_from('<I', self._data, e_lfanew)[0]
    if sig != 0x00004550:
        raise ValueError(f"Invalid PE signature: 0x{sig:08X}")

    # IMAGE_FILE_HEADER (20 bytes after signature)
    offset = e_lfanew + 4
    machine, num_sections, ts, _, _, opt_hdr_size, chars = struct.unpack_from(
        '<HHIIIHH', self._data, offset)
    self.file_header = FileHeader(
        machine=machine,
        time_date_stamp=ts,
        number_of_sections=num_sections,
        characteristics=chars,
    )

    # IMAGE_OPTIONAL_HEADER
    offset += 20
    magic = struct.unpack_from('<H', self._data, offset)[0]

    if magic == 0x20B:  # PE32+
        self._parse_optional_header_64(offset, num_sections)
    elif magic == 0x10B:  # PE32
        self._parse_optional_header_32(offset, num_sections)
    else:
        raise ValueError(f"Unknown optional header magic: 0x{magic:04X}")

def _parse_optional_header_64(self, offset, num_sections):
    if offset + 112 > len(self._data):
        raise ValueError("Data too short for PE32+ optional header")

    fields = struct.unpack_from('<HBBIIIIIIQIIIIHHHHHHIIII',
                                self._data, offset)
    # fields: magic(0), maj_link(1), min_link(2), size_code(3),
    #   size_init_data(4), size_uninit_data(5), entry_point(6), base_of_code(7),
    #   image_base(8), section_align(9), file_align(10),
    #   ... skip to NumberOfRvaAndSizes
    # NumberOfRvaAndSizes is at offset 92 from start of optional header
    num_rva = struct.unpack_from('<I', self._data, offset + 92)[0]

    # Data directories
    data_dirs_offset = offset + 112  # PE32+ static fields = 112 bytes
    data_dirs = {}
    for i in range(min(num_rva, 16)):
        dd_offset = data_dirs_offset + i * 8
        if dd_offset + 8 > len(self._data):
            break
        rva, size = struct.unpack_from('<II', self._data, dd_offset)
        data_dirs[i] = DataDirectory(virtual_address=rva, size=size)

    self.optional_header = OptionalHeader(
        magic=fields[0],
        major_linker_version=fields[1],
        minor_linker_version=fields[2],
        size_of_code=fields[3],
        entry_point_rva=fields[6],
        base_of_code=fields[7],
        image_base=fields[8],
        section_alignment=fields[9],
        file_alignment=fields[10],
        size_of_image=struct.unpack_from('<I', self._data, offset + 56)[0],
        size_of_headers=struct.unpack_from('<I', self._data, offset + 60)[0],
        checksum=struct.unpack_from('<I', self._data, offset + 64)[0],
        subsystem=struct.unpack_from('<H', self._data, offset + 68)[0],
        number_of_rva_and_sizes=num_rva,
        data_directories=data_dirs,
    )

    # Parse sections
    sections_offset = data_dirs_offset + num_rva * 8
    self._parse_sections(sections_offset, num_sections)

def _parse_optional_header_32(self, offset, num_sections):
    if offset + 96 > len(self._data):
        raise ValueError("Data too short for PE32 optional header")

    magic = struct.unpack_from('<H', self._data, offset)[0]
    maj_link = struct.unpack_from('<B', self._data, offset + 2)[0]
    min_link = struct.unpack_from('<B', self._data, offset + 3)[0]
    size_code = struct.unpack_from('<I', self._data, offset + 4)[0]
    entry_point = struct.unpack_from('<I', self._data, offset + 16)[0]
    base_of_code = struct.unpack_from('<I', self._data, offset + 20)[0]
    image_base = struct.unpack_from('<I', self._data, offset + 28)[0]
    section_align = struct.unpack_from('<I', self._data, offset + 32)[0]
    file_align = struct.unpack_from('<I', self._data, offset + 36)[0]
    size_of_image = struct.unpack_from('<I', self._data, offset + 56)[0]
    size_of_headers = struct.unpack_from('<I', self._data, offset + 60)[0]
    checksum = struct.unpack_from('<I', self._data, offset + 64)[0]
    subsystem = struct.unpack_from('<H', self._data, offset + 68)[0]
    num_rva = struct.unpack_from('<I', self._data, offset + 92)[0]

    # Data directories start after PE32 static fields (96 bytes)
    data_dirs_offset = offset + 96
    data_dirs = {}
    for i in range(min(num_rva, 16)):
        dd_offset = data_dirs_offset + i * 8
        if dd_offset + 8 > len(self._data):
            break
        rva, size = struct.unpack_from('<II', self._data, dd_offset)
        data_dirs[i] = DataDirectory(virtual_address=rva, size=size)

    self.optional_header = OptionalHeader(
        magic=magic,
        major_linker_version=maj_link,
        minor_linker_version=min_link,
        size_of_code=size_code,
        entry_point_rva=entry_point,
        base_of_code=base_of_code,
        image_base=image_base,
        section_alignment=section_align,
        file_alignment=file_align,
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
        checksum=checksum,
        subsystem=subsystem,
        number_of_rva_and_sizes=num_rva,
        data_directories=data_dirs,
    )

    # Parse sections
    sections_offset = data_dirs_offset + num_rva * 8
    self._parse_sections(sections_offset, num_sections)

def _parse_sections(self, offset, count):
    self.sections = []
    for i in range(count):
        sec_offset = offset + i * 40
        if sec_offset + 40 > len(self._data):
            raise ValueError(f"Data too short for section header {i}")
        raw_name = struct.unpack_from('<8s', self._data, sec_offset)[0]
        name = raw_name.split(b'\x00', 1)[0].decode('ascii', errors='replace')
        vs, va, rs, rp, _, _, _, _, chars = struct.unpack_from(
            '<IIIIIIIHH', self._data, sec_offset + 8)
        self.sections.append(SectionHeader(
            name=name,
            virtual_size=vs,
            virtual_address=va,
            size_of_raw_data=rs,
            pointer_to_raw_data=rp,
            characteristics=chars,
        ))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_pe.TestSyntheticPE -v`
Expected: PASS (3 tests)

---

### Task 4: Implement RVA to file offset conversion

**Files:**
- Modify: `pydbg/pe.py`
- Modify: `tests/test_pe.py`

- [ ] **Step 1: Write the failing test**

```python
# Add to tests/test_pe.py:

class TestRvaConversion(unittest.TestCase):
    """Tests for RVA to file offset conversion."""

    def test_rva_to_offset(self):
        from pydbg.pe import PE
        data = build_minimal_pe32plus()
        pe = PE(data)
        # .text section: VirtualAddress=0x1000, PointerToRawData=0x400
        # RVA 0x1050 -> file offset 0x450
        offset = pe.rva_to_offset(0x1050)
        self.assertEqual(offset, 0x450)

    def test_rva_outside_sections(self):
        from pydbg.pe import PE
        data = build_minimal_pe32plus()
        pe = PE(data)
        offset = pe.rva_to_offset(0x99999)
        self.assertIsNone(offset)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_pe.TestRvaConversion -v`
Expected: FAIL with `AttributeError: rva_to_offset`

- [ ] **Step 3: Implement rva_to_offset**

Add to `pydbg/pe.py` in the `PE` class:

```python
def rva_to_offset(self, rva):
    """Convert RVA to file offset using section headers.

    Returns file offset (int), or None if RVA is outside all sections.
    """
    for section in self.sections:
        if section.virtual_address <= rva < section.virtual_address + section.virtual_size:
            return rva - section.virtual_address + section.pointer_to_raw_data
    return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_pe.TestRvaConversion -v`
Expected: PASS (2 tests)

---

### Task 5: Implement export directory parsing

**Files:**
- Modify: `pydbg/pe.py`
- Modify: `tests/test_pe.py`

- [ ] **Step 1: Write the failing test**

Add a helper to `build_minimal_pe32plus` that also builds export data, and add test class:

```python
# Add to tests/test_pe.py:

def build_pe_with_exports():
    """Build PE32+ bytes with a synthetic export directory."""
    data = build_minimal_pe32plus()

    # We'll build a complete PE with export directory at file offset corresponding to RVA 0x3000
    # .rdata section: VirtualAddress=0x2000, PointerToRawData=0x1400, VirtualSize=0xA00
    # So RVA 0x3000 -> 0x3000 - 0x2000 + 0x1400 = 0x2400
    # But our file is only 0x4200 bytes, and .rdata ends at 0x1400 + 0xC00 = 0x2000
    # We need to restructure. Let's just build it cleanly.

    # Rebuild with proper layout
    dos_header = struct.pack('<2s58xI', b'MZ', 0x80)
    dos_header += b'\x00' * (0x80 - len(dos_header))
    pe_sig = struct.pack('<I', 0x00004550)
    file_header = struct.pack('<HHIIIHH', 0x8664, 2, 0x5A000000, 0, 0, 0xF0, 0x22)

    # Optional header (PE32+)
    oh = struct.pack('<HBB', 0x20B, 14, 0)
    oh += struct.pack('<III', 0x1000, 0, 0)
    oh += struct.pack('<II', 0x1000, 0x1000)
    oh += struct.pack('<Q', 0x140000000)
    oh += struct.pack('<II', 0x1000, 0x200)
    oh += b'\x00' * 52
    oh += struct.pack('<I', 2)  # 2 data dirs

    # Export dir: RVA=0x3000, Size=0x200
    # Import dir: RVA=0x4000, Size=0x100
    data_dirs = struct.pack('<IIII', 0x3000, 0x200, 0x4000, 0x100)

    # .text: RVA=0x1000, file=0x400, size=0x1000
    text = struct.pack('<8sIIIIIIHHI',
        b'.text\x00\x00\x00', 0xE00, 0x1000, 0x1000, 0x400,
        0, 0, 0, 0, 0x60000020)

    # .rdata: RVA=0x2000, file=0x1400, size=0x3000 (big enough for exports)
    rdata = struct.pack('<8sIIIIIIHHI',
        b'.rdata\x00\x00', 0x3000, 0x2000, 0x3000, 0x1400,
        0, 0, 0, 0, 0x40000040)

    data = dos_header + pe_sig + file_header + oh + data_dirs + text + rdata
    # Pad to 0x4400
    if len(data) < 0x4400:
        data += b'\x00' * (0x4400 - len(data))

    # Now build export directory at file offset 0x2400 (RVA 0x3000)
    # IMAGE_EXPORT_DIRECTORY (40 bytes):
    # Characteristics(4), TimeDateStamp(4), MajorVersion(2), MinorVersion(2),
    # Name(4), Base(4), NumberOfFunctions(4), NumberOfNames(4),
    # AddressOfFunctions(4), AddressOfNames(4), AddressOfNameOrdinals(4)

    export_dir_offset = 0x2400
    # Name string "test.dll" at RVA 0x3100 -> file offset 0x2500
    name_rva = 0x3100
    data = bytearray(data)
    name_str = b'test.dll\x00'
    data[0x2500:0x2500 + len(name_str)] = name_str

    # AddressOfFunctions at RVA 0x3200 -> file offset 0x2600 (1 function)
    # AddressOfNames at RVA 0x3204 -> file offset 0x2604 (1 name)
    # AddressOfNameOrdinals at RVA 0x3208 -> file offset 0x2608 (1 ordinal)
    # Function RVA: 0x1000 (points to .text)
    # Name RVA: 0x3300 -> file offset 0x2700 (function name "MyExport")
    # Ordinal: 0

    func_rva = 0x3200
    names_rva = 0x3204
    ordinals_rva = 0x3208
    func_name_rva = 0x3300

    export_dir = struct.pack('<IIHHIIIIIII',
        0,              # Characteristics
        0,              # TimeDateStamp
        0, 0,           # Version
        name_rva,       # Name
        1,              # Base (ordinal base = 1)
        1,              # NumberOfFunctions
        1,              # NumberOfNames
        func_rva,       # AddressOfFunctions
        names_rva,      # AddressOfNames
        ordinals_rva)   # AddressOfNameOrdinals

    data[export_dir_offset:export_dir_offset + 40] = export_dir

    # Function address table: 1 entry = 0x1000 (RVA of the function)
    struct.pack_into('<I', data, 0x2600, 0x1000)
    # Name pointer table: 1 entry = func_name_rva
    struct.pack_into('<I', data, 0x2604, func_name_rva)
    # Ordinal table: 1 entry = 0
    struct.pack_into('<H', data, 0x2608, 0)
    # Function name: "MyExport\x00"
    func_name = b'MyExport\x00'
    data[0x2700:0x2700 + len(func_name)] = func_name

    return bytes(data)


class TestExportParsing(unittest.TestCase):
    """Tests for export directory parsing."""

    def test_parse_exports(self):
        from pydbg.pe import PE
        data = build_pe_with_exports()
        pe = PE(data)
        self.assertEqual(len(pe.exports), 1)
        self.assertEqual(pe.exports[0].name, 'MyExport')
        self.assertEqual(pe.exports[0].ordinal, 0)
        self.assertEqual(pe.exports[0].rva, 0x1000)
        self.assertIsNone(pe.exports[0].forwarder)

    def test_no_exports(self):
        from pydbg.pe import PE
        data = build_minimal_pe32plus()
        pe = PE(data)
        self.assertEqual(pe.exports, [])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_pe.TestExportParsing -v`
Expected: FAIL (exports list is empty)

- [ ] **Step 3: Implement _parse_exports**

Add to `pydbg/pe.py` in the `PE` class, call it from `_parse`:

```python
def _parse(self):
    self._parse_dos_header()
    self._parse_nt_headers()
    self._parse_exports()
    self._parse_imports()

def _read_string_at_offset(self, offset):
    """Read a null-terminated ASCII string from _data at the given offset."""
    end = self._data.find(b'\x00', offset)
    if end == -1:
        end = len(self._data)
    return self._data[offset:end].decode('ascii', errors='replace')

def _parse_exports(self):
    self.exports = []
    if 0 not in self.optional_header.data_directories:
        return
    dd = self.optional_header.data_directories[0]
    if dd.virtual_address == 0 or dd.size == 0:
        return

    offset = self.rva_to_offset(dd.virtual_address)
    if offset is None or offset + 40 > len(self._data):
        return

    fields = struct.unpack_from('<IIHHIIIIIII', self._data, offset)
    # fields: Characteristics, TimeDateStamp, MajorVersion, MinorVersion,
    #         Name, Base, NumberOfFunctions, NumberOfNames,
    #         AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals
    base = fields[5]
    num_funcs = fields[6]
    num_names = fields[7]
    func_table_rva = fields[8]
    name_table_rva = fields[9]
    ordinal_table_rva = fields[10]

    # Read function addresses
    func_offsets = []
    func_table_offset = self.rva_to_offset(func_table_rva)
    if func_table_offset is None:
        return
    for i in range(num_funcs):
        off = func_table_offset + i * 4
        if off + 4 > len(self._data):
            break
        func_offsets.append(struct.unpack_from('<I', self._data, off)[0])

    # Read name-to-ordinal mapping
    name_to_ordinal = {}
    name_table_offset = self.rva_to_offset(name_table_rva)
    ordinal_table_offset = self.rva_to_offset(ordinal_table_rva)
    if name_table_offset is not None and ordinal_table_offset is not None:
        for i in range(num_names):
            name_off = name_table_offset + i * 4
            ord_off = ordinal_table_offset + i * 2
            if name_off + 4 > len(self._data) or ord_off + 2 > len(self._data):
                break
            name_rva = struct.unpack_from('<I', self._data, name_off)[0]
            ordinal = struct.unpack_from('<H', self._data, ord_off)[0]
            name_offset = self.rva_to_offset(name_rva)
            if name_offset is not None:
                name = self._read_string_at_offset(name_offset)
                name_to_ordinal[ordinal] = name

    # Determine export directory range for forwarder detection
    export_dir_rva = dd.virtual_address
    export_dir_end = export_dir_rva + dd.size

    # Build export entries
    for i in range(len(func_offsets)):
        func_rva = func_offsets[i]
        name = name_to_ordinal.get(i)
        forwarder = None
        if export_dir_rva <= func_rva < export_dir_end:
            # Forwarder: RVA points to a string inside the export directory
            fwd_offset = self.rva_to_offset(func_rva)
            if fwd_offset is not None:
                forwarder = self._read_string_at_offset(fwd_offset)
        self.exports.append(ExportEntry(
            name=name,
            ordinal=i + base,
            rva=func_rva,
            forwarder=forwarder,
        ))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_pe.TestExportParsing -v`
Expected: PASS (2 tests)

---

### Task 6: Implement import directory parsing

**Files:**
- Modify: `pydbg/pe.py`
- Modify: `tests/test_pe.py`

- [ ] **Step 1: Write the failing test**

```python
# Add to tests/test_pe.py:

def build_pe_with_imports():
    """Build PE32+ bytes with a synthetic import directory."""
    data = build_minimal_pe32plus()

    dos_header = struct.pack('<2s58xI', b'MZ', 0x80)
    dos_header += b'\x00' * (0x80 - len(dos_header))
    pe_sig = struct.pack('<I', 0x00004550)
    file_header = struct.pack('<HHIIIHH', 0x8664, 2, 0x5A000000, 0, 0, 0xF0, 0x22)

    oh = struct.pack('<HBB', 0x20B, 14, 0)
    oh += struct.pack('<III', 0x1000, 0, 0)
    oh += struct.pack('<II', 0x1000, 0x1000)
    oh += struct.pack('<Q', 0x140000000)
    oh += struct.pack('<II', 0x1000, 0x200)
    oh += b'\x00' * 52
    oh += struct.pack('<I', 2)

    # Export: RVA=0, Size=0 (none)
    # Import: RVA=0x5000, Size=0x200
    data_dirs = struct.pack('<IIII', 0, 0, 0x5000, 0x200)

    text = struct.pack('<8sIIIIIIHHI',
        b'.text\x00\x00\x00', 0xE00, 0x1000, 0x1000, 0x400,
        0, 0, 0, 0, 0x60000020)
    rdata = struct.pack('<8sIIIIIIHHI',
        b'.rdata\x00\x00', 0x5000, 0x2000, 0x5000, 0x1400,
        0, 0, 0, 0, 0x40000040)

    data = dos_header + pe_sig + file_header + oh + data_dirs + text + rdata
    if len(data) < 0x6400:
        data += b'\x00' * (0x6400 - len(data))

    # Import directory at RVA 0x5000 -> file offset 0x1400 + (0x5000 - 0x2000) = 0x4400
    # But .rdata raw data starts at 0x1400 and covers RVA 0x2000 to 0x7000
    # So RVA 0x5000 -> file offset 0x1400 + 0x3000 = 0x4400
    import_dir_offset = 0x4400

    data = bytearray(data)

    # ILT at RVA 0x5100 -> file offset 0x4500 (1 entry: points to import by name)
    # Import by name at RVA 0x5200 -> file offset 0x4600 (hint=1, name="MessageBoxA")
    # DLL name at RVA 0x5300 -> file offset 0x4700 ("user32.dll\x00")
    # IAT at RVA 0x5400 -> file offset 0x4800

    ilt_rva = 0x5100
    import_by_name_rva = 0x5200
    dll_name_rva = 0x5300
    iat_rva = 0x5400

    # IMAGE_IMPORT_DESCRIPTOR (20 bytes):
    # OriginalFirstThunk(4), TimeDateStamp(4), ForwarderChain(4), Name(4), FirstThunk(4)
    import_desc = struct.pack('<IIIII',
        ilt_rva,      # OriginalFirstThunk (ILT)
        0,            # TimeDateStamp
        0,            # ForwarderChain
        dll_name_rva, # Name
        iat_rva)      # FirstThunk (IAT)
    data[import_dir_offset:import_dir_offset + 20] = import_desc
    # Null terminator (next 20 bytes are already zero)

    # ILT: 1 entry pointing to import by name RVA, then null
    struct.pack_into('<Q', data, 0x4500, import_by_name_rva)

    # IMAGE_IMPORT_BY_NAME: Hint(2) + Name string
    struct.pack_into('<H', data, 0x4600, 1)  # hint = 1
    func_name = b'MessageBoxA\x00'
    data[0x4602:0x4602 + len(func_name)] = func_name

    # DLL name
    dll_name = b'user32.dll\x00'
    data[0x4700:0x4700 + len(dll_name)] = dll_name

    return bytes(data)


class TestImportParsing(unittest.TestCase):
    """Tests for import directory parsing."""

    def test_parse_imports(self):
        from pydbg.pe import PE
        data = build_pe_with_imports()
        pe = PE(data)
        self.assertEqual(len(pe.imports), 1)
        self.assertEqual(pe.imports[0].dll_name, 'user32.dll')
        self.assertEqual(pe.imports[0].name, 'MessageBoxA')
        self.assertIsNone(pe.imports[0].ordinal)
        self.assertEqual(pe.imports[0].rva, 0x5400)

    def test_no_imports(self):
        from pydbg.pe import PE
        data = build_minimal_pe32plus()
        pe = PE(data)
        self.assertEqual(pe.imports, [])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_pe.TestImportParsing -v`
Expected: FAIL (imports list is empty)

- [ ] **Step 3: Implement _parse_imports**

Add to `pydbg/pe.py`:

```python
def _parse_imports(self):
    self.imports = []
    if 1 not in self.optional_header.data_directories:
        return
    dd = self.optional_header.data_directories[1]
    if dd.virtual_address == 0 or dd.size == 0:
        return

    offset = self.rva_to_offset(dd.virtual_address)
    if offset is None:
        return

    # Read IMAGE_IMPORT_DESCRIPTOR entries (20 bytes each, null-terminated)
    while offset + 20 <= len(self._data):
        ilt_rva, _, _, name_rva, iat_rva = struct.unpack_from(
            '<IIIII', self._data, offset)
        if ilt_rva == 0 and name_rva == 0 and iat_rva == 0:
            break  # null terminator

        # Read DLL name
        name_offset = self.rva_to_offset(name_rva)
        dll_name = ''
        if name_offset is not None:
            dll_name = self._read_string_at_offset(name_offset)

        # Read ILT entries (thunks)
        thunk_rva = ilt_rva  # OriginalFirstThunk
        if thunk_rva == 0:
            thunk_rva = iat_rva  # fallback to FirstThunk

        thunk_offset = self.rva_to_offset(thunk_rva)
        if thunk_offset is not None:
            is_pe32plus = self.optional_header.magic == 0x20B
            thunk_size = 8 if is_pe32plus else 4
            ordinal_flag = 0x8000000000000000 if is_pe32plus else 0x80000000

            while thunk_offset + thunk_size <= len(self._data):
                if is_pe32plus:
                    thunk = struct.unpack_from('<Q', self._data, thunk_offset)[0]
                else:
                    thunk = struct.unpack_from('<I', self._data, thunk_offset)[0]

                if thunk == 0:
                    break

                if thunk & ordinal_flag:
                    # Import by ordinal
                    ordinal = thunk & 0xFFFF
                    self.imports.append(ImportEntry(
                        dll_name=dll_name,
                        name=None,
                        ordinal=ordinal,
                        rva=iat_rva + (thunk_offset - self.rva_to_offset(thunk_rva)),
                    ))
                else:
                    # Import by name: thunk is RVA to IMAGE_IMPORT_BY_NAME
                    ibn_offset = self.rva_to_offset(thunk)
                    func_name = None
                    if ibn_offset is not None and ibn_offset + 2 < len(self._data):
                        func_name = self._read_string_at_offset(ibn_offset + 2)
                    thunk_index = (thunk_offset - self.rva_to_offset(thunk_rva)) // thunk_size
                    self.imports.append(ImportEntry(
                        dll_name=dll_name,
                        name=func_name,
                        ordinal=None,
                        rva=iat_rva + thunk_index * thunk_size,
                    ))

                thunk_offset += thunk_size

        offset += 20
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_pe.TestImportParsing -v`
Expected: PASS (2 tests)

---

### Task 7: Implement PE32 (32-bit) support and validation tests

**Files:**
- Modify: `tests/test_pe.py`

- [ ] **Step 1: Write the failing tests for validation**

```python
# Add to tests/test_pe.py:

class TestValidation(unittest.TestCase):
    """Tests for PE parser error handling."""

    def test_invalid_dos_signature(self):
        from pydbg.pe import PE
        data = b'XX' + b'\x00' * 100
        with self.assertRaises(ValueError) as cm:
            PE(data)
        self.assertIn("DOS signature", str(cm.exception))

    def test_invalid_pe_signature(self):
        from pydbg.pe import PE
        data = struct.pack('<2s58xI', b'MZ', 0x40)
        data += b'\x00' * (0x44 - len(data))
        data += b'BADS'  # bad PE sig
        data += b'\x00' * 100
        with self.assertRaises(ValueError) as cm:
            PE(data)
        self.assertIn("PE signature", str(cm.exception))

    def test_truncated_data(self):
        from pydbg.pe import PE
        data = b'MZ' + b'\x00' * 10
        with self.assertRaises(ValueError):
            PE(data)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_pe.TestValidation -v`
Expected: May fail depending on current implementation of validation

- [ ] **Step 3: Ensure _parse_dos_header validates properly**

Verify that `_parse_dos_header` raises `ValueError` with "DOS signature" in the message. Verify `_parse_nt_headers` raises `ValueError` with "PE signature". The current implementation already does this — run tests to confirm.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest tests.test_pe.TestValidation -v`
Expected: PASS (3 tests)

---

### Task 8: Add convenience methods and full test suite run

**Files:**
- Modify: `pydbg/pe.py`
- Modify: `tests/test_pe.py`

- [ ] **Step 1: Add from_file static method**

Add to `pydbg/pe.py` in the `PE` class:

```python
@staticmethod
def from_file(path):
    """Parse PE from a file on disk.

    Args:
        path: Path to PE file.

    Returns:
        PE object.
    """
    with open(path, 'rb') as f:
        return PE(f.read())
```

- [ ] **Step 2: Write the integration test for real DLL**

```python
# Add to tests/test_pe.py:

class TestRealDLL(unittest.TestCase):
    """Integration tests with real DLL files."""

    def test_parse_kernel32(self):
        """Parse kernel32.dll from System32."""
        import os
        from pydbg.pe import PE

        path = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'),
                            'System32', 'kernel32.dll')
        if not os.path.exists(path):
            self.skipTest("kernel32.dll not found")

        pe = PE.from_file(path)
        self.assertEqual(pe.dos_header.e_magic, 0x5A4D)
        self.assertIn(pe.file_header.machine, (0x14C, 0x8664))
        self.assertIn(pe.optional_header.magic, (0x10B, 0x20B))
        self.assertGreater(len(pe.sections), 0)
        # kernel32.dll definitely has exports
        self.assertGreater(len(pe.exports), 0)
        # Check some well-known exports exist
        export_names = [e.name for e in pe.exports if e.name is not None]
        self.assertIn('GetProcAddress', export_names)
        self.assertIn('LoadLibraryA', export_names)
```

- [ ] **Step 3: Run full test suite**

Run: `python -m unittest tests.test_pe -v`
Expected: ALL PASS

---

### Task 9: Export PE types from `__init__.py`

**Files:**
- Modify: `pydbg/__init__.py`

- [ ] **Step 1: Add PE imports to `__init__.py`**

```python
from .pe import PE, DosHeader, FileHeader, OptionalHeader, SectionHeader, ExportEntry, ImportEntry, DataDirectory
```

Add `PE`, `DosHeader`, `FileHeader`, `OptionalHeader`, `SectionHeader`, `ExportEntry`, `ImportEntry`, `DataDirectory` to the `__all__` list.

- [ ] **Step 2: Verify import works**

Run: `python -c "from pydbg import PE, DosHeader, FileHeader, OptionalHeader, SectionHeader, ExportEntry, ImportEntry, DataDirectory; print('OK')"`
Expected: OK

---

### Task 10: Integrate LOAD_DLL event with Cython layer

**Files:**
- Modify: `pydbg/cython/_win32types.pxd`
- Modify: `pydbg/cython/_process.pyx`
- Modify: `pydbg/debugger.py`

- [ ] **Step 1: Add Win32 declarations to `_win32types.pxd`**

Add to the existing `cdef extern from "windows.h":` block:

```c
    DWORD GetFileSize(HANDLE hFile, DWORD* lpFileSizeHigh)
    BOOL ReadFile(HANDLE hFile, void* lpBuffer, DWORD nNumberOfBytesToRead,
                  DWORD* lpNumberOfBytesRead, void* lpOverlapped)
```

- [ ] **Step 2: Modify `_process.pyx` to read hFile during LOAD_DLL**

Replace the LOAD_DLL handling in `wait_for_debug_event`:

```python
elif code == LOAD_DLL_DEBUG_EVENT:
    event['dll_base'] = <unsigned long long>de.u.LoadDll.lpBaseOfDll

    # Read DLL file data from hFile
    cdef HANDLE h_dll_file = de.u.LoadDll.hFile
    if h_dll_file != NULL:
        cdef DWORD file_size = GetFileSize(h_dll_file, NULL)
        if file_size != 0xFFFFFFFF and file_size > 0 and file_size < 100 * 1024 * 1024:
            # Limit to 100MB to avoid OOM
            cdef char* buf = <char*>malloc(file_size)
            if buf != NULL:
                cdef DWORD bytes_read = 0
                cdef BOOL read_result = ReadFile(
                    h_dll_file, buf, file_size, &bytes_read, NULL)
                if read_result != 0 and bytes_read > 0:
                    event['dll_data'] = (<char*>buf)[:bytes_read]
                free(buf)
```

Also add `malloc` and `free` imports at the top of `_process.pyx`:

```python
from libc.stdlib cimport malloc, free
```

And add `GetFileSize`, `ReadFile` to the `_win32types` import list.

- [ ] **Step 3: Add `dll_base` and `dll_data` to `DebugEvent`**

Modify `DebugEvent.__slots__` in `debugger.py`:

```python
__slots__ = ('type', 'pid', 'tid', 'exception_code', 'exception_addr',
             'first_chance', 'exception_name', 'exception_info', 'raw',
             'dll_base', 'dll_data')
```

Add to `__init__`:

```python
self.dll_base = event_dict.get('dll_base')
self.dll_data = event_dict.get('dll_data')
```

- [ ] **Step 4: Add `parse_loaded_dll` method to `Debugger`**

```python
def parse_loaded_dll(self, event):
    """Parse PE from a LOAD_DLL event's dll_data.

    Args:
        event: DebugEvent with dll_data attribute.

    Returns:
        PE object, or None if no dll_data available.
    """
    if event.dll_data is None:
        return None
    from .pe import PE
    return PE(event.dll_data)
```

- [ ] **Step 5: Verify compilation**

Run: `meson compile -C build`
Expected: SUCCESS (no Cython compilation errors)

---

### Task 11: Register pe test in meson.build

**Files:**
- Modify: `tests/meson.build`

- [ ] **Step 1: Add pe test to meson.build**

Add to `tests/meson.build`:

```
test(
  'pe',
  py,
  args: ['-m', 'unittest', 'tests.test_pe'],
  env: test_env,
  workdir: meson.project_build_root(),
)
```

- [ ] **Step 2: Run pe tests via meson**

Run: `meson test pe -C build -v`
Expected: ALL PASS

---

### Task 12: Final commit

- [ ] **Step 1: Run all tests**

Run: `meson test -C build -v`
Expected: ALL PASS (process, memory, thread, breakpoint, pe)

- [ ] **Step 2: Commit**

```bash
git add pydbg/pe.py pydbg/__init__.py pydbg/debugger.py pydbg/cython/_process.pyx pydbg/cython/_win32types.pxd tests/test_pe.py tests/meson.build
git commit -m "feat: add PE format parser with LOAD_DLL integration"
```

---

## Self-Review

**1. Spec coverage:**
- Pure-Python PE parser from bytes: Tasks 1-8
- DOS header, NT headers, section headers: Tasks 2-3
- Export directory parsing: Task 5
- Import directory parsing: Task 6
- RVA to file offset: Task 4
- LOAD_DLL integration (Cython reads hFile): Task 10
- DebugEvent.dll_base/dll_data: Task 10
- Convenience methods (from_file): Task 8
- Exports from __init__.py: Task 9
- Test coverage: Tasks 2-8, 11
- No external dependencies: confirmed, only `struct` and `dataclasses`

**2. Placeholder scan:** No TBD/TODO found. All code is complete.

**3. Type consistency:**
- `PE.rva_to_offset` returns `int | None` — consistent across Tasks 4, 5, 6
- `ExportEntry.name` is `str | None` — consistent
- `ImportEntry.name` is `str | None`, `ordinal` is `int | None` — consistent
- `OptionalHeader.data_directories` is `dict` — consistent

**Plan complete.** Two execution options:

1. **Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration
2. **Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints

Which approach?
