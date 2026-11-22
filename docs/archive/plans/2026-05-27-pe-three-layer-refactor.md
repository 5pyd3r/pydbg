# PE Three-Layer Architecture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor `pe.py` into three-layer architecture (Source/View/Parse) supporting multiple byte sources and PE states, while keeping public API backward compatible.

**Architecture:** Source provides `read(offset, size)` random byte access. View provides `rva_to_source_offset(rva)` address translation strategy. Parse consumes Source+View to produce structured PE dataclass output. PE class remains the public facade.

**Tech Stack:** Python 3.12+, dataclasses, struct, abc (abstract base classes)

---

### Task 1: Create pe/ package and move dataclasses to types.py

**Files:**
- Create: `src/pydbg/pe/__init__.py`
- Create: `src/pydbg/pe/types.py`
- Modify: `src/pydbg/pe.py`

- [ ] **Step 1: Create pe/ package directory**

```bash
mkdir -p src/pydbg/pe
touch src/pydbg/pe/__init__.py
```

- [ ] **Step 2: Write pe/types.py with all dataclasses from pe.py**

```python
"""PE format dataclass types."""

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

- [ ] **Step 3: Update pe.py to import dataclasses from pe.types**

Replace the dataclass definitions (lines 10-72) in `pe.py` with:

```python
from .pe.types import (
    DosHeader, FileHeader, OptionalHeader, DataDirectory,
    SectionHeader, ExportEntry, ImportEntry,
)
```

- [ ] **Step 4: Verify imports**

```bash
cd src && python3 -c "from pydbg.pe.types import DosHeader, FileHeader, SectionHeader; print('OK')"
```

Expected: `OK`

- [ ] **Step 5: Commit**

```bash
git add src/pydbg/pe/ src/pydbg/pe.py
git commit -m "refactor: move PE dataclasses to pe/types.py"
```

---

### Task 2: Create Source layer (source.py)

**Files:**
- Create: `src/pydbg/pe/source.py`

- [ ] **Step 1: Write source.py with Source ABC and FileSource**

```python
"""Source layer — random-access byte providers."""

from abc import ABC, abstractmethod


class Source(ABC):
    """Abstract byte source with random access."""

    @abstractmethod
    def read(self, offset: int, size: int) -> bytes:
        """Read bytes at given offset."""


class FileSource(Source):
    """Read PE bytes from a file on disk."""

    def __init__(self, path: str):
        self._path = path
        self._file = open(path, 'rb')

    def read(self, offset: int, size: int) -> bytes:
        self._file.seek(offset)
        return self._file.read(size)

    def close(self):
        self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class BytesSource(Source):
    """Read PE bytes from an in-memory buffer."""

    def __init__(self, data: bytes):
        self._data = data

    def read(self, offset: int, size: int) -> bytes:
        if offset + size > len(self._data):
            raise ValueError(
                f"Read out of bounds: offset={offset}, size={size}, len={len(self._data)}")
        return self._data[offset:offset + size]
```

- [ ] **Step 2: Verify**

```bash
cd src && python3 -c "
from pydbg.pe.source import FileSource, BytesSource
bs = BytesSource(b'MZ\x00\x00')
assert bs.read(0, 2) == b'MZ'
print('OK')
"
```

- [ ] **Step 3: Commit**

```bash
git add src/pydbg/pe/source.py
git commit -m "feat: add Source layer with FileSource and BytesSource"
```

---

### Task 3: Create View layer (view.py)

**Files:**
- Create: `src/pydbg/pe/view.py`

- [ ] **Step 1: Write view.py with View ABC, FileView, LoadedView**

```python
"""View layer — address translation strategies."""

from abc import ABC, abstractmethod


class View(ABC):
    """Abstract address translation strategy."""

    @abstractmethod
    def rva_to_source_offset(self, rva: int) -> int | None:
        """Convert PE-relative RVA to Source offset."""


class FileView(View):
    """File-state view: RVA -> file offset via section headers."""

    def __init__(self, sections):
        self._sections = sections

    def rva_to_source_offset(self, rva: int) -> int | None:
        for section in self._sections:
            if section.virtual_address <= rva < section.virtual_address + section.virtual_size:
                return rva - section.virtual_address + section.pointer_to_raw_data
        return None


class LoadedView(View):
    """Loaded-state view: RVA is the source offset (Source already at module base)."""

    def rva_to_source_offset(self, rva: int) -> int | None:
        return rva
```

- [ ] **Step 2: Verify**

```bash
cd src && python3 -c "
from pydbg.pe.types import SectionHeader
from pydbg.pe.view import FileView, LoadedView

sec = SectionHeader(name='.text', virtual_size=0x1000, virtual_address=0x1000,
                    size_of_raw_data=0x1000, pointer_to_raw_data=0x400,
                    characteristics=0x20)
fv = FileView([sec])
assert fv.rva_to_source_offset(0x1050) == 0x450
assert fv.rva_to_source_offset(0x9999) is None

lv = LoadedView()
assert lv.rva_to_source_offset(0x1050) == 0x1050
print('OK')
"
```

- [ ] **Step 3: Commit**

```bash
git add src/pydbg/pe/view.py
git commit -m "feat: add View layer with FileView and LoadedView"
```

---

### Task 4: Create Parse layer (parser.py)

**Files:**
- Create: `src/pydbg/pe/parser.py`

Move all parsing logic from `pe.py`'s PE class methods into a PEParser class. The `rva_to_offset` logic moves to `FileView`. PEParser uses Source for byte reads and View for address translation.

- [ ] **Step 1: Write parser.py**

```python
"""Parse layer — PE binary structure parser."""

import struct

from .types import (
    DosHeader, FileHeader, OptionalHeader, DataDirectory,
    SectionHeader, ExportEntry, ImportEntry,
)
from .view import View


class PEParser:
    """Parse PE binary structures from a byte source."""

    def __init__(self, source, view: View):
        self._src = source
        self._view = view

    def parse_dos_header(self) -> DosHeader:
        magic = struct.unpack_from('<2s', self._src.read(0, 64), 0)[0]
        if magic != b'MZ':
            raise ValueError(f"Invalid DOS signature: {magic!r}")
        e_lfanew = struct.unpack_from('<I', self._src.read(0, 64), 0x3C)[0]
        return DosHeader(e_magic=0x5A4D, e_lfanew=e_lfanew)

    def parse_nt_headers(self, e_lfanew: int) -> tuple[FileHeader, OptionalHeader]:
        sig = struct.unpack_from('<I', self._src.read(e_lfanew, 4), 0)[0]
        if sig != 0x00004550:
            raise ValueError(f"Invalid PE signature: 0x{sig:08X}")

        offset = e_lfanew + 4
        data = self._src.read(offset, 20)
        machine, num_sections, ts, _, _, opt_hdr_size, chars = struct.unpack_from(
            '<HHIIIHH', data, 0)
        file_hdr = FileHeader(
            machine=machine, time_date_stamp=ts,
            number_of_sections=num_sections, characteristics=chars)

        offset += 20
        magic_data = self._src.read(offset, 2)
        magic = struct.unpack_from('<H', magic_data, 0)[0]

        if magic == 0x20B:
            opt_hdr = self._parse_optional_64(offset, num_sections)
        elif magic == 0x10B:
            opt_hdr = self._parse_optional_32(offset, num_sections)
        else:
            raise ValueError(f"Unknown optional header magic: 0x{magic:04X}")

        return file_hdr, opt_hdr

    def _parse_optional_64(self, offset, num_sections):
        fields_data = self._src.read(offset, 112)
        fields = struct.unpack_from('<HBBIIIIIQIIIIHHHHHHIIII', fields_data, 0)
        num_rva = struct.unpack_from('<I', fields_data, 92)[0]

        data_dirs = self._parse_data_directories(offset + 112, num_rva)

        opt_hdr = OptionalHeader(
            magic=fields[0], major_linker_version=fields[1],
            minor_linker_version=fields[2], size_of_code=fields[3],
            entry_point_rva=fields[6], base_of_code=fields[7],
            image_base=fields[8], section_alignment=fields[9],
            file_alignment=fields[10],
            size_of_image=struct.unpack_from('<I', fields_data, 56)[0],
            size_of_headers=struct.unpack_from('<I', fields_data, 60)[0],
            checksum=struct.unpack_from('<I', fields_data, 64)[0],
            subsystem=struct.unpack_from('<H', fields_data, 68)[0],
            number_of_rva_and_sizes=num_rva, data_directories=data_dirs)

        return opt_hdr

    def _parse_optional_32(self, offset, num_sections):
        fields_data = self._src.read(offset, 96)
        fields = struct.unpack_from(
            '<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII', fields_data, 0)
        num_rva = struct.unpack_from('<I', fields_data, 92)[0]

        data_dirs = self._parse_data_directories(offset + 96, num_rva)

        opt_hdr = OptionalHeader(
            magic=fields[0], major_linker_version=fields[1],
            minor_linker_version=fields[2], size_of_code=fields[3],
            entry_point_rva=fields[6], base_of_code=fields[7],
            image_base=fields[9], section_alignment=fields[10],
            file_alignment=fields[11],
            size_of_image=struct.unpack_from('<I', fields_data, 56)[0],
            size_of_headers=struct.unpack_from('<I', fields_data, 60)[0],
            checksum=struct.unpack_from('<I', fields_data, 64)[0],
            subsystem=struct.unpack_from('<H', fields_data, 68)[0],
            number_of_rva_and_sizes=num_rva, data_directories=data_dirs)

        return opt_hdr

    def _parse_data_directories(self, offset: int, count: int) -> dict:
        data_dirs = {}
        for i in range(min(count, 16)):
            dd_offset = offset + i * 8
            dd_data = self._src.read(dd_offset, 8)
            rva, size = struct.unpack_from('<II', dd_data, 0)
            data_dirs[i] = DataDirectory(virtual_address=rva, size=size)
        return data_dirs

    def parse_sections(self, offset: int, count: int) -> list[SectionHeader]:
        sections = []
        for i in range(count):
            sec_offset = offset + i * 40
            sec_data = self._src.read(sec_offset, 40)
            raw_name = struct.unpack_from('<8s', sec_data, 0)[0]
            name = raw_name.split(b'\x00', 1)[0].decode('ascii', errors='replace')
            vs, va, rs, rp, _, _, _, _, chars = struct.unpack_from(
                '<IIIIIIIHH', sec_data, 8)
            sections.append(SectionHeader(
                name=name, virtual_size=vs, virtual_address=va,
                size_of_raw_data=rs, pointer_to_raw_data=rp,
                characteristics=chars))
        return sections

    def parse_exports(self, data_dirs: dict) -> list[ExportEntry]:
        exports = []
        if 0 not in data_dirs:
            return exports
        dd = data_dirs[0]
        if dd.virtual_address == 0 or dd.size == 0:
            return exports

        offset = self._view.rva_to_source_offset(dd.virtual_address)
        if offset is None:
            return exports

        export_data = self._src.read(offset, 40)
        fields = struct.unpack_from('<IIHHIIIIIII', export_data, 0)
        base = fields[5]
        num_funcs = fields[6]
        num_names = fields[7]
        func_table_rva = fields[8]
        name_table_rva = fields[9]
        ordinal_table_rva = fields[10]

        func_offsets = self._read_rva_table(func_table_rva, num_funcs, 4, '<I')
        name_to_ordinal = self._read_name_ordinal_map(
            name_table_rva, ordinal_table_rva, num_names)

        export_dir_end = dd.virtual_address + dd.size
        for i in range(len(func_offsets)):
            func_rva = func_offsets[i]
            name = name_to_ordinal.get(i)
            forwarder = None
            if dd.virtual_address <= func_rva < export_dir_end:
                fwd_offset = self._view.rva_to_source_offset(func_rva)
                if fwd_offset is not None:
                    forwarder = self._read_string_at_offset(fwd_offset)
            exports.append(ExportEntry(
                name=name, ordinal=i + base,
                rva=func_rva, forwarder=forwarder))
        return exports

    def parse_imports(self, data_dirs: dict, magic: int) -> list[ImportEntry]:
        imports = []
        if 1 not in data_dirs:
            return imports
        dd = data_dirs[1]
        if dd.virtual_address == 0 or dd.size == 0:
            return imports

        offset = self._view.rva_to_source_offset(dd.virtual_address)
        if offset is None:
            return imports

        is_pe32plus = magic == 0x20B
        thunk_size = 8 if is_pe32plus else 4
        ordinal_flag = 0x8000000000000000 if is_pe32plus else 0x80000000
        thunk_fmt = '<Q' if is_pe32plus else '<I'

        cursor = offset
        while True:
            desc_data = self._src.read(cursor, 20)
            ilt_rva, _, _, name_rva, iat_rva = struct.unpack_from(
                '<IIIII', desc_data, 0)
            if ilt_rva == 0 and name_rva == 0 and iat_rva == 0:
                break

            dll_name = ''
            name_offset = self._view.rva_to_source_offset(name_rva)
            if name_offset is not None:
                dll_name = self._read_string_at_offset(name_offset)

            thunk_rva = ilt_rva if ilt_rva != 0 else iat_rva
            thunk_offset = self._view.rva_to_source_offset(thunk_rva)
            if thunk_offset is not None:
                t_index = 0
                while True:
                    t_data = self._src.read(thunk_offset, thunk_size)
                    thunk = struct.unpack_from(thunk_fmt, t_data, 0)[0]
                    if thunk == 0:
                        break
                    if thunk & ordinal_flag:
                        imports.append(ImportEntry(
                            dll_name=dll_name, name=None,
                            ordinal=thunk & 0xFFFF,
                            rva=iat_rva + t_index * thunk_size))
                    else:
                        ibn_offset = self._view.rva_to_source_offset(thunk)
                        func_name = None
                        if ibn_offset is not None:
                            func_name = self._read_string_at_offset(ibn_offset + 2)
                        imports.append(ImportEntry(
                            dll_name=dll_name, name=func_name,
                            ordinal=None,
                            rva=iat_rva + t_index * thunk_size))
                    thunk_offset += thunk_size
                    t_index += 1
            cursor += 20
        return imports

    def _read_rva_table(self, table_rva: int, count: int,
                        entry_size: int, fmt: str) -> list[int]:
        result = []
        table_offset = self._view.rva_to_source_offset(table_rva)
        if table_offset is None:
            return result
        for i in range(count):
            data = self._src.read(table_offset + i * entry_size, entry_size)
            result.append(struct.unpack_from(fmt, data, 0)[0])
        return result

    def _read_name_ordinal_map(self, name_table_rva: int,
                                ordinal_table_rva: int,
                                num_names: int) -> dict:
        mapping = {}
        name_off = self._view.rva_to_source_offset(name_table_rva)
        ord_off = self._view.rva_to_source_offset(ordinal_table_rva)
        if name_off is None or ord_off is None:
            return mapping
        for i in range(num_names):
            n_data = self._src.read(name_off + i * 4, 4)
            name_rva = struct.unpack_from('<I', n_data, 0)[0]
            o_data = self._src.read(ord_off + i * 2, 2)
            ordinal = struct.unpack_from('<H', o_data, 0)[0]
            str_off = self._view.rva_to_source_offset(name_rva)
            if str_off is not None:
                name = self._read_string_at_offset(str_off)
                mapping[ordinal] = name
        return mapping

    def _read_string_at_offset(self, offset: int) -> str:
        max_read = 256
        data = self._src.read(offset, max_read)
        end = data.find(b'\x00')
        if end == -1:
            end = len(data)
        return data[:end].decode('ascii', errors='replace')
```

- [ ] **Step 2: Verify syntax**

```bash
cd src && python3 -m py_compile pydbg/pe/parser.py && echo "Syntax OK"
```

- [ ] **Step 3: Commit**

```bash
git add src/pydbg/pe/parser.py
git commit -m "feat: add PEParser with Source+View-based parsing"
```

---

### Task 5: Refactor PE class as facade, update __init__.py

**Files:**
- Modify: `src/pydbg/pe.py` (replace PE class with facade)
- Modify: `src/pydbg/pe/__init__.py` (re-exports)

- [ ] **Step 1: Rewrite pe.py PE class**

Replace the PE class in `pe.py` (lines 75-408) with a facade that delegates to PEParser:

```python
class PE:
    """PE format parser facade. Delegates to PEParser with Source+View."""

    def __init__(self, data: bytes):
        """Parse PE from raw bytes (backward-compatible)."""
        from .pe.source import BytesSource
        from .pe.view import FileView
        from .pe.parser import PEParser

        self._source = BytesSource(data)
        self._parser = PEParser(self._source, None)  # view built after sections

        self._data = data  # kept for backward compat in tests
        self.dos_header = self._parser.parse_dos_header()
        e_lfanew = self.dos_header.e_lfanew
        self.file_header, self.optional_header = self._parser.parse_nt_headers(e_lfanew)

        # Compute section offset and parse sections
        data_dirs = self.optional_header.data_directories
        num_rva = self.optional_header.number_of_rva_and_sizes
        offset = e_lfanew + 4 + 20  # after signature + file header
        magic = self.optional_header.magic
        opt_hdr_size = 112 if magic == 0x20B else 96
        sections_offset = offset + opt_hdr_size + num_rva * 8

        self._view = FileView([])
        self.sections = self._parser.parse_sections(sections_offset, self.file_header.number_of_sections)
        self._view = FileView(self.sections)

        # Re-create parser with correct view for export/import parsing
        self._parser = PEParser(self._source, self._view)
        self.exports = self._parser.parse_exports(data_dirs)
        self.imports = self._parser.parse_imports(data_dirs, magic)

    def rva_to_offset(self, rva):
        """Convert RVA to file offset (delegated to FileView)."""
        return self._view.rva_to_source_offset(rva)

    @staticmethod
    def from_file(path):
        """Parse PE from a file on disk."""
        from .pe.source import FileSource
        from .pe.view import FileView
        from .pe.parser import PEParser

        source = FileSource(path)
        parser = PEParser(source, None)

        dos = parser.parse_dos_header()
        file_hdr, opt_hdr = parser.parse_nt_headers(dos.e_lfanew)

        data_dirs = opt_hdr.data_directories
        num_rva = opt_hdr.number_of_rva_and_sizes
        offset = dos.e_lfanew + 4 + 20
        magic = opt_hdr.magic
        opt_hdr_size = 112 if magic == 0x20B else 96
        sections_offset = offset + opt_hdr_size + num_rva * 8

        sections = parser.parse_sections(sections_offset, file_hdr.number_of_sections)
        view = FileView(sections)
        parser = PEParser(source, view)

        pe = PE.__new__(PE)
        pe._source = source
        pe._parser = parser
        pe._view = view
        pe.dos_header = dos
        pe.file_header = file_hdr
        pe.optional_header = opt_hdr
        pe.sections = sections
        pe.exports = parser.parse_exports(data_dirs)
        pe.imports = parser.parse_imports(data_dirs, magic)
        return pe
```

- [ ] **Step 2: Write pe/__init__.py**

```python
"""PE format parser package — three-layer architecture (Source/View/Parse)."""

from .types import (
    DosHeader, FileHeader, OptionalHeader, DataDirectory,
    SectionHeader, ExportEntry, ImportEntry,
)
from .source import Source, FileSource, BytesSource
from .view import View, FileView, LoadedView
from .parser import PEParser

__all__ = [
    'DosHeader', 'FileHeader', 'OptionalHeader', 'DataDirectory',
    'SectionHeader', 'ExportEntry', 'ImportEntry',
    'Source', 'FileSource', 'BytesSource',
    'View', 'FileView', 'LoadedView',
    'PEParser',
]
```

- [ ] **Step 3: Verify backward compat — import PE from old path**

```bash
cd src && python3 -c "
import importlib.util, sys
exc_spec = importlib.util.spec_from_file_location('pydbg.exceptions', 'pydbg/exceptions.py')
exc_mod = importlib.util.module_from_spec(exc_spec)
sys.modules['pydbg.exceptions'] = exc_mod
exc_spec.loader.exec_module(exc_mod)

# Enable relative imports by making pydbg a package
sys.modules['pydbg'] = type(sys)('pydbg')

# Verify types import
from pydbg.pe.types import DosHeader, SectionHeader
from pydbg.pe.source import BytesSource, FileSource
from pydbg.pe.view import FileView, LoadedView
from pydbg.pe.parser import PEParser
print('All imports OK')
"
```

- [ ] **Step 4: Verify full PE parsing works (PE32+)**

```bash
cd src && python3 << 'PYEOF'
import importlib.util, sys

# Setup pydbg package
exc_spec = importlib.util.spec_from_file_location('pydbg.exceptions', 'pydbg/exceptions.py')
exc_mod = importlib.util.module_from_spec(exc_spec)
sys.modules['pydbg.exceptions'] = exc_mod
exc_spec.loader.exec_module(exc_mod)

# Load pe.types
types_spec = importlib.util.spec_from_file_location('pydbg.pe.types', 'pydbg/pe/types.py')
types_mod = importlib.util.module_from_spec(types_spec)
sys.modules['pydbg.pe.types'] = types_mod
types_spec.loader.exec_module(types_mod)

# Load pe.source
src_spec = importlib.util.spec_from_file_location('pydbg.pe.source', 'pydbg/pe/source.py')
src_mod = importlib.util.module_from_spec(src_spec)
sys.modules['pydbg.pe.source'] = src_mod
src_spec.loader.exec_module(src_mod)

# Load pe.view
view_spec = importlib.util.spec_from_file_location('pydbg.pe.view', 'pydbg/pe/view.py')
view_mod = importlib.util.module_from_spec(view_spec)
sys.modules['pydbg.pe.view'] = view_mod
view_spec.loader.exec_module(view_mod)

# Load pe.parser
parser_spec = importlib.util.spec_from_file_location('pydbg.pe.parser', 'pydbg/pe/parser.py')
parser_mod = importlib.util.module_from_spec(parser_spec)
sys.modules['pydbg.pe.parser'] = parser_mod
parser_spec.loader.exec_module(parser_mod)

# Test BytesSource -> FileView -> PEParser
from pydbg.pe.source import BytesSource
from pydbg.pe.view import FileView
from pydbg.pe.parser import PEParser
from pydbg.pe.types import SectionHeader

# Generate minimal PE32+ data
import struct
dos_header = struct.pack('<2s58xI', b'MZ', 0x80) + b'\x00' * (0x80 - 64)
pe_sig = struct.pack('<I', 0x00004550)
file_hdr = struct.pack('<HHIIIHH', 0x8664, 2, 0, 0, 0, 0xF0, 0x22)
opt_hdr = struct.pack('<HBB', 0x20B, 14, 0)
opt_hdr += struct.pack('<IIIII', 0x1000, 0, 0, 0x1000, 0x1000)
opt_hdr += struct.pack('<Q', 0x140000000)
opt_hdr += struct.pack('<II', 0x1000, 0x200)
opt_hdr += struct.pack('<HHHHHH', 4, 0, 0, 0, 4, 0)
opt_hdr += struct.pack('<III', 0, 0x4000, 0x400)
opt_hdr += struct.pack('<I', 0)
opt_hdr += struct.pack('<HH', 2, 0)
opt_hdr += struct.pack('<IIII', 0x100000, 0x1000, 0x100000, 0x1000)
opt_hdr += struct.pack('<II', 0, 2)
data_dirs = struct.pack('<IIII', 0, 0, 0, 0)
text_sec = struct.pack('<8sIIIIIIHHI', b'.text\x00\x00\x00', 0xE00, 0x1000, 0x1000, 0x400, 0, 0, 0, 0, 0x60000020)
rdata_sec = struct.pack('<8sIIIIIIHHI', b'.rdata\x00\x00', 0xA00, 0x2000, 0xC00, 0x1400, 0, 0, 0, 0, 0x40000040)
data = dos_header + pe_sig + file_hdr + opt_hdr + data_dirs + text_sec + rdata_sec
data += b'\x00' * (0x4200 - len(data))

source = BytesSource(data)
parser = PEParser(source, None)

dos = parser.parse_dos_header()
assert dos.e_magic == 0x5A4D
file_h, opt_h = parser.parse_nt_headers(dos.e_lfanew)
assert file_h.number_of_sections == 2
assert opt_h.magic == 0x20B

sections = parser.parse_sections(
    dos.e_lfanew + 4 + 20 + 112 + 2 * 8,
    file_h.number_of_sections)
assert sections[0].name == '.text'

view = FileView(sections)
assert view.rva_to_source_offset(0x1050) == 0x450

print('PE32+ parsing OK')
PYEOF
```

- [ ] **Step 5: Commit**

```bash
git add src/pydbg/pe.py src/pydbg/pe/__init__.py
git commit -m "refactor: PE class as facade delegating to PEParser+Source+View"
```

---

### Task 6: Add design doc and implementation plan

**Files:**
- Create: `docs/superpowers/specs/2026-05-27-pe-three-layer-architecture.md`
- Create: `docs/superpowers/plans/2026-05-27-pe-three-layer-refactor.md`

- [ ] **Step 1: Write design doc to file**

Write the design spec from the brainstorming session to `docs/superpowers/specs/2026-05-27-pe-three-layer-architecture.md`.

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/specs/2026-05-27-pe-three-layer-architecture.md \
        docs/superpowers/plans/2026-05-27-pe-three-layer-refactor.md
git commit -m "docs: add PE three-layer architecture design spec and implementation plan"
```

---

### Task 7: Run full test suite and lint

**Files:**
- Verify: all tests, lint

- [ ] **Step 1: Lint**

```bash
flake8 src/ tests/ --max-line-length=120
```

Expected: Zero errors.

- [ ] **Step 2: Run tests**

```bash
PYTHONPATH=build/src python3 -m pytest tests/ -v 2>&1 | tail -20
```

Expected: All previously passing tests still pass. PE32/PE32+ tests pass.

- [ ] **Step 3: Fix any regressions, commit fixes**

If no changes needed, no commit.
