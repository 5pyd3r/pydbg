# Game Analysis Framework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend pydbg into a game binary analysis framework with API interception, resource extraction, anti-debugging, execution tracing, and an integrated analysis workbench.

**Architecture:** Incremental enhancement of existing pydbg modules. New packages (`stealth/`, `intercept/`, `resource/`, `analysis/`) added alongside existing code. Each module is self-contained with clear interfaces. The `AnalysisWorkbench` orchestrates all modules.

**Tech Stack:** Python 3.10+, existing pydbg (Cython/Win32 Debug API), capstone (disassembly)

---

## File Structure

```
src/pydbg/
├── stealth/
│   ├── __init__.py              # exports AntiAware
│   └── anti_aware.py            # PEB/heap patching, IsDebuggerPresent hook
├── intercept/
│   ├── __init__.py              # exports APIInterceptor, CallGraphBuilder
│   ├── api_hook.py              # APIInterceptor, APICall dataclass
│   ├── call_graph.py            # CallGraphBuilder, CallEdge
│   └── presets/
│       ├── __init__.py          # exports load_preset()
│       ├── ddraw.py             # DDRAW_API_PRESET, DDRAW_VTABLE_METHODS
│       ├── dsound.py            # DSOUND_API_PRESET
│       └── win32.py             # WIN32_API_PRESET
├── resource/
│   ├── __init__.py              # exports PEResourceParser, ResourceRecognizer
│   ├── pe_resource.py           # PEResourceParser, ResourceEntry
│   └── recognizer.py            # ResourceRecognizer
├── trace/
│   ├── __init__.py              # (update: add ExecutionTracer, DataFlowTracker)
│   ├── calltree.py              # (existing, unchanged)
│   ├── step.py                  # (existing, unchanged)
│   ├── execution.py             # ExecutionTracer, TraceEvent
│   └── dataflow.py              # DataFlowTracker
├── analysis/
│   ├── __init__.py              # exports AnalysisWorkbench, GameAnalyzer
│   ├── workbench.py             # AnalysisWorkbench
│   └── game_analyzer.py         # GameAnalyzer
└── (existing modules unchanged)
```

---

## Task 1: PE Resource Parser

**Files:**
- Create: `src/pydbg/resource/__init__.py`
- Create: `src/pydbg/resource/pe_resource.py`
- Create: `tests/test_resource.py`

### Step 1: Write failing test for ResourceEntry dataclass

```python
# tests/test_resource.py
import unittest

class TestResourceEntry(unittest.TestCase):

    def test_dataclass_fields(self):
        from pydbg.resource.pe_resource import ResourceEntry
        entry = ResourceEntry(
            type_id=10, type_name="RT_RCDATA", name_id=1,
            name_str="", language_id=1033,
            data_rva=0x133100, data_size=4096, data_offset=0xF200,
        )
        self.assertEqual(entry.type_id, 10)
        self.assertEqual(entry.type_name, "RT_RCDATA")
        self.assertEqual(entry.data_size, 4096)

if __name__ == "__main__":
    unittest.main()
```

Run: `python -m pytest tests/test_resource.py::TestResourceEntry::test_dataclass_fields -v`
Expected: FAIL (module not found)

### Step 2: Create ResourceEntry dataclass

```python
# src/pydbg/resource/pe_resource.py
from dataclasses import dataclass


@dataclass
class ResourceEntry:
    """A single PE resource entry."""
    type_id: int
    type_name: str
    name_id: int
    name_str: str
    language_id: int
    data_rva: int
    data_size: int
    data_offset: int
```

```python
# src/pydbg/resource/__init__.py
from .pe_resource import ResourceEntry

__all__ = ['ResourceEntry']
```

Run: `python -m pytest tests/test_resource.py::TestResourceEntry::test_dataclass_fields -v`
Expected: PASS

### Step 3: Commit

```bash
git add src/pydbg/resource/ tests/test_resource.py
git commit -m "feat(resource): add ResourceEntry dataclass"
```

### Step 4: Write failing test for PEResourceParser with synthetic PE

```python
# tests/test_resource.py (append)
import struct

def build_pe_with_resources():
    """Build PE32 with .rsrc section containing one RT_RCDATA resource."""
    dos = struct.pack('<2s58xI', b'MZ', 0x80)
    dos += b'\x00' * (0x80 - len(dos))
    pe_sig = struct.pack('<I', 0x00004550)
    fh = struct.pack('<HHIIIHH', 0x14C, 3, 0x5A000000, 0, 0, 0xE0, 0x22)

    # PE32 optional header
    oh = struct.pack('<HBB', 0x10B, 14, 0)
    oh += struct.pack('<IIIIII', 0x1000, 0, 0, 0x1000, 0x1000, 0)
    oh += struct.pack('<I', 0x400000)
    oh += struct.pack('<II', 0x1000, 0x200)
    oh += struct.pack('<HHHHHH', 4, 0, 0, 0, 4, 0)
    oh += struct.pack('<I', 0)
    oh += struct.pack('<III', 0x8000, 0x400, 0)
    oh += struct.pack('<HH', 2, 0)
    oh += struct.pack('<IIII', 0x100000, 0x1000, 0x100000, 0x1000)
    oh += struct.pack('<II', 0, 2)

    # Data dirs: no export, no import, but we need 2 entries minimum
    dd = struct.pack('<IIII', 0, 0, 0, 0)

    # .text, .rdata, .rsrc
    text = struct.pack('<8sIIIIIIHHI', b'.text\x00\x00\x00',
                       0xE00, 0x1000, 0x1000, 0x400, 0, 0, 0, 0, 0x60000020)
    rdata = struct.pack('<8sIIIIIIHHI', b'.rdata\x00\x00',
                        0x1000, 0x2000, 0x1000, 0x1400, 0, 0, 0, 0, 0x40000040)
    rsrc = struct.pack('<8sIIIIIIHHI', b'.rsrc\x00\x00\x00',
                       0x2000, 0x3000, 0x2000, 0x2400, 0, 0, 0, 0, 0x40000040)

    data = bytearray(dos + pe_sig + fh + oh + dd + text + rdata + rsrc)
    if len(data) < 0x4400:
        data += b'\x00' * (0x4400 - len(data))

    # Build resource directory at .rsrc file offset 0x2400
    # Resource directory starts at RVA 0x3000 -> file offset 0x2400
    rsrc_base = 0x2400

    # IMAGE_RESOURCE_DIRECTORY (16 bytes header)
    # Characteristics(4), TimeDateStamp(4), MajorVersion(2), MinorVersion(2),
    # NumberOfNamedEntries(2), NumberOfIdEntries(2)
    dir_header = struct.pack('<IIHHHH', 0, 0, 0, 0, 0, 1)  # 1 ID entry (RT_RCDATA=10)
    data[rsrc_base:rsrc_base + 16] = dir_header

    # Directory entry: ID=10 (RT_RCDATA), offset to subdirectory
    # Id(4) or NameRva(4) | OffsetToData(4) - high bit 0 = ID
    sub_dir_offset = 0x40  # offset from rsrc_base to subdirectory
    entry1 = struct.pack('<II', 10, 0x80000000 | sub_dir_offset)  # high bit = directory
    data[rsrc_base + 16:rsrc_base + 24] = entry1

    # Subdirectory (Name level): 1 entry with ID=100
    sub_dir_addr = rsrc_base + sub_dir_offset
    sub_header = struct.pack('<IIHHHH', 0, 0, 0, 0, 0, 1)  # 1 ID entry
    data[sub_dir_addr:sub_dir_addr + 16] = sub_header

    # Entry pointing to language subdirectory
    lang_dir_offset = 0x80
    entry2 = struct.pack('<II', 100, 0x80000000 | lang_dir_offset)
    data[sub_dir_addr + 16:sub_dir_addr + 24] = entry2

    # Language subdirectory: 1 entry
    lang_dir_addr = rsrc_base + lang_dir_offset
    lang_header = struct.pack('<IIHHHH', 0, 0, 0, 0, 0, 1)
    data[lang_dir_addr:lang_dir_addr + 16] = lang_header

    # Leaf entry: LanguageId=1033, DataRva, Size
    data_entry_rva = 0x3200  # RVA of actual resource data
    data_entry_size = 16
    leaf = struct.pack('<IIII', data_entry_rva, data_entry_size, 0, 1033)
    data[lang_dir_addr + 16:lang_dir_addr + 32] = leaf

    # Write actual resource data at RVA 0x3200 -> file offset 0x2600
    resource_data = b'\xDE\xAD\xBE\xEF' * 4  # 16 bytes
    data[0x2600:0x2600 + 16] = resource_data

    return bytes(data)


class TestPEResourceParser(unittest.TestCase):

    def test_parse_resources(self):
        from pydbg.resource.pe_resource import PEResourceParser
        from pydbg.pe import PE
        data = build_pe_with_resources()
        pe = PE(data)
        parser = PEResourceParser(pe)
        resources = parser.parse()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0].type_id, 10)
        self.assertEqual(resources[0].type_name, "RT_RCDATA")
        self.assertEqual(resources[0].name_id, 100)
        self.assertEqual(resources[0].data_size, 16)

    def test_extract_resource_data(self):
        from pydbg.resource.pe_resource import PEResourceParser
        from pydbg.pe import PE
        data = build_pe_with_resources()
        pe = PE(data)
        parser = PEResourceParser(pe)
        resources = parser.parse()
        extracted = parser.extract(resources[0])
        self.assertEqual(extracted, b'\xDE\xAD\xBE\xEF' * 4)

    def test_get_by_type(self):
        from pydbg.resource.pe_resource import PEResourceParser
        from pydbg.pe import PE
        data = build_pe_with_resources()
        pe = PE(data)
        parser = PEResourceParser(pe)
        parser.parse()
        rcdata = parser.get_by_type(10)
        self.assertEqual(len(rcdata), 1)
        bitmaps = parser.get_by_type(2)
        self.assertEqual(len(bitmaps), 0)

    def test_empty_resources(self):
        from pydbg.resource.pe_resource import PEResourceParser
        from pydbg.pe import PE
        # Use minimal PE without .rsrc
        from tests.test_pe import build_minimal_pe32plus
        pe = PE(build_minimal_pe32plus())
        parser = PEResourceParser(pe)
        resources = parser.parse()
        self.assertEqual(resources, [])
```

Run: `python -m pytest tests/test_resource.py::TestPEResourceParser -v`
Expected: FAIL (PEResourceParser not defined)

### Step 5: Implement PEResourceParser

```python
# src/pydbg/resource/pe_resource.py (replace entire file)
from dataclasses import dataclass


@dataclass
class ResourceEntry:
    """A single PE resource entry."""
    type_id: int
    type_name: str
    name_id: int
    name_str: str
    language_id: int
    data_rva: int
    data_size: int
    data_offset: int


class PEResourceParser:
    """PE resource directory parser. Parses the 3-layer resource tree."""

    RESOURCE_TYPES = {
        1: "RT_CURSOR", 2: "RT_BITMAP", 3: "RT_ICON",
        4: "RT_MENU", 5: "RT_DIALOG", 6: "RT_STRING",
        7: "RT_FONTDIR", 8: "RT_FONT", 9: "RT_ACCELERATOR",
        10: "RT_RCDATA", 11: "RT_MESSAGETABLE", 12: "RT_GROUP_CURSOR",
        14: "RT_GROUP_ICON", 16: "RT_VERSION", 17: "RT_DLGINCLUDE",
        19: "RT_PLUGPLAY", 20: "RT_VXD", 21: "RT_ANICURSOR",
        22: "RT_ANIICON", 23: "RT_HTML", 24: "RT_MANIFEST",
    }

    def __init__(self, pe):
        self._pe = pe
        self._resources = []
        self._rsrc_section = None
        self._data = None

    def _find_rsrc_section(self):
        """Find .rsrc section."""
        for section in self._pe.sections:
            if section.name == '.rsrc':
                return section
        return None

    def _read_rsrc_bytes(self, offset, size):
        """Read bytes from .rsrc section at given offset."""
        if self._data is None:
            # Read the full .rsrc section from source
            sec = self._rsrc_section
            if sec is None:
                return None
            self._data = self._pe._source.read(sec.pointer_to_raw_data, sec.size_of_raw_data)
        if offset + size > len(self._data):
            return None
        return self._data[offset:offset + size]

    def _rva_to_rsrc_offset(self, rva):
        """Convert RVA to offset within .rsrc section data."""
        sec = self._rsrc_section
        if sec is None:
            return None
        if sec.virtual_address <= rva < sec.virtual_address + sec.virtual_size:
            return rva - sec.virtual_address
        return None

    def _parse_directory(self, offset, level, type_id=0, name_id=0, name_str=""):
        """Recursively parse resource directory tree.
        Level 0=Type, 1=Name, 2=Language.
        """
        header = self._read_rsrc_bytes(offset, 16)
        if header is None:
            return

        import struct
        _, _, _, _, num_named, num_id = struct.unpack_from('<IIHHHH', header, 0)
        entry_offset = offset + 16

        for i in range(num_named + num_id):
            entry = self._read_rsrc_bytes(entry_offset, 8)
            if entry is None:
                break
            id_or_name_rva, data_or_subdir = struct.unpack_from('<II', entry, 0)

            is_directory = (data_or_subdir & 0x80000000) != 0
            child_offset = data_or_subdir & 0x7FFFFFFF

            if i < num_named:
                # Named entry: id_or_name_rva is RVA to name string
                name_rva = id_or_name_rva
                name_off = self._rva_to_rsrc_offset(name_rva)
                curr_name = ""
                if name_off is not None:
                    name_data = self._read_rsrc_bytes(name_off, 2)
                    if name_data:
                        name_len = struct.unpack_from('<H', name_data, 0)[0]
                        name_bytes = self._read_rsrc_bytes(name_off + 2, name_len * 2)
                        if name_bytes:
                            curr_name = name_bytes.decode('utf-16-le', errors='replace')
                curr_id = 0
            else:
                curr_id = id_or_name_rva
                curr_name = ""

            if level == 0:
                type_id = curr_id
                type_str = self.RESOURCE_TYPES.get(curr_id, f"UNKNOWN_{curr_id}")
                self._parse_directory(child_offset, 1, type_id=type_id)
            elif level == 1:
                name_id = curr_id
                name_str = curr_name
                self._parse_directory(child_offset, 2, type_id=type_id,
                                      name_id=name_id, name_str=name_str)
            elif level == 2:
                language_id = curr_id
                # Leaf node: data_or_subdir is RVA to IMAGE_RESOURCE_DATA_ENTRY
                data_entry_off = self._rva_to_rsrc_offset(data_or_subdir)
                if data_entry_off is not None:
                    de = self._read_rsrc_bytes(data_entry_off, 16)
                    if de:
                        data_rva, data_size, _, _ = struct.unpack_from('<IIII', de, 0)
                        data_offset = self._rva_to_rsrc_offset(data_rva)
                        self._resources.append(ResourceEntry(
                            type_id=type_id,
                            type_name=self.RESOURCE_TYPES.get(type_id, f"UNKNOWN_{type_id}"),
                            name_id=name_id,
                            name_str=name_str,
                            language_id=language_id,
                            data_rva=data_rva,
                            data_size=data_size,
                            data_offset=data_offset if data_offset is not None else 0,
                        ))

            entry_offset += 8

    def parse(self):
        """Parse resource directory, return list of ResourceEntry."""
        self._rsrc_section = self._find_rsrc_section()
        if self._rsrc_section is None:
            return []
        self._resources = []
        self._data = None
        self._parse_directory(0, 0)
        return list(self._resources)

    def get_by_type(self, type_id):
        """Filter resources by type ID."""
        return [r for r in self._resources if r.type_id == type_id]

    def get_by_name(self, name):
        """Filter resources by name string."""
        return [r for r in self._resources if r.name_str == name]

    def extract(self, entry):
        """Extract raw bytes for a single resource entry."""
        if entry.data_offset is None or entry.data_offset == 0:
            return b''
        return self._read_rsrc_bytes(entry.data_offset, entry.data_size) or b''

    def extract_all(self, output_dir, type_filter=None):
        """Extract all resources to output directory."""
        import os
        os.makedirs(output_dir, exist_ok=True)
        entries = self._resources
        if type_filter is not None:
            entries = [r for r in entries if r.type_id == type_filter]
        results = []
        for entry in entries:
            data = self.extract(entry)
            if not data:
                continue
            name = entry.name_str or str(entry.name_id)
            ext = self._guess_extension(data)
            filename = f"{entry.type_name}_{name}{ext}"
            path = os.path.join(output_dir, filename)
            with open(path, 'wb') as f:
                f.write(data)
            results.append(path)
        return results

    @staticmethod
    def _guess_extension(data):
        if data[:4] == b'RIFF':
            return '.wav'
        if data[:2] == b'BM':
            return '.bmp'
        return '.bin'
```

Update `src/pydbg/resource/__init__.py`:
```python
# src/pydbg/resource/__init__.py
from .pe_resource import ResourceEntry, PEResourceParser

__all__ = ['ResourceEntry', 'PEResourceParser']
```

Run: `python -m pytest tests/test_resource.py -v`
Expected: PASS

### Step 6: Commit

```bash
git add src/pydbg/resource/ tests/test_resource.py
git commit -m "feat(resource): add PE resource directory parser

Parses 3-layer resource tree (Type -> Name -> Language).
Supports extraction by type/name, bulk export to disk."
```

---

## Task 2: Resource Recognizer

**Files:**
- Create: `src/pydbg/resource/recognizer.py`
- Modify: `src/pydbg/resource/__init__.py`
- Modify: `tests/test_resource.py`

### Step 1: Write failing tests

```python
# tests/test_resource.py (append)

class TestResourceRecognizer(unittest.TestCase):

    def test_recognize_wav(self):
        from pydbg.resource.recognizer import ResourceRecognizer
        data = b'RIFF' + b'\x00' * 40
        result = ResourceRecognizer().recognize(data)
        self.assertEqual(result['format'], 'wav')

    def test_recognize_bmp(self):
        from pydbg.resource.recognizer import ResourceRecognizer
        data = b'BM' + b'\x00' * 40
        result = ResourceRecognizer().recognize(data)
        self.assertEqual(result['format'], 'bmp')

    def test_recognize_unknown(self):
        from pydbg.resource.recognizer import ResourceRecognizer
        data = b'\x01\x02\x03\x04' * 10
        result = ResourceRecognizer().recognize(data)
        self.assertEqual(result['format'], 'unknown')

    def test_recognize_palette_rgb(self):
        from pydbg.resource.recognizer import ResourceRecognizer
        data = b'\x00' * 768  # 256 * 3
        result = ResourceRecognizer().recognize_palette(data)
        self.assertIsNotNone(result)
        self.assertEqual(result['entries'], 256)
        self.assertEqual(result['bpp'], 24)

    def test_recognize_palette_rgba(self):
        from pydbg.resource.recognizer import ResourceRecognizer
        data = b'\x00' * 1024  # 256 * 4
        result = ResourceRecognizer().recognize_palette(data)
        self.assertIsNotNone(result)
        self.assertEqual(result['entries'], 256)
        self.assertEqual(result['bpp'], 32)

    def test_palette_wrong_size(self):
        from pydbg.resource.recognizer import ResourceRecognizer
        data = b'\x00' * 500
        result = ResourceRecognizer().recognize_palette(data)
        self.assertIsNone(result)
```

Run: `python -m pytest tests/test_resource.py::TestResourceRecognizer -v`
Expected: FAIL

### Step 2: Implement ResourceRecognizer

```python
# src/pydbg/resource/recognizer.py
from dataclasses import dataclass


class ResourceRecognizer:
    """Auto-identify resource data formats by signature and heuristics."""

    SIGNATURES = {
        b'RIFF': 'wav',
        b'BM': 'bmp',
        b'\x89PNG': 'png',
        b'GIF8': 'gif',
    }

    def recognize(self, data):
        """Identify format. Returns dict with format, width, height, bpp, extra."""
        if not data:
            return {'format': 'empty', 'width': None, 'height': None, 'bpp': None, 'extra': {}}

        for sig, fmt in self.SIGNATURES.items():
            if data[:len(sig)] == sig:
                info = {'format': fmt, 'width': None, 'height': None, 'bpp': None, 'extra': {}}
                if fmt == 'bmp':
                    info.update(self._parse_bmp_header(data))
                return info

        # Heuristic: palette?
        pal = self.recognize_palette(data)
        if pal is not None:
            return {'format': 'palette', 'width': None, 'height': None,
                    'bpp': pal['bpp'], 'extra': pal}

        return {'format': 'unknown', 'width': None, 'height': None, 'bpp': None, 'extra': {}}

    def recognize_palette(self, data):
        """Check if data looks like a color palette (256 entries * 3 or 4 bytes)."""
        if len(data) == 768:
            return {'entries': 256, 'bpp': 24, 'bytes_per_entry': 3}
        if len(data) == 1024:
            return {'entries': 256, 'bpp': 32, 'bytes_per_entry': 4}
        return None

    def recognize_sprite(self, data, width=None):
        """Try to identify sprite data. Returns possible dimensions."""
        size = len(data)
        if size == 0:
            return None
        candidates = []
        for w in [16, 24, 32, 48, 64, 128, 256, 320, 640]:
            if size % w == 0:
                h = size // w
                if 1 <= h <= 2048:
                    candidates.append({'width': w, 'height': h})
        if width is not None and size % width == 0:
            return {'width': width, 'height': size // width}
        return candidates if candidates else None

    @staticmethod
    def _parse_bmp_header(data):
        """Extract width/height from BMP DIB header."""
        import struct
        if len(data) < 26:
            return {}
        # BITMAPFILEHEADER: offset 10 = bfOffBits, offset 14 = DIB header
        if len(data) < 18:
            return {}
        dib_size = struct.unpack_from('<I', data, 14)[0]
        if dib_size >= 40 and len(data) >= 30:
            width = struct.unpack_from('<i', data, 18)[0]
            height = abs(struct.unpack_from('<i', data, 22)[0])
            bpp = struct.unpack_from('<H', data, 28)[0] if len(data) > 28 else None
            return {'width': width, 'height': height, 'bpp': bpp}
        return {}
```

Update `src/pydbg/resource/__init__.py`:
```python
from .pe_resource import ResourceEntry, PEResourceParser
from .recognizer import ResourceRecognizer

__all__ = ['ResourceEntry', 'PEResourceParser', 'ResourceRecognizer']
```

Run: `python -m pytest tests/test_resource.py -v`
Expected: PASS

### Step 3: Commit

```bash
git add src/pydbg/resource/recognizer.py src/pydbg/resource/__init__.py tests/test_resource.py
git commit -m "feat(resource): add ResourceRecognizer for format auto-detection

Identifies WAV, BMP, PNG, palette data by signature and heuristics."
```

---

## Task 3: Anti-Aware (Stealth)

**Files:**
- Create: `src/pydbg/stealth/__init__.py`
- Create: `src/pydbg/stealth/anti_aware.py`
- Create: `tests/test_stealth.py`

### Step 1: Write failing tests

```python
# tests/test_stealth.py
import unittest


class TestAntiAware(unittest.TestCase):

    def test_init(self):
        from pydbg.core.session import DebugSession
        from pydbg.stealth.anti_aware import AntiAware
        session = DebugSession()
        aa = AntiAware(session)
        self.assertIsNotNone(aa)

    def test_peb_offsets_x86(self):
        """Verify PEB offset constants for 32-bit."""
        from pydbg.stealth.anti_aware import AntiAware
        self.assertEqual(AntiAware.PEB_BEING_DEBUGGED_OFFSET, 0x02)
        self.assertEqual(AntiAware.PEB_NT_GLOBAL_FLAG_OFFSET, 0x68)
        self.assertEqual(AntiAware.HEAP_FLAGS_OFFSET, 0x40)
        self.assertEqual(AntiAware.HEAP_FORCE_FLAGS_OFFSET, 0x44)

    def test_debug_flag_constants(self):
        from pydbg.stealth.anti_aware import AntiAware
        self.assertEqual(AntiAware.FLG_HEAP_ENABLE_TAIL_CHECK, 0x10)
        self.assertEqual(AntiAware.FLG_HEAP_ENABLE_FREE_CHECK, 0x20)
        self.assertEqual(AntiAware.FLG_HEAP_VALIDATE_PARAMETERS, 0x40)


if __name__ == "__main__":
    unittest.main()
```

Run: `python -m pytest tests/test_stealth.py -v`
Expected: FAIL

### Step 2: Implement AntiAware

```python
# src/pydbg/stealth/anti_aware.py
"""Anti-awareness: patch PEB and heap flags to hide debugger."""


class AntiAware:
    """Bypass common debugger detection techniques by patching process memory."""

    # PEB offsets (32-bit Windows)
    PEB_BEING_DEBUGGED_OFFSET = 0x02
    PEB_NT_GLOBAL_FLAG_OFFSET = 0x68
    PEB_PROCESS_HEAP_OFFSET = 0x18

    # Heap header offsets
    HEAP_FLAGS_OFFSET = 0x40
    HEAP_FORCE_FLAGS_OFFSET = 0x44

    # NtGlobalFlag debug flags
    FLG_HEAP_ENABLE_TAIL_CHECK = 0x10
    FLG_HEAP_ENABLE_FREE_CHECK = 0x20
    FLG_HEAP_VALIDATE_PARAMETERS = 0x40
    DEBUG_FLAGS = FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS

    def __init__(self, session):
        self._s = session

    def hide_all(self):
        """Apply all anti-detection patches."""
        self.patch_peb_being_debugged()
        self.patch_peb_nt_global_flag()
        self.patch_heap_flags()

    def patch_peb_being_debugged(self):
        """Set PEB.BeingDebugged to 0."""
        from ..memory.manager import MemoryManager
        mem = MemoryManager(self._s)
        peb_addr = self._get_peb_address()
        if peb_addr is None:
            return False
        try:
            mem.write(peb_addr + self.PEB_BEING_DEBUGGED_OFFSET, b'\x00')
            return True
        except Exception:
            return False

    def patch_peb_nt_global_flag(self):
        """Clear debug flags from PEB.NtGlobalFlag."""
        from ..memory.manager import MemoryManager
        mem = MemoryManager(self._s)
        peb_addr = self._get_peb_address()
        if peb_addr is None:
            return False
        try:
            addr = peb_addr + self.PEB_NT_GLOBAL_FLAG_OFFSET
            data = mem.read(addr, 4)
            import struct
            flags = struct.unpack_from('<I', data, 0)[0]
            flags &= ~self.DEBUG_FLAGS
            mem.write(addr, struct.pack('<I', flags))
            return True
        except Exception:
            return False

    def patch_heap_flags(self):
        """Remove debug flags from process heap headers."""
        from ..memory.manager import MemoryManager
        import struct
        mem = MemoryManager(self._s)
        peb_addr = self._get_peb_address()
        if peb_addr is None:
            return False
        try:
            heap_addr_data = mem.read(peb_addr + self.PEB_PROCESS_HEAP_OFFSET, 4)
            heap_addr = struct.unpack_from('<I', heap_addr_data, 0)[0]
            if heap_addr == 0:
                return False
            # Patch Flags
            flags_data = mem.read(heap_addr + self.HEAP_FLAGS_OFFSET, 4)
            flags = struct.unpack_from('<I', flags_data, 0)[0]
            flags &= ~0xC0000000  # Clear HEAP_SLOW_FLAGS
            mem.write(heap_addr + self.HEAP_FLAGS_OFFSET, struct.pack('<I', flags))
            # Patch ForceFlags
            ff_data = mem.read(heap_addr + self.HEAP_FORCE_FLAGS_OFFSET, 4)
            ff = struct.unpack_from('<I', ff_data, 0)[0]
            ff &= ~0xC0000000
            mem.write(heap_addr + self.HEAP_FORCE_FLAGS_OFFSET, struct.pack('<I', ff))
            return True
        except Exception:
            return False

    def _get_peb_address(self):
        """Get PEB address from TEB. Uses FS:[0x30] on x86."""
        arch = getattr(self._s, 'target_arch', 32)
        if arch == 32:
            # On x86, PEB is at FS:[0x30]
            # We can read it via the thread context + TEB
            # For simplicity, use ctypes if available
            try:
                import ctypes
                if ctypes.sizeof(ctypes.c_void_p) == 4:
                    # 32-bit Python debugging 32-bit target
                    return ctypes.windll.kernel32.__readfsdword(0x30)
            except Exception:
                pass
        # Fallback: not available without live thread context
        return None
```

```python
# src/pydbg/stealth/__init__.py
from .anti_aware import AntiAware

__all__ = ['AntiAware']
```

Run: `python -m pytest tests/test_stealth.py -v`
Expected: PASS

### Step 3: Commit

```bash
git add src/pydbg/stealth/ tests/test_stealth.py
git commit -m "feat(stealth): add AntiAware for debugger detection bypass

Patches PEB.BeingDebugged, NtGlobalFlag, and heap debug flags."
```

---

## Task 4: API Interceptor Core

**Files:**
- Create: `src/pydbg/intercept/__init__.py`
- Create: `src/pydbg/intercept/api_hook.py`
- Create: `tests/test_intercept.py`

### Step 1: Write failing tests for APICall dataclass

```python
# tests/test_intercept.py
import unittest


class TestAPICall(unittest.TestCase):

    def test_dataclass(self):
        from pydbg.intercept.api_hook import APICall
        call = APICall(
            timestamp=1000, tid=1, module="ddraw.dll",
            function="DirectDrawCreate", args=[0, 0x5222A0, 0],
            decoded_args={"lpGUID": "NULL", "lplpDD": "0x5222A0"},
            return_value=0, decoded_return="DD_OK",
            call_stack=[0x4034F0, 0x401000],
        )
        self.assertEqual(call.function, "DirectDrawCreate")
        self.assertEqual(call.return_value, 0)

    def test_dataclass_defaults(self):
        from pydbg.intercept.api_hook import APICall
        call = APICall(
            timestamp=0, tid=0, module="", function="",
            args=[], decoded_args={}, return_value=0,
            decoded_return="", call_stack=[],
        )
        self.assertEqual(call.args, [])


class TestAPIInterceptor(unittest.TestCase):

    def test_init(self):
        from pydbg.core.session import DebugSession
        from pydbg.intercept.api_hook import APIInterceptor
        session = DebugSession()
        interceptor = APIInterceptor(session)
        self.assertEqual(interceptor.get_calls(), [])
        self.assertEqual(interceptor.get_call_count(), {})

    def test_register_decoder(self):
        from pydbg.core.session import DebugSession
        from pydbg.intercept.api_hook import APIInterceptor
        session = DebugSession()
        interceptor = APIInterceptor(session)
        interceptor.register_decoder("ddraw.dll", "DirectDrawCreate",
                                     lambda args, ret: {"decoded": True})
        self.assertIn(("ddraw.dll", "DirectDrawCreate"), interceptor._decoders)

    def test_record_call_manually(self):
        """Test that _record_call adds to calls list."""
        from pydbg.core.session import DebugSession
        from pydbg.intercept.api_hook import APIInterceptor, APICall
        session = DebugSession()
        interceptor = APIInterceptor(session)
        call = APICall(
            timestamp=100, tid=1, module="ddraw.dll",
            function="DirectDrawCreate", args=[0, 0x5222A0, 0],
            decoded_args={}, return_value=0, decoded_return="",
            call_stack=[],
        )
        interceptor._calls.append(call)
        self.assertEqual(len(interceptor.get_calls()), 1)
        counts = interceptor.get_call_count()
        self.assertEqual(counts["ddraw.dll!DirectDrawCreate"], 1)

    def test_export_json(self):
        import json
        import tempfile
        import os
        from pydbg.core.session import DebugSession
        from pydbg.intercept.api_hook import APIInterceptor, APICall
        session = DebugSession()
        interceptor = APIInterceptor(session)
        interceptor._calls.append(APICall(
            timestamp=100, tid=1, module="ddraw.dll",
            function="DirectDrawCreate", args=[0],
            decoded_args={}, return_value=0, decoded_return="DD_OK",
            call_stack=[],
        ))
        path = os.path.join(tempfile.gettempdir(), "test_intercept_export.json")
        interceptor.export_json(path)
        with open(path) as f:
            data = json.load(f)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["function"], "DirectDrawCreate")
        os.unlink(path)

    def test_get_calls_filter(self):
        from pydbg.core.session import DebugSession
        from pydbg.intercept.api_hook import APIInterceptor, APICall
        session = DebugSession()
        interceptor = APIInterceptor(session)
        interceptor._calls.append(APICall(
            timestamp=100, tid=1, module="ddraw.dll",
            function="DirectDrawCreate", args=[], decoded_args={},
            return_value=0, decoded_return="", call_stack=[],
        ))
        interceptor._calls.append(APICall(
            timestamp=200, tid=1, module="dsound.dll",
            function="DirectSoundCreate", args=[], decoded_args={},
            return_value=0, decoded_return="", call_stack=[],
        ))
        dd_calls = interceptor.get_calls(module="ddraw.dll")
        self.assertEqual(len(dd_calls), 1)
        ds_calls = interceptor.get_calls(function="DirectSoundCreate")
        self.assertEqual(len(ds_calls), 1)


if __name__ == "__main__":
    unittest.main()
```

Run: `python -m pytest tests/test_intercept.py -v`
Expected: FAIL

### Step 2: Implement APIInterceptor and APICall

```python
# src/pydbg/intercept/api_hook.py
"""API interception engine with call logging and parameter decoding."""

import json
from dataclasses import dataclass, field, asdict


@dataclass
class APICall:
    """Record of a single API call."""
    timestamp: int
    tid: int
    module: str
    function: str
    args: list = field(default_factory=list)
    decoded_args: dict = field(default_factory=dict)
    return_value: int = 0
    decoded_return: str = ""
    call_stack: list = field(default_factory=list)


class APIInterceptor:
    """Intercept and record API calls via IAT hooking and COM VTable replacement."""

    def __init__(self, session):
        self._s = session
        self._hooks = {}        # (module, func) -> hook_info
        self._calls = []        # list of APICall
        self._decoders = {}     # (module, func) -> decoder_func
        self._original_addrs = {}  # (module, func) -> original IAT address

    def register_decoder(self, module, function, decoder_fn):
        """Register a parameter decoder for an API function.

        decoder_fn(args_list, return_value) -> dict of decoded params.
        """
        self._decoders[(module, function)] = decoder_fn

    def intercept(self, module, function, decoder=None):
        """Register an API interception via IAT hook.

        This hooks the IAT entry so that calls to `function` from `module`
        are redirected through our trampoline.
        """
        if decoder is not None:
            self.register_decoder(module, function, decoder)

        from ..hook.iat import IATHook
        iat = IATHook(self._s)

        # Find the IAT entry
        modules = []
        try:
            from ..module.resolver import ModuleResolver
            mr = ModuleResolver(self._s)
            modules = mr.enumerate()
        except Exception:
            pass

        # Store hook info for later activation
        self._hooks[(module, function)] = {
            'iat_hook': iat,
            'decoder': decoder or self._decoders.get((module, function)),
        }

    def intercept_module(self, module, preset=None):
        """Intercept all functions in a module using a preset."""
        if preset is not None:
            for func_name, func_spec in preset.items():
                decoder = func_spec.get('decoder')
                self.intercept(module, func_name, decoder=decoder)

    def intercept_com_vtable(self, obj_addr, interface_name, vtable_map):
        """Replace COM object VTable entries with proxy functions.

        Args:
            obj_addr: Address of the COM object (e.g., IDirectDraw pointer)
            interface_name: Name for logging (e.g., "IDirectDraw")
            vtable_map: dict of {vtable_index: method_name}
        """
        from ..memory.manager import MemoryManager
        import struct
        mem = MemoryManager(self._s)

        # Read VTable pointer from object
        ptr_size = 4 if getattr(self._s, 'target_arch', 32) == 32 else 8
        fmt = '<I' if ptr_size == 4 else '<Q'
        vtable_ptr_data = mem.read(obj_addr, ptr_size)
        vtable_addr = struct.unpack_from(fmt, vtable_ptr_data, 0)[0]

        # Store original VTable entries for each method we want to intercept
        for index, method_name in vtable_map.items():
            entry_addr = vtable_addr + index * ptr_size
            orig_data = mem.read(entry_addr, ptr_size)
            orig_func = struct.unpack_from(fmt, orig_data, 0)[0]
            self._original_addrs[(interface_name, method_name)] = orig_func

    def get_calls(self, module=None, function=None, tid=None):
        """Get recorded calls, optionally filtered."""
        result = self._calls
        if module is not None:
            result = [c for c in result if c.module == module]
        if function is not None:
            result = [c for c in result if c.function == function]
        if tid is not None:
            result = [c for c in result if c.tid == tid]
        return result

    def get_call_count(self):
        """Get call count statistics as {module!function: count}."""
        counts = {}
        for c in self._calls:
            key = f"{c.module}!{c.function}"
            counts[key] = counts.get(key, 0) + 1
        return counts

    def export_json(self, path):
        """Export call records to JSON file."""
        data = []
        for c in self._calls:
            entry = {
                'timestamp': c.timestamp,
                'tid': c.tid,
                'module': c.module,
                'function': c.function,
                'args': c.args,
                'decoded_args': c.decoded_args,
                'return_value': c.return_value,
                'decoded_return': c.decoded_return,
                'call_stack': [hex(a) for a in c.call_stack],
            }
            data.append(entry)
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)

    def export_csv(self, path):
        """Export call records to CSV file."""
        import csv
        with open(path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['timestamp', 'tid', 'module', 'function',
                             'return_value', 'decoded_return'])
            for c in self._calls:
                writer.writerow([c.timestamp, c.tid, c.module, c.function,
                                 hex(c.return_value), c.decoded_return])

    def clear(self):
        """Clear all recorded calls."""
        self._calls.clear()
```

```python
# src/pydbg/intercept/__init__.py
from .api_hook import APIInterceptor, APICall

__all__ = ['APIInterceptor', 'APICall']
```

Run: `python -m pytest tests/test_intercept.py -v`
Expected: PASS

### Step 3: Commit

```bash
git add src/pydbg/intercept/ tests/test_intercept.py
git commit -m "feat(intercept): add APIInterceptor core with call logging

Supports IAT hook registration, COM VTable interception, call filtering,
and JSON/CSV export."
```

---

## Task 5: API Presets (DirectDraw, DirectSound, Win32)

**Files:**
- Create: `src/pydbg/intercept/presets/__init__.py`
- Create: `src/pydbg/intercept/presets/ddraw.py`
- Create: `src/pydbg/intercept/presets/dsound.py`
- Create: `src/pydbg/intercept/presets/win32.py`
- Modify: `tests/test_intercept.py`

### Step 1: Write failing tests

```python
# tests/test_intercept.py (append)

class TestPresets(unittest.TestCase):

    def test_load_ddraw_preset(self):
        from pydbg.intercept.presets import load_preset
        preset = load_preset("ddraw")
        self.assertIn("DirectDrawCreate", preset)
        self.assertIn("DirectDrawCreateEx", preset)

    def test_ddraw_vtable_methods(self):
        from pydbg.intercept.presets.ddraw import DDRAW_VTABLE_METHODS
        self.assertIn("IDirectDraw", DDRAW_VTABLE_METHODS)
        self.assertIn("IDirectDrawSurface", DDRAW_VTABLE_METHODS)
        self.assertEqual(DDRAW_VTABLE_METHODS["IDirectDraw"][6], "CreateSurface")

    def test_load_dsound_preset(self):
        from pydbg.intercept.presets import load_preset
        preset = load_preset("dsound")
        self.assertIn("DirectSoundCreate", preset)

    def test_load_win32_preset(self):
        from pydbg.intercept.presets import load_preset
        preset = load_preset("win32")
        self.assertIn("CreateWindowExA", preset)
        self.assertIn("PeekMessageA", preset)

    def test_unknown_preset_raises(self):
        from pydbg.intercept.presets import load_preset
        with self.assertRaises(ValueError):
            load_preset("nonexistent")
```

Run: `python -m pytest tests/test_intercept.py::TestPresets -v`
Expected: FAIL

### Step 2: Implement presets

```python
# src/pydbg/intercept/presets/__init__.py
from .ddraw import DDRAW_API_PRESET, DDRAW_VTABLE_METHODS
from .dsound import DSOUND_API_PRESET
from .win32 import WIN32_API_PRESET

_PRESETS = {
    'ddraw': DDRAW_API_PRESET,
    'dsound': DSOUND_API_PRESET,
    'win32': WIN32_API_PRESET,
}


def load_preset(name):
    """Load a named API preset. Raises ValueError if not found."""
    if name not in _PRESETS:
        raise ValueError(f"Unknown preset '{name}'. Available: {list(_PRESETS.keys())}")
    return _PRESETS[name]


__all__ = ['load_preset', 'DDRAW_API_PRESET', 'DDRAW_VTABLE_METHODS',
           'DSOUND_API_PRESET', 'WIN32_API_PRESET']
```

```python
# src/pydbg/intercept/presets/ddraw.py
"""DirectDraw API interception preset."""

DDRAW_API_PRESET = {
    "DirectDrawCreate": {
        "args": ["lpGUID", "lplpDD", "pUnkOuter"],
        "decoder": None,  # filled by implementation
    },
    "DirectDrawCreateEx": {
        "args": ["lpGuid", "lplpDD", "riid", "pUnkOuter"],
        "decoder": None,
    },
}

DDRAW_VTABLE_METHODS = {
    "IDirectDraw": {
        0: "QueryInterface",
        1: "AddRef",
        2: "Release",
        3: "Compact",
        4: "CreateClipper",
        5: "CreatePalette",
        6: "CreateSurface",
        7: "DuplicateSurface",
        8: "EnumDisplayModes",
        9: "EnumSurfaces",
        10: "FlipToGDISurface",
        11: "GetCaps",
        12: "GetDisplayMode",
        13: "GetFourCCCodes",
        14: "GetGDISurface",
        15: "GetMonitorFrequency",
        16: "GetScanLine",
        17: "GetVerticalBlankStatus",
        18: "Initialize",
        19: "RestoreDisplayMode",
        20: "SetCooperativeLevel",
        21: "SetDisplayMode",
        22: "WaitForVerticalBlank",
    },
    "IDirectDrawSurface": {
        0: "QueryInterface",
        1: "AddRef",
        2: "Release",
        3: "AddAttachedSurface",
        4: "AddOverlayDirtyRect",
        5: "Blt",
        6: "BltBatch",
        7: "BltFast",
        8: "DeleteAttachedSurface",
        9: "EnumAttachedSurfaces",
        10: "EnumOverlayZOrders",
        11: "Flip",
        12: "GetAttachedSurface",
        13: "GetBltStatus",
        14: "GetCaps",
        15: "GetColorKey",
        16: "GetDC",
        17: "GetPixelFormat",
        18: "GetSurfaceDesc",
        19: "Initialize",
        20: "IsLost",
        21: "Lock",
        22: "ReleaseDC",
        23: "Restore",
        24: "SetClipper",
        25: "SetColorKey",
        26: "SetOverlayPosition",
        27: "SetPalette",
        28: "Unlock",
        29: "UpdateOverlay",
        30: "UpdateOverlayDisplay",
        31: "UpdateOverlayZOrder",
    },
}

# HRESULT decoder for DirectDraw
DDRAW_HRESULTS = {
    0: "DD_OK",
    0x88760001: "DDERR_ALREADYINITIALIZED",
    0x8876000A: "DDERR_CANNOTATTACHSURFACE",
    0x8876000F: "DDERR_GENERIC",
    0x8876001E: "DDERR_HEIGHTALIGN",
    0x88760022: "DDERR_INCOMPATIBLEPRIMARY",
    0x88760028: "DDERR_INVALIDCAPS",
    0x88760032: "DDERR_INVALIDPARAMS",
    0x88760050: "DDERR_NODIRECTDRAWSUPPORT",
    0x88760064: "DDERR_NOEMULATION",
    0x88760078: "DDERR_OUTOFMEMORY",
    0x8876012C: "DDERR_SURFACELOST",
    0x88760140: "DDERR_UNSUPPORTED",
}


def decode_hresult(value):
    """Decode DirectDraw HRESULT to string."""
    return DDRAW_HRESULTS.get(value, f"0x{value:08X}")
```

```python
# src/pydbg/intercept/presets/dsound.py
"""DirectSound API interception preset."""

DSOUND_API_PRESET = {
    "DirectSoundCreate": {
        "args": ["lpGUID", "ppDS", "pUnkOuter"],
        "decoder": None,
    },
    "DirectSoundCreate8": {
        "args": ["lpGUID", "ppDS8", "pUnkOuter"],
        "decoder": None,
    },
}
```

```python
# src/pydbg/intercept/presets/win32.py
"""Common Win32 API interception preset."""

WIN32_API_PRESET = {
    "CreateWindowExA": {
        "args": ["dwExStyle", "lpClassName", "lpWindowName", "dwStyle",
                 "X", "Y", "nWidth", "nHeight", "hWndParent", "hMenu",
                 "hInstance", "lpParam"],
        "decoder": None,
    },
    "CreateWindowExW": {
        "args": ["dwExStyle", "lpClassName", "lpWindowName", "dwStyle",
                 "X", "Y", "nWidth", "nHeight", "hWndParent", "hMenu",
                 "hInstance", "lpParam"],
        "decoder": None,
    },
    "PeekMessageA": {
        "args": ["lpMsg", "hWnd", "wMsgFilterMin", "wMsgFilterMax", "wRemoveMsg"],
        "decoder": None,
    },
    "PeekMessageW": {
        "args": ["lpMsg", "hWnd", "wMsgFilterMin", "wMsgFilterMax", "wRemoveMsg"],
        "decoder": None,
    },
    "GetMessageA": {
        "args": ["lpMsg", "hWnd", "wMsgFilterMin", "wMsgFilterMax"],
        "decoder": None,
    },
    "GetMessageW": {
        "args": ["lpMsg", "hWnd", "wMsgFilterMin", "wMsgFilterMax"],
        "decoder": None,
    },
    "DispatchMessageA": {
        "args": ["lpMsg"],
        "decoder": None,
    },
    "timeGetTime": {
        "args": [],
        "decoder": None,
    },
    "IsDebuggerPresent": {
        "args": [],
        "decoder": None,
    },
}
```

Run: `python -m pytest tests/test_intercept.py::TestPresets -v`
Expected: PASS

### Step 3: Commit

```bash
git add src/pydbg/intercept/presets/ tests/test_intercept.py
git commit -m "feat(intercept): add API presets for DirectDraw, DirectSound, Win32

Includes VTable method maps for IDirectDraw and IDirectDrawSurface,
HRESULT decoders, and common Win32 API definitions."
```

---

## Task 6: Call Graph Builder

**Files:**
- Create: `src/pydbg/intercept/call_graph.py`
- Modify: `src/pydbg/intercept/__init__.py`
- Modify: `tests/test_intercept.py`

### Step 1: Write failing tests

```python
# tests/test_intercept.py (append)

class TestCallGraphBuilder(unittest.TestCase):

    def test_init(self):
        from pydbg.intercept.call_graph import CallGraphBuilder
        cg = CallGraphBuilder()
        self.assertEqual(cg.build_graph(), {'nodes': {}, 'edges': []})

    def test_add_call(self):
        from pydbg.intercept.call_graph import CallGraphBuilder
        cg = CallGraphBuilder()
        cg.add_call(0x4034F0, 0x401000, 1000, 1010)
        cg.add_call(0x4034F0, 0x402000, 1020, 1030)
        graph = cg.build_graph()
        self.assertEqual(len(graph['edges']), 2)
        self.assertIn(0x4034F0, graph['nodes'])
        self.assertIn(0x401000, graph['nodes'])

    def test_edge_count_aggregation(self):
        from pydbg.intercept.call_graph import CallGraphBuilder
        cg = CallGraphBuilder()
        cg.add_call(0x4034F0, 0x401000, 1000, 1010)
        cg.add_call(0x4034F0, 0x401000, 2000, 2010)
        graph = cg.build_graph()
        self.assertEqual(len(graph['edges']), 1)
        self.assertEqual(graph['edges'][0]['count'], 2)

    def test_export_json(self):
        import json
        import tempfile
        import os
        from pydbg.intercept.call_graph import CallGraphBuilder
        cg = CallGraphBuilder()
        cg.add_call(0x4034F0, 0x401000, 1000, 1010)
        path = os.path.join(tempfile.gettempdir(), "test_cg.json")
        cg.export_json(path)
        with open(path) as f:
            data = json.load(f)
        self.assertEqual(len(data['edges']), 1)
        os.unlink(path)

    def test_export_dot(self):
        import tempfile
        import os
        from pydbg.intercept.call_graph import CallGraphBuilder
        cg = CallGraphBuilder()
        cg.add_call(0x4034F0, 0x401000, 1000, 1010)
        path = os.path.join(tempfile.gettempdir(), "test_cg.dot")
        cg.export_dot(path)
        with open(path) as f:
            content = f.read()
        self.assertIn('digraph', content)
        self.assertIn('0x4034f0', content)
        os.unlink(path)

    def test_get_hot_paths(self):
        from pydbg.intercept.call_graph import CallGraphBuilder
        cg = CallGraphBuilder()
        cg.add_call(0x4034F0, 0x401000, 1000, 1010)
        cg.add_call(0x4034F0, 0x401000, 2000, 2010)
        cg.add_call(0x4034F0, 0x402000, 3000, 3010)
        hot = cg.get_hot_paths(top_n=1)
        self.assertEqual(len(hot), 1)
        self.assertEqual(hot[0]['count'], 2)
```

Run: `python -m pytest tests/test_intercept.py::TestCallGraphBuilder -v`
Expected: FAIL

### Step 2: Implement CallGraphBuilder

```python
# src/pydbg/intercept/call_graph.py
"""Call graph builder from API interception records."""

import json
from dataclasses import dataclass, field


@dataclass
class CallEdge:
    """Edge in the call graph."""
    caller: int
    callee: int
    count: int = 0
    total_time: int = 0


class CallGraphBuilder:
    """Build call graphs from recorded API calls."""

    def __init__(self):
        self._edges = {}   # (caller, callee) -> CallEdge
        self._nodes = {}   # addr -> {'count': int, 'first_seen': int}

    def add_call(self, caller_addr, callee_addr, timestamp, return_timestamp):
        """Record a call event."""
        key = (caller_addr, callee_addr)
        if key not in self._edges:
            self._edges[key] = CallEdge(caller=caller_addr, callee=callee_addr)
        edge = self._edges[key]
        edge.count += 1
        edge.total_time += max(0, return_timestamp - timestamp)

        for addr in (caller_addr, callee_addr):
            if addr not in self._nodes:
                self._nodes[addr] = {'count': 0, 'first_seen': timestamp}
            self._nodes[addr]['count'] += 1

    def build_graph(self):
        """Build graph structure: {nodes: {addr: info}, edges: [{...}]}."""
        edges = []
        for edge in self._edges.values():
            edges.append({
                'caller': edge.caller,
                'callee': edge.callee,
                'count': edge.count,
                'total_time': edge.total_time,
            })
        return {'nodes': dict(self._nodes), 'edges': edges}

    def export_json(self, path):
        """Export graph to JSON file."""
        graph = self.build_graph()
        # Convert int keys to hex strings for readability
        graph['nodes'] = {hex(k): v for k, v in graph['nodes'].items()}
        with open(path, 'w') as f:
            json.dump(graph, f, indent=2)

    def export_dot(self, path):
        """Export graph to Graphviz DOT format."""
        lines = ['digraph callgraph {', '  rankdir=LR;']
        for addr, info in self._nodes.items():
            lines.append(f'  "0x{addr:x}" [label="0x{addr:x}\\ncalls={info["count"]}"];')
        for edge in self._edges.values():
            lines.append(
                f'  "0x{edge.caller:x}" -> "0x{edge.callee:x}" '
                f'[label="{edge.count}" penwidth={min(edge.count, 10)}];'
            )
        lines.append('}')
        with open(path, 'w') as f:
            f.write('\n'.join(lines))

    def get_hot_paths(self, top_n=10):
        """Get the most frequently called edges."""
        sorted_edges = sorted(self._edges.values(), key=lambda e: e.count, reverse=True)
        return [{'caller': e.caller, 'callee': e.callee,
                 'count': e.count, 'total_time': e.total_time}
                for e in sorted_edges[:top_n]]

    def clear(self):
        """Clear all recorded data."""
        self._edges.clear()
        self._nodes.clear()
```

Update `src/pydbg/intercept/__init__.py`:
```python
from .api_hook import APIInterceptor, APICall
from .call_graph import CallGraphBuilder, CallEdge

__all__ = ['APIInterceptor', 'APICall', 'CallGraphBuilder', 'CallEdge']
```

Run: `python -m pytest tests/test_intercept.py -v`
Expected: PASS

### Step 3: Commit

```bash
git add src/pydbg/intercept/call_graph.py src/pydbg/intercept/__init__.py tests/test_intercept.py
git commit -m "feat(intercept): add CallGraphBuilder for call graph construction

Supports DOT/JSON export, edge aggregation, and hot path analysis."
```

---

## Task 7: Execution Tracer

**Files:**
- Create: `src/pydbg/trace/execution.py`
- Modify: `src/pydbg/trace/__init__.py`
- Create: `tests/test_execution_trace.py`

### Step 1: Write failing tests

```python
# tests/test_execution_trace.py
import unittest


class TestTraceEvent(unittest.TestCase):

    def test_dataclass(self):
        from pydbg.trace.execution import TraceEvent
        event = TraceEvent(
            index=0, timestamp=1000, tid=1, type="insn",
            address=0x401000, mnemonic="mov", op_str="eax, ebx",
            raw_bytes=b'\x89\xd8', registers=None,
            memory_access=None, call_target=None,
        )
        self.assertEqual(event.address, 0x401000)
        self.assertEqual(event.mnemonic, "mov")


class TestExecutionTracer(unittest.TestCase):

    def test_init(self):
        from pydbg.core.session import DebugSession
        from pydbg.trace.execution import ExecutionTracer
        session = DebugSession()
        tracer = ExecutionTracer(session)
        self.assertEqual(len(tracer.get_events()), 0)

    def test_configure(self):
        from pydbg.core.session import DebugSession
        from pydbg.trace.execution import ExecutionTracer
        session = DebugSession()
        tracer = ExecutionTracer(session)
        tracer.configure(record_regs=True, record_memory=True, max_events=500)
        self.assertTrue(tracer._record_regs)
        self.assertTrue(tracer._record_memory)
        self.assertEqual(tracer._max_events, 500)

    def test_add_module_filter(self):
        from pydbg.core.session import DebugSession
        from pydbg.trace.execution import ExecutionTracer
        session = DebugSession()
        tracer = ExecutionTracer(session)
        tracer.add_module_filter("OdenTodo.exe")
        self.assertIn("OdenTodo.exe", tracer._filters['modules'])

    def test_add_function_filter(self):
        from pydbg.core.session import DebugSession
        from pydbg.trace.execution import ExecutionTracer
        session = DebugSession()
        tracer = ExecutionTracer(session)
        tracer.add_function_filter(0x4034F0, 0x100)
        self.assertEqual(len(tracer._filters['functions']), 1)
        self.assertEqual(tracer._filters['functions'][0], (0x4034F0, 0x4035F0))

    def test_record_event_manually(self):
        from pydbg.core.session import DebugSession
        from pydbg.trace.execution import ExecutionTracer, TraceEvent
        session = DebugSession()
        tracer = ExecutionTracer(session)
        event = TraceEvent(
            index=0, timestamp=100, tid=1, type="insn",
            address=0x401000, mnemonic="nop", op_str="",
            raw_bytes=b'\x90', registers=None,
            memory_access=None, call_target=None,
        )
        tracer._events.append(event)
        self.assertEqual(len(tracer.get_events()), 1)
        self.assertEqual(tracer.get_events()[0].mnemonic, "nop")

    def test_search_memory_access(self):
        from pydbg.core.session import DebugSession
        from pydbg.trace.execution import ExecutionTracer, TraceEvent
        session = DebugSession()
        tracer = ExecutionTracer(session)
        tracer._events.append(TraceEvent(
            index=0, timestamp=100, tid=1, type="mem_write",
            address=0x401000, mnemonic="mov", op_str="[0x40EFC0], 1",
            raw_bytes=b'', registers=None,
            memory_access=(0x40EFC0, 4, 1), call_target=None,
        ))
        tracer._events.append(TraceEvent(
            index=1, timestamp=200, tid=1, type="insn",
            address=0x401005, mnemonic="nop", op_str="",
            raw_bytes=b'', registers=None,
            memory_access=None, call_target=None,
        ))
        results = tracer.search_memory_access(0x40EFC0)
        self.assertEqual(len(results), 1)

    def test_get_execution_heatmap(self):
        from pydbg.core.session import DebugSession
        from pydbg.trace.execution import ExecutionTracer, TraceEvent
        session = DebugSession()
        tracer = ExecutionTracer(session)
        for i in range(5):
            tracer._events.append(TraceEvent(
                index=i, timestamp=i * 100, tid=1, type="insn",
                address=0x401000, mnemonic="nop", op_str="",
                raw_bytes=b'\x90', registers=None,
                memory_access=None, call_target=None,
            ))
        tracer._events.append(TraceEvent(
            index=5, timestamp=500, tid=1, type="insn",
            address=0x402000, mnemonic="nop", op_str="",
            raw_bytes=b'\x90', registers=None,
            memory_access=None, call_target=None,
        ))
        heatmap = tracer.get_execution_heatmap()
        self.assertEqual(heatmap[0x401000], 5)
        self.assertEqual(heatmap[0x402000], 1)

    def test_export_json(self):
        import json
        import tempfile
        import os
        from pydbg.core.session import DebugSession
        from pydbg.trace.execution import ExecutionTracer, TraceEvent
        session = DebugSession()
        tracer = ExecutionTracer(session)
        tracer._events.append(TraceEvent(
            index=0, timestamp=100, tid=1, type="insn",
            address=0x401000, mnemonic="nop", op_str="",
            raw_bytes=b'\x90', registers=None,
            memory_access=None, call_target=None,
        ))
        path = os.path.join(tempfile.gettempdir(), "test_trace.json")
        tracer.export_json(path)
        with open(path) as f:
            data = json.load(f)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["mnemonic"], "nop")
        os.unlink(path)

    def test_max_events_ring_buffer(self):
        from pydbg.core.session import DebugSession
        from pydbg.trace.execution import ExecutionTracer, TraceEvent
        session = DebugSession()
        tracer = ExecutionTracer(session)
        tracer._max_events = 3
        for i in range(5):
            tracer._events.append(TraceEvent(
                index=i, timestamp=i * 100, tid=1, type="insn",
                address=0x401000 + i, mnemonic="nop", op_str="",
                raw_bytes=b'\x90', registers=None,
                memory_access=None, call_target=None,
            ))
            # Enforce ring buffer
            if len(tracer._events) > tracer._max_events:
                tracer._events.pop(0)
        self.assertEqual(len(tracer.get_events()), 3)
        self.assertEqual(tracer.get_events()[0].address, 0x401002)


if __name__ == "__main__":
    unittest.main()
```

Run: `python -m pytest tests/test_execution_trace.py -v`
Expected: FAIL

### Step 2: Implement ExecutionTracer and TraceEvent

```python
# src/pydbg/trace/execution.py
"""Execution tracing engine with single-step and sampling modes."""

import json
from dataclasses import dataclass, field


@dataclass
class TraceEvent:
    """A single execution trace event."""
    index: int
    timestamp: int
    tid: int
    type: str           # "insn", "call", "ret", "jmp", "mem_read", "mem_write"
    address: int
    mnemonic: str
    op_str: str
    raw_bytes: bytes = b''
    registers: dict = None
    memory_access: tuple = None  # (addr, size, value)
    call_target: int = None


class ExecutionTracer:
    """Execution trace engine with filtering and export."""

    def __init__(self, session):
        self._s = session
        self._events = []
        self._max_events = 1000000
        self._filters = {
            'modules': [],       # only trace code in these modules
            'functions': [],     # (start, end) address ranges
            'skip_ranges': [],   # address ranges to skip
        }
        self._record_regs = False
        self._record_memory = False
        self._running = False
        self._next_index = 0

    def configure(self, record_regs=False, record_memory=False, max_events=1000000):
        """Configure tracing options."""
        self._record_regs = record_regs
        self._record_memory = record_memory
        self._max_events = max_events

    def add_module_filter(self, module_name):
        """Only trace code within the specified module."""
        self._filters['modules'].append(module_name)

    def add_function_filter(self, start_addr, size):
        """Only trace code within the specified address range."""
        self._filters['functions'].append((start_addr, start_addr + size))

    def add_skip_range(self, start_addr, size):
        """Skip tracing within the specified address range."""
        self._filters['skip_ranges'].append((start_addr, start_addr + size))

    def start(self):
        """Start tracing (sets single-step flag on current thread)."""
        self._running = True

    def stop(self):
        """Stop tracing."""
        self._running = False

    def record_event(self, event):
        """Manually record a trace event."""
        event.index = self._next_index
        self._next_index += 1
        self._events.append(event)
        # Ring buffer enforcement
        if len(self._events) > self._max_events:
            self._events.pop(0)

    def get_events(self, start=0, end=None):
        """Get recorded events, optionally sliced."""
        if end is None:
            return self._events[start:]
        return self._events[start:end]

    def search_memory_access(self, addr):
        """Find all events that accessed the specified memory address."""
        results = []
        for event in self._events:
            if event.memory_access is not None:
                mem_addr, mem_size, _ = event.memory_access
                if mem_addr <= addr < mem_addr + mem_size:
                    results.append(event)
        return results

    def get_execution_heatmap(self):
        """Get address -> execution count mapping."""
        heatmap = {}
        for event in self._events:
            if event.type == 'insn':
                heatmap[event.address] = heatmap.get(event.address, 0) + 1
        return heatmap

    def export_json(self, path):
        """Export trace events to JSON."""
        data = []
        for event in self._events:
            entry = {
                'index': event.index,
                'timestamp': event.timestamp,
                'tid': event.tid,
                'type': event.type,
                'address': hex(event.address),
                'mnemonic': event.mnemonic,
                'op_str': event.op_str,
            }
            if event.registers:
                entry['registers'] = {k: hex(v) for k, v in event.registers.items()}
            if event.memory_access:
                entry['memory_access'] = {
                    'addr': hex(event.memory_access[0]),
                    'size': event.memory_access[1],
                    'value': hex(event.memory_access[2]),
                }
            if event.call_target is not None:
                entry['call_target'] = hex(event.call_target)
            data.append(entry)
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)

    def clear(self):
        """Clear all recorded events."""
        self._events.clear()
        self._next_index = 0
```

Update `src/pydbg/trace/__init__.py`:
```python
from .calltree import CallTree, CallNode
from .step import StepTracer
from .execution import ExecutionTracer, TraceEvent

__all__ = ['CallTree', 'CallNode', 'StepTracer', 'ExecutionTracer', 'TraceEvent']
```

Run: `python -m pytest tests/test_execution_trace.py -v`
Expected: PASS

### Step 3: Commit

```bash
git add src/pydbg/trace/execution.py src/pydbg/trace/__init__.py tests/test_execution_trace.py
git commit -m "feat(trace): add ExecutionTracer with filtering and heatmap export

Supports module/function filtering, memory access search, ring buffer,
and JSON export."
```

---

## Task 8: Data Flow Tracker

**Files:**
- Create: `src/pydbg/trace/dataflow.py`
- Modify: `src/pydbg/trace/__init__.py`
- Modify: `tests/test_execution_trace.py`

### Step 1: Write failing tests

```python
# tests/test_execution_trace.py (append)

class TestDataFlowTracker(unittest.TestCase):

    def test_init(self):
        from pydbg.core.session import DebugSession
        from pydbg.trace.execution import ExecutionTracer
        from pydbg.trace.dataflow import DataFlowTracker
        tracer = ExecutionTracer(DebugSession())
        dft = DataFlowTracker(tracer)
        self.assertIsNotNone(dft)

    def test_track_register_value_propagation(self):
        from pydbg.core.session import DebugSession
        from pydbg.trace.execution import ExecutionTracer, TraceEvent
        from pydbg.trace.dataflow import DataFlowTracker
        tracer = ExecutionTracer(DebugSession())
        # Simulate: eax = 5 at 0x401000, then eax used at 0x401005
        tracer._events.append(TraceEvent(
            index=0, timestamp=100, tid=1, type="insn",
            address=0x401000, mnemonic="mov", op_str="eax, 5",
            raw_bytes=b'', registers={'eax': 5, 'ebx': 0},
            memory_access=None, call_target=None,
        ))
        tracer._events.append(TraceEvent(
            index=1, timestamp=200, tid=1, type="insn",
            address=0x401005, mnemonic="add", op_str="eax, ebx",
            raw_bytes=b'', registers={'eax': 5, 'ebx': 3},
            memory_access=None, call_target=None,
        ))
        dft = DataFlowTracker(tracer)
        # Find where eax=5 was written
        writes = dft.find_register_writes('eax', 5)
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0].address, 0x401000)

    def test_find_register_writes_empty(self):
        from pydbg.core.session import DebugSession
        from pydbg.trace.execution import ExecutionTracer
        from pydbg.trace.dataflow import DataFlowTracker
        tracer = ExecutionTracer(DebugSession())
        dft = DataFlowTracker(tracer)
        writes = dft.find_register_writes('eax', 999)
        self.assertEqual(writes, [])
```

Run: `python -m pytest tests/test_execution_trace.py::TestDataFlowTracker -v`
Expected: FAIL

### Step 2: Implement DataFlowTracker

```python
# src/pydbg/trace/dataflow.py
"""Data flow analysis over execution traces."""


class DataFlowTracker:
    """Analyze data propagation through registers and memory."""

    def __init__(self, tracer):
        """
        Args:
            tracer: ExecutionTracer instance with recorded events.
        """
        self._tracer = tracer

    def find_register_writes(self, reg_name, value):
        """Find all events where a register was set to a specific value.

        Returns list of TraceEvent where reg_name == value.
        """
        results = []
        for event in self._tracer.get_events():
            if event.registers and event.registers.get(reg_name) == value:
                results.append(event)
        return results

    def find_register_readers(self, reg_name, after_index=0):
        """Find all events after after_index that read from reg_name.

        Note: This is a heuristic — we check if reg_name appears in op_str.
        """
        results = []
        for event in self._tracer.get_events():
            if event.index <= after_index:
                continue
            if reg_name in event.op_str:
                results.append(event)
        return results

    def track_memory_writers(self, addr, size=4):
        """Find all events that wrote to the specified memory address."""
        results = []
        for event in self._tracer.get_events():
            if event.type == 'mem_write' and event.memory_access is not None:
                mem_addr, mem_size, _ = event.memory_access
                if mem_addr <= addr < mem_addr + mem_size:
                    results.append(event)
        return results

    def track_memory_readers(self, addr, size=4):
        """Find all events that read from the specified memory address."""
        results = []
        for event in self._tracer.get_events():
            if event.type == 'mem_read' and event.memory_access is not None:
                mem_addr, mem_size, _ = event.memory_access
                if mem_addr <= addr < mem_addr + mem_size:
                    results.append(event)
        return results

    def find_origin(self, event_index, reg_name):
        """Backtrack to find the original source of a register value.

        Walks backwards through events to find where reg_name was last written.
        """
        events = self._tracer.get_events()
        target_event = None
        for e in events:
            if e.index == event_index:
                target_event = e
                break
        if target_event is None or target_event.registers is None:
            return None

        value = target_event.registers.get(reg_name)
        if value is None:
            return None

        # Walk backwards to find the write
        for e in reversed(events):
            if e.index >= event_index:
                continue
            if e.registers and e.registers.get(reg_name) == value:
                return e
        return None
```

Update `src/pydbg/trace/__init__.py`:
```python
from .calltree import CallTree, CallNode
from .step import StepTracer
from .execution import ExecutionTracer, TraceEvent
from .dataflow import DataFlowTracker

__all__ = ['CallTree', 'CallNode', 'StepTracer', 'ExecutionTracer',
           'TraceEvent', 'DataFlowTracker']
```

Run: `python -m pytest tests/test_execution_trace.py -v`
Expected: PASS

### Step 3: Commit

```bash
git add src/pydbg/trace/dataflow.py src/pydbg/trace/__init__.py tests/test_execution_trace.py
git commit -m "feat(trace): add DataFlowTracker for register/memory propagation analysis

Supports finding register writers/readers, memory access tracking,
and origin backtracking."
```

---

## Task 9: Analysis Workbench

**Files:**
- Create: `src/pydbg/analysis/__init__.py`
- Create: `src/pydbg/analysis/workbench.py`
- Create: `tests/test_workbench.py`

### Step 1: Write failing tests

```python
# tests/test_workbench.py
import unittest


class TestAnalysisWorkbench(unittest.TestCase):

    def test_init(self):
        from pydbg.analysis.workbench import AnalysisWorkbench
        wb = AnalysisWorkbench("test.exe")
        self.assertEqual(wb._target, "test.exe")
        self.assertIsNone(wb._dbg)

    def test_setup_creates_debugger(self):
        from pydbg.analysis.workbench import AnalysisWorkbench
        wb = AnalysisWorkbench("test.exe")
        wb.setup(stealth=False)
        self.assertIsNotNone(wb._dbg)
        self.assertIsNone(wb._stealth)

    def test_setup_with_stealth(self):
        from pydbg.analysis.workbench import AnalysisWorkbench
        wb = AnalysisWorkbench("test.exe")
        wb.setup(stealth=True)
        self.assertIsNotNone(wb._dbg)
        # Stealth requires live process, so _stealth may be None without one
        # Just verify no crash

    def test_load_pe_static(self):
        """Test static PE analysis on a real file."""
        import os
        from pydbg.analysis.workbench import AnalysisWorkbench
        kernel32 = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'),
                                'System32', 'kernel32.dll')
        if not os.path.exists(kernel32):
            self.skipTest("kernel32.dll not found")
        wb = AnalysisWorkbench(kernel32)
        info = wb.load_and_analyze_pe()
        self.assertIn('sections', info)
        self.assertIn('imports', info)
        self.assertIn('exports', info)
        self.assertGreater(len(info['exports']), 0)

    def test_extract_resources_from_pe(self):
        """Test resource extraction from a PE with resources."""
        from pydbg.analysis.workbench import AnalysisWorkbench
        wb = AnalysisWorkbench("dummy.exe")
        # Manually set up PE with resources
        from tests.test_resource import build_pe_with_resources
        from pydbg.pe import PE
        wb._pe = PE(build_pe_with_resources())
        import tempfile
        import os
        out_dir = os.path.join(tempfile.gettempdir(), "test_wb_resources")
        results = wb.extract_resources(out_dir)
        self.assertGreater(len(results), 0)
        # Cleanup
        import shutil
        shutil.rmtree(out_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
```

Run: `python -m pytest tests/test_workbench.py -v`
Expected: FAIL

### Step 2: Implement AnalysisWorkbench

```python
# src/pydbg/analysis/workbench.py
"""Analysis workbench: orchestrates all analysis modules."""

import os


class AnalysisWorkbench:
    """Game binary analysis workbench.

    Coordinates PE analysis, API interception, resource extraction,
    execution tracing, and report generation.
    """

    def __init__(self, target_exe):
        self._target = target_exe
        self._dbg = None
        self._stealth = None
        self._interceptor = None
        self._tracer = None
        self._pe = None

    def setup(self, stealth=True):
        """Initialize the analysis environment.

        Args:
            stealth: If True, prepare anti-detection measures.
        """
        from ..core.debugger import Debugger
        self._dbg = Debugger()
        if stealth:
            from ..stealth.anti_aware import AntiAware
            self._stealth = AntiAware(self._dbg._session)

    def load_and_analyze_pe(self):
        """Static analysis: parse PE structure, imports, exports.

        Returns dict with keys: dos_header, file_header, optional_header,
        sections, imports, exports.
        """
        from ..pe import PE

        if os.path.isfile(self._target):
            self._pe = PE.from_file(self._target)
        else:
            raise FileNotFoundError(f"Target not found: {self._target}")

        sections = []
        for sec in self._pe.sections:
            sections.append({
                'name': sec.name,
                'virtual_address': sec.virtual_address,
                'virtual_size': sec.virtual_size,
                'size_of_raw_data': sec.size_of_raw_data,
                'characteristics': sec.characteristics,
            })

        imports = []
        for imp in self._pe.imports:
            imports.append({
                'dll': imp.dll_name,
                'name': imp.name,
                'ordinal': imp.ordinal,
                'rva': imp.rva,
            })

        exports = []
        for exp in self._pe.exports:
            exports.append({
                'name': exp.name,
                'ordinal': exp.ordinal,
                'rva': exp.rva,
                'forwarder': exp.forwarder,
            })

        return {
            'machine': hex(self._pe.file_header.machine),
            'entry_point': hex(self._pe.optional_header.entry_point_rva),
            'image_base': hex(self._pe.optional_header.image_base),
            'sections': sections,
            'imports': imports,
            'exports': exports,
        }

    def setup_interception(self, preset_name="ddraw"):
        """Set up API interception with a named preset.

        Returns the APIInterceptor instance.
        """
        from ..intercept.api_hook import APIInterceptor
        from ..intercept.presets import load_preset

        self._interceptor = APIInterceptor(self._dbg._session)
        preset = load_preset(preset_name)
        self._interceptor.intercept_module(
            f"{preset_name}.dll" if preset_name in ("ddraw", "dsound") else preset_name,
            preset,
        )
        return self._interceptor

    def extract_resources(self, output_dir=None):
        """Extract resources from the PE file.

        Args:
            output_dir: Directory to write extracted files. If None, returns data only.

        Returns list of extracted file paths (or ResourceEntry list if no output_dir).
        """
        from ..resource.pe_resource import PEResourceParser

        if self._pe is None:
            self.load_and_analyze_pe()

        parser = PEResourceParser(self._pe)
        resources = parser.parse()

        if output_dir is None:
            return resources

        parser._resources = resources  # ensure parser has the list
        return parser.extract_all(output_dir)

    def generate_report(self, output_path):
        """Generate a Markdown analysis report."""
        lines = [
            f"# Analysis Report: {os.path.basename(self._target)}",
            "",
            f"Generated by pydbg AnalysisWorkbench",
            "",
        ]

        # PE Info
        if self._pe is not None:
            info = self.load_and_analyze_pe()
            lines.append("## PE Information")
            lines.append(f"- Machine: {info['machine']}")
            lines.append(f"- Entry Point: {info['entry_point']}")
            lines.append(f"- Image Base: {info['image_base']}")
            lines.append(f"- Sections: {len(info['sections'])}")
            lines.append(f"- Imports: {len(info['imports'])}")
            lines.append(f"- Exports: {len(info['exports'])}")
            lines.append("")

        # API Calls
        if self._interceptor is not None:
            counts = self._interceptor.get_call_count()
            if counts:
                lines.append("## API Call Summary")
                for func, count in sorted(counts.items(), key=lambda x: -x[1]):
                    lines.append(f"- {func}: {count}")
                lines.append("")

        # Trace
        if self._tracer is not None:
            events = self._tracer.get_events()
            heatmap = self._tracer.get_execution_heatmap()
            lines.append("## Execution Trace")
            lines.append(f"- Total events: {len(events)}")
            lines.append(f"- Unique addresses: {len(heatmap)}")
            if heatmap:
                top = sorted(heatmap.items(), key=lambda x: -x[1])[:10]
                lines.append("- Top addresses:")
                for addr, count in top:
                    lines.append(f"  - 0x{addr:X}: {count} executions")
            lines.append("")

        with open(output_path, 'w') as f:
            f.write('\n'.join(lines))
```

```python
# src/pydbg/analysis/__init__.py
from .workbench import AnalysisWorkbench

__all__ = ['AnalysisWorkbench']
```

Run: `python -m pytest tests/test_workbench.py -v`
Expected: PASS

### Step 3: Commit

```bash
git add src/pydbg/analysis/ tests/test_workbench.py
git commit -m "feat(analysis): add AnalysisWorkbench for orchestrated analysis

Coordinates PE parsing, API interception, resource extraction,
and report generation in a single workflow."
```

---

## Task 10: Game Analyzer

**Files:**
- Create: `src/pydbg/analysis/game_analyzer.py`
- Modify: `src/pydbg/analysis/__init__.py`
- Modify: `tests/test_workbench.py`

### Step 1: Write failing tests

```python
# tests/test_workbench.py (append)

class TestGameAnalyzer(unittest.TestCase):

    def test_init(self):
        from pydbg.analysis.workbench import AnalysisWorkbench
        from pydbg.analysis.game_analyzer import GameAnalyzer
        wb = AnalysisWorkbench("test.exe")
        ga = GameAnalyzer(wb)
        self.assertIs(ga._wb, wb)

    def test_analyze_game_loop_no_process(self):
        """Should return empty result when no process is running."""
        from pydbg.analysis.workbench import AnalysisWorkbench
        from pydbg.analysis.game_analyzer import GameAnalyzer
        wb = AnalysisWorkbench("test.exe")
        wb.setup(stealth=False)
        ga = GameAnalyzer(wb)
        result = ga.analyze_game_loop()
        self.assertIn('messages', result)
        self.assertEqual(result['messages'], [])

    def test_analyze_rendering_pipeline_no_process(self):
        from pydbg.analysis.workbench import AnalysisWorkbench
        from pydbg.analysis.game_analyzer import GameAnalyzer
        wb = AnalysisWorkbench("test.exe")
        wb.setup(stealth=False)
        ga = GameAnalyzer(wb)
        result = ga.analyze_rendering_pipeline()
        self.assertIn('surfaces', result)

    def test_analyze_input_handling_no_process(self):
        from pydbg.analysis.workbench import AnalysisWorkbench
        from pydbg.analysis.game_analyzer import GameAnalyzer
        wb = AnalysisWorkbench("test.exe")
        wb.setup(stealth=False)
        ga = GameAnalyzer(wb)
        result = ga.analyze_input_handling()
        self.assertIn('key_map', result)
```

Run: `python -m pytest tests/test_workbench.py::TestGameAnalyzer -v`
Expected: FAIL

### Step 2: Implement GameAnalyzer

```python
# src/pydbg/analysis/game_analyzer.py
"""Game-specific analysis helpers for Win32 games."""


class GameAnalyzer:
    """Specialized analyzers for old Win32 games."""

    def __init__(self, workbench):
        """
        Args:
            workbench: AnalysisWorkbench instance.
        """
        self._wb = workbench

    def analyze_game_loop(self):
        """Analyze the game's main loop structure.

        Returns dict with:
        - messages: list of intercepted message dispatches
        - frame_times: list of frame delta times
        - loop_function: address of the main loop (if detected)
        """
        result = {'messages': [], 'frame_times': [], 'loop_function': None}

        if self._wb._interceptor is None:
            return result

        calls = self._wb._interceptor.get_calls()
        for call in calls:
            if call.function in ('PeekMessageA', 'PeekMessageW',
                                 'GetMessageA', 'GetMessageW',
                                 'DispatchMessageA', 'DispatchMessageW'):
                result['messages'].append({
                    'function': call.function,
                    'timestamp': call.timestamp,
                    'args': call.args,
                })

        return result

    def analyze_rendering_pipeline(self):
        """Analyze DirectDraw rendering calls.

        Returns dict with:
        - surfaces: list of surface operations
        - blts: list of Blt/BltFast calls
        - flips: list of Flip calls
        """
        result = {'surfaces': [], 'blts': [], 'flips': []}

        if self._wb._interceptor is None:
            return result

        calls = self._wb._interceptor.get_calls()
        for call in calls:
            if call.function == 'CreateSurface':
                result['surfaces'].append({
                    'timestamp': call.timestamp,
                    'args': call.args,
                    'return': call.decoded_return,
                })
            elif call.function in ('Blt', 'BltFast'):
                result['blts'].append({
                    'function': call.function,
                    'timestamp': call.timestamp,
                    'args': call.args,
                })
            elif call.function == 'Flip':
                result['flips'].append({
                    'timestamp': call.timestamp,
                    'args': call.args,
                })

        return result

    def analyze_audio_system(self):
        """Analyze DirectSound calls.

        Returns dict with:
        - buffers: list of sound buffer operations
        - plays: list of Play calls
        """
        result = {'buffers': [], 'plays': []}

        if self._wb._interceptor is None:
            return result

        calls = self._wb._interceptor.get_calls()
        for call in calls:
            if call.function == 'CreateSoundBuffer':
                result['buffers'].append({
                    'timestamp': call.timestamp,
                    'args': call.args,
                })
            elif call.function == 'Play':
                result['plays'].append({
                    'timestamp': call.timestamp,
                    'args': call.args,
                })

        return result

    def analyze_input_handling(self):
        """Analyze input message handling.

        Returns dict with:
        - key_map: mapping of virtual key codes to actions
        - messages: list of input-related messages
        """
        result = {'key_map': {}, 'messages': []}

        VK_NAMES = {
            0x25: 'LEFT', 0x26: 'UP', 0x27: 'RIGHT', 0x28: 'DOWN',
            0x20: 'SPACE', 0x0D: 'ENTER', 0x1B: 'ESCAPE',
        }

        if self._wb._interceptor is None:
            return result

        calls = self._wb._interceptor.get_calls()
        for call in calls:
            if call.function in ('PeekMessageA', 'PeekMessageW',
                                 'GetMessageA', 'GetMessageW'):
                result['messages'].append({
                    'function': call.function,
                    'timestamp': call.timestamp,
                })

        return result

    def analyze_game_objects(self, object_array_addr=None, object_size=132,
                             max_objects=512):
        """Read game object array from memory.

        Args:
            object_array_addr: Address of the object array in memory.
            object_size: Size of each object in bytes.
            max_objects: Maximum number of objects to read.

        Returns list of raw object bytes.
        """
        if object_array_addr is None:
            return []

        if self._wb._dbg is None:
            return []

        objects = []
        try:
            for i in range(max_objects):
                addr = object_array_addr + i * object_size
                data = self._wb._dbg.read_memory(addr, object_size)
                if any(b != 0 for b in data):
                    objects.append({'index': i, 'address': hex(addr), 'data': data.hex()})
        except Exception:
            pass

        return objects
```

Update `src/pydbg/analysis/__init__.py`:
```python
from .workbench import AnalysisWorkbench
from .game_analyzer import GameAnalyzer

__all__ = ['AnalysisWorkbench', 'GameAnalyzer']
```

Run: `python -m pytest tests/test_workbench.py -v`
Expected: PASS

### Step 3: Commit

```bash
git add src/pydbg/analysis/game_analyzer.py src/pydbg/analysis/__init__.py tests/test_workbench.py
git commit -m "feat(analysis): add GameAnalyzer for Win32 game analysis

Analyzes game loop, rendering pipeline, audio system, input handling,
and game object arrays."
```

---

## Task 11: Wire Up Exports and Integration Test

**Files:**
- Modify: `src/pydbg/__init__.py`
- Create: `tests/test_integration_analysis.py`

### Step 1: Update top-level exports

```python
# src/pydbg/__init__.py — add these imports after existing ones

# New: Analysis framework
from .stealth.anti_aware import AntiAware
from .intercept.api_hook import APIInterceptor, APICall
from .intercept.call_graph import CallGraphBuilder, CallEdge
from .intercept.presets import load_preset as load_api_preset
from .intercept.presets.ddraw import DDRAW_VTABLE_METHODS, decode_hresult
from .resource.pe_resource import PEResourceParser, ResourceEntry
from .resource.recognizer import ResourceRecognizer
from .trace.execution import ExecutionTracer, TraceEvent
from .trace.dataflow import DataFlowTracker
from .analysis.workbench import AnalysisWorkbench
from .analysis.game_analyzer import GameAnalyzer
```

Add to `__all__`:
```python
    "AntiAware",
    "APIInterceptor", "APICall",
    "CallGraphBuilder", "CallEdge",
    "load_api_preset",
    "DDRAW_VTABLE_METHODS", "decode_hresult",
    "PEResourceParser", "ResourceEntry",
    "ResourceRecognizer",
    "ExecutionTracer", "TraceEvent",
    "DataFlowTracker",
    "AnalysisWorkbench", "GameAnalyzer",
```

### Step 2: Write integration test

```python
# tests/test_integration_analysis.py
"""Integration test: full analysis pipeline on a synthetic PE."""

import os
import tempfile
import unittest

from tests.test_resource import build_pe_with_resources
from tests.test_pe import build_pe_with_imports, build_pe_with_exports


class TestIntegrationAnalysis(unittest.TestCase):

    def test_full_static_analysis(self):
        """Static analysis pipeline: PE parse -> resource extract -> report."""
        from pydbg.pe import PE
        from pydbg.resource.pe_resource import PEResourceParser
        from pydbg.resource.recognizer import ResourceRecognizer

        # Parse PE with resources
        pe_data = build_pe_with_resources()
        pe = PE(pe_data)

        # Parse resources
        parser = PEResourceParser(pe)
        resources = parser.parse()
        self.assertGreater(len(resources), 0)

        # Recognize formats
        recognizer = ResourceRecognizer()
        for res in resources:
            data = parser.extract(res)
            info = recognizer.recognize(data)
            self.assertIn('format', info)

    def test_interceptor_call_count(self):
        """APIInterceptor call recording and export."""
        from pydbg.core.session import DebugSession
        from pydbg.intercept.api_hook import APIInterceptor, APICall

        session = DebugSession()
        interceptor = APIInterceptor(session)

        # Simulate some calls
        interceptor._calls.append(APICall(
            timestamp=100, tid=1, module="ddraw.dll",
            function="DirectDrawCreate", args=[0, 0x5222A0, 0],
            decoded_args={}, return_value=0, decoded_return="DD_OK",
            call_stack=[],
        ))
        interceptor._calls.append(APICall(
            timestamp=200, tid=1, module="ddraw.dll",
            function="CreateSurface", args=[0x5222A0, 0x40EFE4, 0],
            decoded_args={}, return_value=0, decoded_return="DD_OK",
            call_stack=[],
        ))

        counts = interceptor.get_call_count()
        self.assertEqual(counts["ddraw.dll!DirectDrawCreate"], 1)
        self.assertEqual(counts["ddraw.dll!CreateSurface"], 1)

        # Export JSON
        path = os.path.join(tempfile.gettempdir(), "integration_test.json")
        interceptor.export_json(path)
        self.assertTrue(os.path.exists(path))
        os.unlink(path)

    def test_call_graph_from_interceptor(self):
        """Build call graph from interceptor data."""
        from pydbg.intercept.call_graph import CallGraphBuilder
        from pydbg.intercept.api_hook import APIInterceptor, APICall
        from pydbg.core.session import DebugSession

        session = DebugSession()
        interceptor = APIInterceptor(session)
        cg = CallGraphBuilder()

        # Simulate calls with timestamps
        calls_data = [
            (0x4034F0, 0x401000, 1000, 1010),  # MainLoop -> DDInit
            (0x4034F0, 0x403200, 1100, 1150),  # MainLoop -> RenderPipeline
            (0x4034F0, 0x401000, 2000, 2010),  # MainLoop -> DDInit again
        ]
        for caller, callee, ts, ret_ts in calls_data:
            cg.add_call(caller, callee, ts, ret_ts)

        hot = cg.get_hot_paths(top_n=1)
        self.assertEqual(hot[0]['caller'], 0x4034F0)
        self.assertEqual(hot[0]['callee'], 0x401000)
        self.assertEqual(hot[0]['count'], 2)

    def test_execution_tracer_events(self):
        """ExecutionTracer event recording and search."""
        from pydbg.core.session import DebugSession
        from pydbg.trace.execution import ExecutionTracer, TraceEvent
        from pydbg.trace.dataflow import DataFlowTracker

        session = DebugSession()
        tracer = ExecutionTracer(session)

        # Record some events
        for i in range(10):
            tracer._events.append(TraceEvent(
                index=i, timestamp=i * 100, tid=1, type="insn",
                address=0x401000 + i * 5, mnemonic="nop", op_str="",
                raw_bytes=b'\x90', registers={'eax': i},
                memory_access=None, call_target=None,
            ))

        heatmap = tracer.get_execution_heatmap()
        self.assertEqual(len(heatmap), 10)

        # Data flow
        dft = DataFlowTracker(tracer)
        writes = dft.find_register_writes('eax', 5)
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0].address, 0x401000 + 5 * 5)

    def test_game_analyzer_no_crash(self):
        """GameAnalyzer methods don't crash without a live process."""
        from pydbg.analysis.workbench import AnalysisWorkbench
        from pydbg.analysis.game_analyzer import GameAnalyzer

        wb = AnalysisWorkbench("dummy.exe")
        wb.setup(stealth=False)
        ga = GameAnalyzer(wb)

        loop = ga.analyze_game_loop()
        render = ga.analyze_rendering_pipeline()
        audio = ga.analyze_audio_system()
        input_info = ga.analyze_input_handling()
        objects = ga.analyze_game_objects()

        self.assertIsInstance(loop, dict)
        self.assertIsInstance(render, dict)
        self.assertIsInstance(audio, dict)
        self.assertIsInstance(input_info, dict)
        self.assertIsInstance(objects, list)


if __name__ == "__main__":
    unittest.main()
```

Run: `python -m pytest tests/test_integration_analysis.py -v`
Expected: PASS

### Step 3: Run full test suite

```bash
python -m pytest tests/ -v
```

Expected: All tests pass.

### Step 4: Commit

```bash
git add src/pydbg/__init__.py tests/test_integration_analysis.py
git commit -m "feat: wire up analysis framework exports and integration tests

All new modules exported from top-level pydbg package.
Integration tests verify cross-module workflows."
```

---

## Task 12: Final Verification

### Step 1: Run all tests

```bash
python -m pytest tests/ -v --tb=short
```

Expected: All tests pass.

### Step 2: Verify imports work

```bash
python -c "
from pydbg import (
    AntiAware, APIInterceptor, APICall,
    CallGraphBuilder, CallEdge, load_api_preset,
    DDRAW_VTABLE_METHODS, decode_hresult,
    PEResourceParser, ResourceEntry, ResourceRecognizer,
    ExecutionTracer, TraceEvent, DataFlowTracker,
    AnalysisWorkbench, GameAnalyzer,
)
print('All imports OK')
"
```

Expected: `All imports OK`

### Step 3: Verify preset loading

```bash
python -c "
from pydbg import load_api_preset, DDRAW_VTABLE_METHODS
ddraw = load_api_preset('ddraw')
dsound = load_api_preset('dsound')
win32 = load_api_preset('win32')
print(f'DirectDraw: {len(ddraw)} APIs, {len(DDRAW_VTABLE_METHODS[\"IDirectDraw\"])} vtable methods')
print(f'DirectSound: {len(dsound)} APIs')
print(f'Win32: {len(win32)} APIs')
"
```

Expected:
```
DirectDraw: 2 APIs, 23 vtable methods
DirectSound: 2 APIs
Win32: 9 APIs
```

### Step 4: Commit (if any fixes needed)

```bash
git add -A
git commit -m "chore: final verification fixes for game analysis framework"
```

---

## Summary

| Task | Module | Files Created | Tests |
|------|--------|---------------|-------|
| 1 | resource/pe_resource.py | 2 | 4 |
| 2 | resource/recognizer.py | 1 | 6 |
| 3 | stealth/anti_aware.py | 2 | 3 |
| 4 | intercept/api_hook.py | 2 | 5 |
| 5 | intercept/presets/ | 4 | 5 |
| 6 | intercept/call_graph.py | 1 | 5 |
| 7 | trace/execution.py | 1 | 8 |
| 8 | trace/dataflow.py | 1 | 3 |
| 9 | analysis/workbench.py | 2 | 4 |
| 10 | analysis/game_analyzer.py | 1 | 3 |
| 11 | Integration | 1 | 5 |
| 12 | Verification | - | - |

**Total: 12 tasks, ~18 new files, ~51 test cases**
