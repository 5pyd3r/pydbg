"""Deterministic PE image builder for parser tests.

The fixtures in test_pe.py re-emit the DOS, PE and optional headers byte by
byte for every case. That does not scale to five more data directories, so this
assembles a whole image from a section list plus a directory map instead.

Layout is chosen so that file offset == RVA for all section data: each section
is given pointer_to_raw_data equal to its own virtual address. FileView then
resolves an RVA to itself, which keeps the fixtures readable — a directory at
RVA 0x2000 is written at index 0x2000 of the built bytes. This is not how a
real linker lays out a file, and it does not need to be: these tests exercise
the directory parsers, and test_pe.py's own fixtures cover the header layouts.
"""

import struct

HEADERS_SIZE = 0x400
SECTION_ALIGN = 0x1000
OPTIONAL_HEADER_SIZE = {0x20B: 112, 0x10B: 96}
NUM_DATA_DIRECTORIES = 16


def section_header(name, rva, data, characteristics=0x60000020):
    """One IMAGE_SECTION_HEADER, laid out with raw offset == RVA."""
    return struct.pack(
        "<8sIIIIIIHHI",
        name.encode("ascii")[:8].ljust(8, b"\x00"),
        len(data),       # VirtualSize
        rva,             # VirtualAddress
        len(data),       # SizeOfRawData
        rva,             # PointerToRawData  (== RVA, see module docstring)
        0, 0, 0, 0,
        characteristics,
    )


class PEBuilder:
    """Assemble a minimal but structurally valid PE32/PE32+ image."""

    def __init__(self, magic=0x20B, image_base=0x140000000, entry_rva=0x1000):
        self.magic = magic
        self.image_base = image_base
        self.entry_rva = entry_rva
        self.machine = 0x8664 if magic == 0x20B else 0x14C
        self.sections = []          # (name, rva, data, characteristics)
        self.dirs = {}              # index -> (rva, size)
        self.rich = None            # raw bytes to drop in the DOS stub

    def add_section(self, name, data, rva, characteristics=0x60000020):
        self.sections.append((name, rva, bytes(data), characteristics))
        return rva

    def add_dir(self, index, rva, size):
        self.dirs[index] = (rva, size)
        return rva

    def set_rich(self, blob):
        self.rich = blob

    def _optional_header(self):
        oh = struct.pack("<HBB", self.magic, 14, 0)
        oh += struct.pack("<III", 0, 0, 0)              # SizeOfCode/Init/Uninit
        oh += struct.pack("<II", self.entry_rva, SECTION_ALIGN)
        if self.magic == 0x10B:
            oh += struct.pack("<I", SECTION_ALIGN)   # BaseOfData: PE32 only
        oh += struct.pack("<Q" if self.magic == 0x20B else "<I", self.image_base)
        oh += struct.pack("<II", SECTION_ALIGN, 0x200)
        oh += struct.pack("<HHHHHHI", 6, 0, 0, 0, 6, 0, 0)
        oh += struct.pack("<III", 0x8000, HEADERS_SIZE, 0)   # SizeOfImage/Headers/Checksum
        oh += struct.pack("<HH", 3, 0)                        # Subsystem, DllCharacteristics
        if self.magic == 0x20B:
            oh += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)
        else:
            oh += struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)
        oh += struct.pack("<II", 0, NUM_DATA_DIRECTORIES)
        assert len(oh) == OPTIONAL_HEADER_SIZE[self.magic], len(oh)

        for index in range(NUM_DATA_DIRECTORIES):
            rva, size = self.dirs.get(index, (0, 0))
            oh += struct.pack("<II", rva, size)
        return oh

    def build(self):
        e_lfanew = 0x80
        # The DOS stub occupies everything before the PE signature, so the
        # Rich header has somewhere to live (real ones sit in this gap too).
        stub = bytearray(e_lfanew)
        stub[0:64] = struct.pack("<2s58xI", b"MZ", e_lfanew)
        if self.rich:
            if 0x40 + len(self.rich) > e_lfanew:
                raise ValueError("Rich header does not fit in the DOS stub")
            stub[0x40:0x40 + len(self.rich)] = self.rich

        opt = self._optional_header()
        file_header = struct.pack(
            "<HHIIIHH", self.machine, len(self.sections), 0, 0, 0,
            len(opt), 0x22)

        headers = bytes(stub) + struct.pack("<I", 0x00004550) + file_header + opt
        headers += b"".join(section_header(n, r, d, c)
                            for n, r, d, c in self.sections)
        if len(headers) > HEADERS_SIZE:
            raise ValueError(
                f"headers overflow {HEADERS_SIZE:#x}: {len(headers):#x}")
        headers = headers.ljust(HEADERS_SIZE, b"\x00")

        size = HEADERS_SIZE
        for _, rva, data, _ in self.sections:
            size = max(size, rva + len(data))
        image = bytearray(size)
        image[0:len(headers)] = headers
        for _, rva, data, _ in self.sections:
            image[rva:rva + len(data)] = data
        return bytes(image)


def build_with_directories(**kwargs):
    """A PE32+ image whose .rdata holds the directories the caller supplies."""
    return PEBuilder(**kwargs)


def build_loaded_image_with_one_import(func_name="MessageBoxA",
                                       dll_name="user32.dll",
                                       image_base=0x140000000):
    """A PE32+ image in *loaded* layout with a single named import.

    Loaded layout (pointer_to_raw_data == RVA) is what a debugger reads from a
    live process, and what LoadedView expects. Both IAT tests used to build a
    file-layout image, which only worked while the lookup parsed memory as a
    file. Returns (image_bytes, iat_rva); the caller fills the IAT slot.
    """
    builder = PEBuilder(image_base=image_base)
    builder.add_section(".text", b"\x90" * 0x100, 0x1000)
    builder.add_section(".rdata", b"\x00" * 0x500, 0x2000)
    builder.add_dir(1, 0x2000, 0x14)      # import directory
    data = bytearray(builder.build())

    ilt_rva, ibn_rva, dll_rva, iat_rva = 0x2100, 0x2200, 0x2300, 0x2400
    struct.pack_into("<IIIII", data, 0x2000, ilt_rva, 0, 0, dll_rva, iat_rva)
    struct.pack_into("<Q", data, ilt_rva, ibn_rva)
    struct.pack_into("<H", data, ibn_rva, 0)          # hint
    name = func_name.encode("ascii") + b"\x00"
    data[ibn_rva + 2:ibn_rva + 2 + len(name)] = name
    dll = dll_name.encode("ascii") + b"\x00"
    data[dll_rva:dll_rva + len(dll)] = dll
    return bytes(data), iat_rva
