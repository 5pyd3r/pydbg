"""AnalyzedImage — a PE plus the address arithmetic analysis needs.

Bridges pe/ (format) and disasm/ (bytes to instructions) without either
depending on the other, and works the same whether the bytes came from a file
or from a live module.
"""

from dataclasses import dataclass

from ..pe import PE
from ..pe.view import LoadedView

_MACHINE_TO_MODE = {0x14C: "x86", 0x8664: "x64"}

# IMAGE_SCN_MEM_EXECUTE
_SCN_MEM_EXECUTE = 0x20000000
_SCN_MEM_WRITE = 0x80000000


@dataclass(frozen=True)
class SectionInfo:
    """One section, in the terms the analyzer thinks in."""

    name: str
    virtual_address: int
    virtual_size: int
    size_of_raw_data: int
    is_exec: bool
    is_write: bool


class AnalyzedImage:
    """A PE image with RVA/VA translation fixed for its actual load address.

    'image_base' here is the base the image's stored addresses are relative
    to — the optional header's for a file, the module's runtime base for a live
    process. That distinction matters: an ASLR'd module's operands are all
    relative to its runtime base, and testing them against the preferred one
    puts every single one outside the window, so the analyzer would return an
    empty result and report success.
    """

    def __init__(self, pe, mode=None, image_base=None):
        self.pe = pe
        self.source = pe.source
        self.mode = mode or _MACHINE_TO_MODE.get(pe.file_header.machine, "x86")
        self.image_base = pe.image_base if image_base is None else image_base
        self.sections = tuple(
            SectionInfo(
                name=s.name,
                virtual_address=s.virtual_address,
                virtual_size=s.virtual_size,
                size_of_raw_data=s.size_of_raw_data,
                is_exec=bool(s.characteristics & _SCN_MEM_EXECUTE),
                is_write=bool(s.characteristics & _SCN_MEM_WRITE),
            )
            for s in pe.sections
        )
        self.exec_ranges = tuple(
            (s.virtual_address,
             s.virtual_address + max(s.virtual_size, s.size_of_raw_data))
            for s in self.sections if s.is_exec)

    def _section_span(self, section):
        """[start, end) an RVA must fall in to belong to 'section'."""
        start = section.virtual_address
        return start, start + max(section.virtual_size, section.size_of_raw_data)

    # ── constructors ───────────────────────────────────────────

    @classmethod
    def from_pe(cls, pe, mode=None, image_base=None):
        return cls(pe, mode=mode, image_base=image_base)

    @classmethod
    def from_file(cls, path, mode=None, lazy=False):
        return cls(PE.from_file(path, lazy=lazy), mode=mode)

    @classmethod
    def from_bytes(cls, data, mode=None):
        return cls(PE(data), mode=mode)

    @classmethod
    def from_process(cls, session, base_address, mode=None, module_size=None):
        """Build from a live module, using LoadedView over a process Source.

        The module's VAs are relative to wherever it actually loaded, so that
        base is used for translation rather than the header's ImageBase.
        """
        from .process_source import ProcessSource

        source = ProcessSource(session, base_address, size=module_size)
        pe = PE.from_source(source, LoadedView(), va_base=base_address)
        return cls(pe, mode=mode, image_base=base_address)

    # ── geometry ───────────────────────────────────────────────

    @property
    def span(self):
        """Size of the image's mapped extent, in bytes."""
        return max((self._section_span(s)[1] for s in self.sections), default=0)

    @property
    def slot_size(self):
        """Pointer width in bytes.

        Every seed reader must take its stride from here. The prototype this
        descends from hard-coded 4 throughout, which on a PE32+ image reads
        the low half of every pointer and the high half of the one before it.
        """
        return 8 if self.pe.optional_header.magic == 0x20B else 4

    def section_of(self, rva):
        for section in self.sections:
            start, end = self._section_span(section)
            if start <= rva < end:
                return section
        return None

    def is_exec(self, rva):
        for start, end in self.exec_ranges:
            if start <= rva < end:
                return True
        return False

    def is_mapped(self, rva):
        return self.section_of(rva) is not None

    # ── address translation ────────────────────────────────────

    def va_to_rva(self, va):
        """RVA for an absolute address, or None when it is outside the image.

        The window test is the one that keeps a small constant from being read
        as an RVA. Treating any value below the image span as an RVA produces
        large numbers of false references, which is worse than missing them.
        """
        if self.image_base <= va < self.image_base + self.span:
            return va - self.image_base
        return None

    def rva_to_va(self, rva):
        return self.image_base + rva

    # ── reads ──────────────────────────────────────────────────

    def read_rva(self, rva, size):
        """Bytes at 'rva', or None when unavailable. Never raises."""
        return self.pe.read_rva(rva, size)

    def read_code_bytes(self, rva, max_len=16, min_len=1):
        """Bytes for decoding at 'rva', short rather than None at a boundary.

        A section's last instruction is rarely exactly 'max_len' bytes long, so
        demanding a full read would drop every instruction within 'max_len' of
        the end. Reads down to 'min_len' and lets the decoder stop at the
        truncated tail instead.
        """
        chunk = self.read_rva(rva, max_len)
        if chunk is not None:
            return chunk
        for size in range(max_len - 1, min_len - 1, -1):
            chunk = self.read_rva(rva, size)
            if chunk is not None:
                return chunk
        return None

    def read_pointer(self, rva):
        """One pointer-sized value at 'rva', or None."""
        raw = self.read_rva(rva, self.slot_size)
        if raw is None:
            return None
        return int.from_bytes(raw, "little")
