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
