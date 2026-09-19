"""View layer — address translation strategies."""

from abc import ABC, abstractmethod


class View(ABC):
    """Abstract address translation strategy."""

    @abstractmethod
    def rva_to_source_offset(self, rva: int) -> int | None:
        """Convert PE-relative RVA to Source offset."""


class FileView(View):
    """File-state view: RVA -> file offset via section headers.

    Only file-backed bytes resolve. A section's in-memory extent can exceed
    what the file stores, and that difference is not addressable in a file
    source at all — that asymmetry is why LoadedView is a separate strategy.
    """

    def __init__(self, sections):
        self._sections = sections

    def rva_to_source_offset(self, rva: int) -> int | None:
        """File offset for 'rva', or None when the RVA is not file-backed.

        The size_of_raw_data check is load-bearing, not defensive. Matching on
        virtual_size alone resolves an RVA in a section's zero-fill tail into
        the *next* section's raw data — plausible-looking bytes from the wrong
        place, which is worse than no answer at all. Packed images make this
        routine: a UPX0-style section declares virtual_size with
        size_of_raw_data == 0, so every RVA in it used to read whatever follows.

        The span is max(virtual_size, size_of_raw_data) because a section may
        store more on disk than it maps; the guard below then decides whether
        the particular RVA is actually stored.
        """
        for section in self._sections:
            start = section.virtual_address
            end = start + max(section.virtual_size, section.size_of_raw_data)
            if not start <= rva < end:
                continue
            delta = rva - start
            if section.size_of_raw_data == 0 or delta >= section.size_of_raw_data:
                return None
            return section.pointer_to_raw_data + delta
        return None


class LoadedView(View):
    """Loaded-state view: RVA is the source offset (Source already at module base).

    Deliberately does no raw-size filtering: in a live process every RVA up to
    size_of_image is readable, including the zero-fill tail FileView must
    refuse. Translating the RVA is all this owes its Source; whether the page
    is committed is the Source's problem, not the view's.
    """

    def rva_to_source_offset(self, rva: int) -> int | None:
        return rva
