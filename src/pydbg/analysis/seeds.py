"""Seed providers — where the analysis decides to start looking.

Recursive descent only finds what something points at, so the seeds decide
what the answer can possibly contain. Each class below is a different kind of
authority, and they are kept apart rather than merged because they are not
equally trustworthy: an export is a fact, a pointer found in a data section is
a guess.

Every stride and width comes from AnalyzedImage.slot_size. The prototype these
descend from hard-coded 4 throughout, which on a PE32+ image reads the low half
of every pointer and — worse — the high half of the pointer before it, so the
seeds that do get read are misaligned and the ones that matter are missed.
"""

from dataclasses import dataclass, field

# IMAGE_REL_BASED_* — the two that carry an address.
REL_BASED_ABSOLUTE = 0     # padding, carries nothing
REL_BASED_HIGHLOW = 3      # 32-bit image
REL_BASED_DIR64 = 10       # 64-bit image
_ADDRESS_RELOCS = frozenset((REL_BASED_HIGHLOW, REL_BASED_DIR64))

# Bytes a function's first instruction may legitimately follow. A preceding
# one of these is weak evidence and nothing more — most of what this filter
# admits is still wrong — but it is cheap and it is what keeps pointer seeds
# from producing thousands of misaligned decodes.
_PAD_BYTES = frozenset((0x90, 0xCC, 0xC3, 0xC2, 0x00))


def looks_like_entry(image, rva, is_call_target=False):
    """Whether 'rva' plausibly begins a function.

    Deliberately weak, and named so: a call target is taken on trust (something
    calls it), and otherwise the byte before has to be padding, a return, or an
    int3. It admits a great deal that is not a function entry, which is why the
    seeds it filters are recorded as tentative rather than confident.
    """
    if is_call_target:
        return True
    section = image.section_of(rva)
    if section is None:
        return False
    if rva == section.virtual_address:
        return True
    previous = image.read_rva(rva - 1, 1)
    if previous is None:
        return False
    return previous[0] in _PAD_BYTES


@dataclass
class SeedSet:
    """Seeds, split by how much they are trusted, plus what each class found."""

    confident: set = field(default_factory=set)
    tentative: set = field(default_factory=set)
    # kind -> the distinct addresses that class produced. Kept per class rather
    # than as a running count so the numbers mean "what this class sees", not
    # "what this class sees that no earlier class already claimed" — the latter
    # depends on the order the classes happen to run in, which makes a class
    # look empty for reasons that have nothing to do with it.
    found: dict = field(default_factory=dict)

    def add(self, rva, confident, kind):
        if rva is None:
            return False
        self.found.setdefault(kind, set()).add(rva)
        target = self.confident if confident else self.tentative
        fresh = rva not in self.confident and rva not in self.tentative
        target.add(rva)
        return fresh

    def classes(self):
        """kind -> number of distinct addresses that class produced."""
        return {kind: len(rvas) for kind, rvas in self.found.items()}


class SeedProvider:
    """Collects every seed class an image can offer."""

    def __init__(self, image, max_data_pointers=200_000):
        self.image = image
        self.max_data_pointers = max_data_pointers

    def collect(self):
        seeds = SeedSet()
        self._entry_point(seeds)
        self._exports(seeds)
        self._tls_callbacks(seeds)
        self._exception_table(seeds)
        self._relocation_pointers(seeds)
        self._data_pointers(seeds)
        return seeds

    # ── exact classes ──────────────────────────────────────────

    def _entry_point(self, seeds):
        entry = self.image.pe.optional_header.entry_point_rva
        if entry:
            seeds.add(entry, True, "entry_point")

    def _exports(self, seeds):
        for export in self.image.pe.exports:
            if export.forwarder or not export.rva:
                continue                      # forwarded: lives in another DLL
            if self.image.is_exec(export.rva):
                seeds.add(export.rva, True, "exports")

    def _tls_callbacks(self, seeds):
        """TLS callbacks run before the entry point, so they are functions.

        The directory stores them as VAs, which is why the image carries a
        va_base; reading them against the wrong one finds nothing at all.
        """
        tls = self.image.pe.tls
        if tls is None:
            return
        for callback in tls.callbacks:
            rva = self.image.va_to_rva(callback)
            if rva is not None and self.image.is_exec(rva):
                seeds.add(rva, True, "tls_callbacks")

    def _exception_table(self, seeds):
        """RUNTIME_FUNCTION ranges (x64).

        The strongest class there is where it exists: the loader's own record
        of where every function begins and ends, rather than a guess about it.
        """
        for entry in self.image.pe.exception_entries:
            if self.image.is_exec(entry.begin_rva):
                seeds.add(entry.begin_rva, True, "exception_table")

    # ── pointer classes ────────────────────────────────────────

    def _relocation_pointers(self, seeds):
        """Function pointers the loader itself has to fix up.

        The base relocation table is the authoritative answer to "which dwords
        in this image are really pointers", which makes it the best pointer
        seed source available — measured on one target, removing it dropped
        coverage from 94% to 42.7%.

        Both relocation kinds are read. Handling only HIGHLOW (3) is the
        prototype's 32-bit assumption, and it empties this class entirely on
        every x64 image, where the form is DIR64 (10).
        """
        for block in self.image.pe.relocations:
            for entry in block.entries:
                if entry.kind not in _ADDRESS_RELOCS:
                    continue
                slot_rva = block.page_rva + entry.offset
                value = self.image.read_pointer(slot_rva)
                if value is None:
                    continue
                rva = self.image.va_to_rva(value)
                if rva is None or not self.image.is_exec(rva):
                    continue
                if looks_like_entry(self.image, rva):
                    seeds.add(rva, False, "relocation_pointers")

    def _data_pointers(self, seeds):
        """Pointer-shaped values in the data sections that land in code.

        The weakest class, and the one most likely to seed misaligned decodes —
        a value only has to *look* like a pointer. Kept because a vtable or a
        callback table often appears nowhere else, and the confidence split
        keeps its unreliability visible downstream.
        """
        slot_size = self.image.slot_size
        found = 0
        for section in self.image.sections:
            if section.is_exec or section.size_of_raw_data == 0:
                continue
            data = self.image.read_rva(section.virtual_address,
                                       section.size_of_raw_data)
            if data is None:
                continue
            for offset in range(0, len(data) - slot_size + 1, slot_size):
                value = int.from_bytes(data[offset:offset + slot_size], "little")
                rva = self.image.va_to_rva(value)
                if rva is None or not self.image.is_exec(rva):
                    continue
                if not looks_like_entry(self.image, rva):
                    continue
                seeds.add(rva, False, "data_pointers")
                found += 1
                if found >= self.max_data_pointers:
                    return
