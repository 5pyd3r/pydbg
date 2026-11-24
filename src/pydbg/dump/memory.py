"""Dump a live memory range into an image plus a gap side table.

`read_memory_safe` already returns bytes that always have the requested
length, zero-filling whatever it could not read and listing it as a gap. That
is not enough to rebuild an image from: a zero-filling read cannot say *why* a
page is missing, and its win32_error is 0 for free/reserved pages, so a caller
that tried to explain the hole from the error would claim every hole was a
success. This module pairs the bytes with region state and protection, which is
where the reason actually lives.

`DumpedImage.data` is indexed from the module base (`data[i]` is `base + i`),
and every gap RVA uses the same origin.

Errors are split by cause: a bad argument (a negative size, an address ceiling
that would truncate the module, an unsupported module record) raises
`ValueError`, because the caller asked for something impossible; `DumpError` is
reserved for runtime failures — no module to dump, no memory access, bytes that
are not a PE image.
"""

from dataclasses import dataclass

from ..exceptions import PydbgError


# VirtualQueryEx state for committed/free/reserved pages. Only a committed
# region has bytes to read; asking for the others would only produce
# ERROR_PARTIAL_COPY, whose win32_error is 0 and explains nothing.
_MEM_COMMIT = 0x1000
_MEM_RESERVE = 0x2000
_MEM_FREE = 0x10000


class DumpError(PydbgError):
    """A module or range could not be dumped.

    Raised when the module cannot be found, when the bytes at its base are
    not a PE image, or when the request would produce a truncated image. A
    range that merely has unreadable pages is not an error: those become
    gaps on the returned DumpedImage.
    """


@dataclass(frozen=True)
class Gap:
    """A span of the dumped image that could not be read.

    'reason' is "free", "reserved", or "unreadable:protect=0x<protect>".
    It is derived from the region's state/protect, never from the read's
    win32_error: an uncommitted page reports error 0 there.
    """

    rva: int
    size: int
    reason: str


@dataclass
class DumpedImage:
    """Bytes of one memory range, with holes explained rather than guessed."""

    rva_base: int
    data: bytes
    gaps: tuple = ()
    module_name: str | None = None
    image_base: int = 0
    size_of_image: int = 0
    entry_point_rva: int = 0
    load_delta: int = 0

    @property
    def complete(self):
        """True when every byte of the range was read."""
        return not self.gaps


def dump_region(dbg, base, size, *, name=None):
    """Dump [base, base+size) without requiring a PE image at 'base'.

    No header is read and no size is guessed: the caller's range is the range.
    rva_base/image_base are 'base', entry_point_rva/load_delta are 0.

    Raises:
        ValueError: 'size' is negative — an impossible request, not a failed
            dump.
    """
    base = int(base)
    size = int(size)
    if size < 0:
        raise ValueError(f"dump_region: negative size {size}")
    data, gaps = _collect(dbg, base, size)
    return DumpedImage(
        rva_base=base,
        data=data,
        gaps=gaps,
        module_name=name,
        image_base=base,
        size_of_image=size,
        entry_point_rva=0,
        load_delta=0,
    )


def dump_module(dbg, module=None, *, max_addr=None):
    """Dump a loaded module from its base to its SizeOfImage.

    'module' is one of the dicts enum_modules() returns, a (base, size) tuple,
    or None for the main module. The bytes at the base are parsed with
    LoadedView first: a region that is not a PE image raises DumpError instead
    of producing a plausible-looking dump of whatever happens to be mapped
    there. SizeOfImage comes from that header, never from the module entry's
    size hint — a stale or wrong hint must not decide how much is read.

    'max_addr' bounds the address space the region walk may enter, which is
    what a 32-bit target needs (0x100000000). It defaults to the module's own
    end. A ceiling below that end would silently truncate the image, so it is
    refused rather than quietly obeyed.

    Raises:
        ValueError: the module argument is unusable, or 'max_addr' would
            truncate the module (a bad request).
        DumpError: nothing could be dumped — no module to dump, the memory
            could not be read, or the bytes at the base are not a PE image.
    """
    base, size_hint, name = _resolve_module(dbg, module)
    pe = _parse_loaded_pe(dbg, base, size_hint)
    size_of_image = pe.optional_header.size_of_image
    if size_of_image <= 0:
        raise DumpError(
            f"not a PE image at 0x{base:X}: SizeOfImage is {size_of_image}")
    end = base + size_of_image
    if max_addr is not None and end > max_addr:
        raise ValueError(
            f"module at 0x{base:X} ends at 0x{end:X}, past max_addr "
            f"0x{max_addr:X}")

    data, gaps = _collect(dbg, base, size_of_image)
    header = pe.optional_header
    return DumpedImage(
        rva_base=base,
        data=data,
        gaps=gaps,
        module_name=name,
        image_base=base,
        size_of_image=size_of_image,
        entry_point_rva=header.entry_point_rva,
        # The header's preferred base versus where the loader actually put it.
        # Rebuilding must not rewrite addresses, so the caller only records it.
        load_delta=base - header.image_base,
    )


def _resolve_module(dbg, module):
    """(base, size hint, name) for a module argument.

    Raises:
        ValueError: the argument is not a module record the dump accepts (not
            a dict, not a (base, size) pair, or a record with no base address).
        DumpError: there is no module to dump or they cannot be enumerated.
    """
    if module is None:
        try:
            modules = dbg.enum_modules()
        except (PydbgError, OSError) as e:
            raise DumpError(f"cannot enumerate modules: {e}") from e
        if not modules:
            raise DumpError("no loaded module to dump")
        module = modules[0]
    if isinstance(module, dict):
        base = int(module.get('base_address') or 0)
        size_hint = int(module.get('size') or 0)
        name = module.get('name')
    elif isinstance(module, (tuple, list)) and len(module) == 2:
        base, size_hint = int(module[0]), int(module[1])
        name = None
    else:
        raise ValueError(f"unsupported module argument: {module!r}")
    if base <= 0:
        raise ValueError(f"module has no base address: {module!r}")
    return base, max(size_hint, 0), name


def _parse_loaded_pe(dbg, base, size_hint):
    """Parse the image mapped at 'base' as a loaded PE, or DumpError.

    Uses ProcessSource with a read_memory_safe-backed reader: the strict
    MemoryManager reader turns one uncommitted page into a MemError that
    pe.Source.try_read does not catch, which would escape as the wrong
    exception type. Zero-filled bytes from a truly empty page fail the header
    signature instead and become the DumpError this function promises.
    """
    from ..analysis.process_source import ProcessSource
    from ..pe import PE
    from ..pe.view import LoadedView

    source = ProcessSource(
        getattr(dbg, '_session', None), base,
        size=size_hint or None,
        reader=_safe_reader(dbg, base, size_hint))
    try:
        return PE.from_source(source, LoadedView(), va_base=base)
    except (ValueError, OSError, PydbgError) as e:
        raise DumpError(f"not a PE image at 0x{base:X}: {e}") from e


def _safe_reader(dbg, base, size_hint):
    """A pe.Source reader over dbg.read_memory_safe, bounded to the module."""
    limit = base + size_hint if size_hint else None

    def read(addr, size):
        if limit is not None and addr + size > limit:
            raise ValueError(
                f"Read past the end of the module: addr=0x{addr:X}, "
                f"size={size}, module end=0x{limit:X}")
        return dbg.read_memory_safe(addr, size).data

    return read


def _collect(dbg, base, size):
    """Read [base, base+size) region by region.

    Returns (zero-filled data, tuple of Gap). Only committed regions are
    read; the rest stay zero.
    """
    data = bytearray(size)
    gaps = []
    end = base + size
    if size == 0:
        return b"", ()

    for region in dbg.enum_regions(start=base, max_addr=end):
        lo = max(base, region['base_address'])
        hi = min(end, region['base_address'] + region['region_size'])
        if lo >= hi:
            continue
        if region['state'] != _MEM_COMMIT:
            gaps.append(Gap(lo - base, hi - lo, _region_gap_reason(region)))
            continue
        read = dbg.read_memory_safe(lo, hi - lo)
        data[lo - base:hi - base] = read.data
        # read_memory_safe already zero-filled these spans; all that is missing
        # is the reason, and its own win32_error cannot supply one.
        for gap_addr, gap_size, _win32_error in read.gaps:
            gaps.append(
                Gap(gap_addr - base, gap_size, _region_gap_reason(region)))
    gaps.sort(key=lambda gap: gap.rva)
    return bytes(data), tuple(gaps)


def _region_gap_reason(region):
    """Why a region cannot be read, from its state and protection.

    read_memory_safe's own gap entries carry a win32_error that is 0 for
    uncommitted pages, so the answer has to come from VirtualQueryEx.
    """
    state = region.get('state', 0)
    if state == _MEM_FREE:
        return 'free'
    if state == _MEM_RESERVE:
        return 'reserved'
    return f"unreadable:protect=0x{region.get('protect', 0):X}"
