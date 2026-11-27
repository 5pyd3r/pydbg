"""MemoryManager — read/write/query/protect process memory, plus allocation.

The manager owns both halves of the interface to the target's address space:
the memory that already exists (read, write, query, protect, tolerant reads)
and the scratch regions callers ask it to create. Remote allocation lives here
so instrumentation code never reaches for `_pydbg` itself: `alloc_remote` is a
free-standing buffer (the BBL event ring) and `alloc_near` is a region within a
window of an address (the stubs a 5-byte E9 detour has to reach).
"""

from dataclasses import dataclass, field

from .. import _pydbg
from ..exceptions import MemError

# VirtualQueryEx state / page constants, used by the tolerant read path.
_MEM_COMMIT = 0x1000
_MEM_FREE = 0x10000
_PAGE_SIZE = 0x1000

# Allocation constants for the remote scratch/buffer path.
_MEM_COMMIT_RESERVE = 0x3000     # MEM_COMMIT | MEM_RESERVE
_MEM_RELEASE = 0x8000
_PAGE_READWRITE = 0x04
_PAGE_EXECUTE_READWRITE = 0x40

# VirtualAllocEx rounds a hint down to the allocation granularity, so a hint
# inside an occupied page fails with ERROR_INVALID_ADDRESS; round up instead.
_ALLOC_GRANULARITY = 0x10000

# The default half-window of `alloc_near`: ±2GB, the reach of an E9 rel32.
_NEAR_LIMIT = 0x80000000

# Ceiling on a single tolerant read. Generous enough for the largest image
# anyone dumps in one call (a whole 512MB process would still fit), small
# enough that a length field which lies fails loudly instead of trying to
# allocate its way through the address space.
DEFAULT_MAX_READ = 0x20000000      # 512 MiB


def _near_hint(region, near, limit, size):
    """The allocation hint inside `region` for `size` bytes, or None.

    The placement rule for `alloc_near`, kept a pure function so it can be
    tested without a target: aligned up to the allocation granularity, inside
    the free region, and inside `near ± limit`. `region` is a `regions_handle`
    dict. A hint that would leave the high edge is pulled back (the window is
    the hard limit); if that lands before the region, or the region is simply
    too small, the answer is None and the caller records why.
    """
    base = region.get('base_address', 0)
    span = region.get('region_size', 0)
    if span < size:
        return None
    hint = (base + _ALLOC_GRANULARITY - 1) & ~(_ALLOC_GRANULARITY - 1)
    high = near + limit
    if hint + size > high:
        hint = high - size
        if hint < base:
            return None
    if hint + size > base + span:
        return None
    return hint


@dataclass
class MemoryRead:
    """Result of a tolerant memory read.

    'data' is always 'size' bytes long: readable spans hold what the target
    returned, unreadable spans are zero-filled and listed in 'gaps'. A caller
    rebuilding an image wants 'data' plus 'complete'; one that only needs the
    bytes that exist can ignore the rest. Raising instead would discard the
    successfully-read prefix, which is the whole reason this exists.
    """

    address: int
    size: int
    data: bytes
    # (address, size, win32_error) per unreadable span, ascending.
    gaps: list = field(default_factory=list)

    @property
    def complete(self):
        """True when every requested byte was read."""
        return not self.gaps

    @property
    def readable_bytes(self):
        """How many of the requested bytes were actually read."""
        return self.size - sum(size for _, size, _ in self.gaps)


class MemoryManager:
    """Manages process memory operations."""

    def __init__(self, session):
        self._s = session

    def read(self, addr, size):
        try:
            return _pydbg.read_process_memory(self._s.process_handle, addr, size)
        except OSError as e:
            raise MemError(f"ReadProcessMemory at 0x{addr:X}: {e}")

    def write(self, addr, data):
        try:
            return _pydbg.write_process_memory(self._s.process_handle, addr, data)
        except OSError as e:
            raise MemError(f"WriteProcessMemory at 0x{addr:X}: {e}")

    def query(self, addr):
        try:
            return _pydbg.virtual_query_ex(self._s.process_handle, addr)
        except OSError as e:
            raise MemError(f"VirtualQueryEx at 0x{addr:X}: {e}")

    def protect(self, addr, size, protect):
        try:
            return _pydbg.virtual_protect_ex(
                self._s.process_handle, addr, size, protect
            )
        except OSError as e:
            raise MemError(f"VirtualProtectEx at 0x{addr:X}: {e}")

    # ── remote allocation ──
    #
    # Instrumentation needs a scratch region inside the target that outlives a
    # single write: the event ring a stub appends to lives there. The rest of
    # this class reads and writes memory that already exists; allocation was the
    # missing half, and it belongs here so callers never reach for `_pydbg`
    # themselves (and tests can stand in one object).

    def alloc_remote(self, size, protect=_PAGE_READWRITE, hint=0):
        """Allocate `size` bytes in the target; return the base address.

        Committed and reserved in one call (VirtualAllocEx), zero-filled by
        Windows. Arbitrary placement is intentional: the buffer is reached by
        absolute address in the stub, so it needs no ±2GB neighbourhood.

        'hint' is VirtualAllocEx's lpAddress: 0 lets Windows choose, a
        non-zero value asks for that base and fails if it is occupied. A WOW64
        target can only address memory below 4 GiB, so its injection path
        passes a low hint rather than trusting a 64-bit allocator's choice; the
        answer is still checked by the caller, which is the one that knows the
        target's architecture.

        Raises:
            MemError: VirtualAllocEx refused, or answered without an address.
        """
        try:
            result = _pydbg.virtual_alloc_ex(
                self._s.process_handle, hint, size, _MEM_COMMIT_RESERVE, protect)
        except OSError as e:
            raise MemError(f"VirtualAllocEx({size}) failed: {e}") from e
        address = result.get('base_address', 0)
        if not address:
            raise MemError(f"VirtualAllocEx({size}) returned no address")
        return address

    def free_remote(self, address):
        """Release an allocation made by `alloc_remote` (MEM_RELEASE).

        Raises:
            MemError: VirtualFreeEx refused; the allocation is still there.
        """
        try:
            _pydbg.virtual_free(
                self._s.process_handle, address, 0, _MEM_RELEASE)
        except OSError as e:
            raise MemError(f"VirtualFreeEx at 0x{address:X}: {e}") from e

    def alloc_near(self, size, near, limit=_NEAR_LIMIT):
        """Allocate `size` RWX bytes within `limit` of `near`; return its base.

        The near variant exists for detours: a 5-byte `E9 rel32` only reaches
        ±2GB, so a stub the detour jumps to has to be placed next to the
        module. `alloc_remote` deliberately does not care where its buffer
        lands. The scan walks the target's regions between `near - limit` and
        `near + limit`, takes each free one, and asks VirtualAllocEx for a
        64KB-aligned hint inside it (`_near_hint`).

        Every candidate is tried, and every failure is kept: a free region
        that cannot hold the request inside the window, a VirtualAllocEx that
        refuses the hint (the region is usually already occupied by the time
        the stale snapshot is used), an allocation that answers without an
        address. The refusal names all of them, because "no free region" would
        be false when regions existed and the allocator was what said no.

        Raises:
            MemError: the region walk failed, or no candidate succeeded; the
                message lists what each failure was.
        """
        if size <= 0:
            raise MemError(f"cannot allocate {size} bytes near 0x{near:X}")
        handle = self._s.process_handle
        low = (near - limit) & ~(_ALLOC_GRANULARITY - 1)
        if low < _ALLOC_GRANULARITY:
            low = _ALLOC_GRANULARITY
        high = near + limit
        try:
            regions = self.regions_handle(handle, low, high)
        except (MemError, OSError) as exc:
            raise MemError(
                f"cannot scan for memory near 0x{near:X}: {exc}") from exc

        failures = []
        for region in regions:
            if region.get('state') != _MEM_FREE:
                continue
            base = region.get('base_address', 0)
            span = region.get('region_size', 0)
            hint = _near_hint(region, near, limit, size)
            if hint is None:
                failures.append(
                    f"free region 0x{base:X}+0x{span:X} cannot hold "
                    f"{size} bytes inside the window")
                continue
            try:
                result = _pydbg.virtual_alloc_ex(
                    handle, hint, size, _MEM_COMMIT_RESERVE,
                    _PAGE_EXECUTE_READWRITE)
            except OSError as exc:
                failures.append(f"VirtualAllocEx at 0x{hint:X}: {exc}")
                continue
            address = result.get('base_address', 0)
            if address:
                return address
            failures.append(f"VirtualAllocEx at 0x{hint:X} returned no address")

        detail = ("; ".join(failures) if failures
                  else f"the scan from 0x{low:X} to 0x{high:X} saw no free "
                       f"region")
        raise MemError(
            f"no free region within ±0x{limit:X} of 0x{near:X} for "
            f"{size} bytes: {detail}")

    # ── handle variants for child process support ──

    def read_handle(self, h_process, addr, size):
        try:
            return _pydbg.read_process_memory(h_process, addr, size)
        except OSError as e:
            raise MemError(f"ReadProcessMemory at 0x{addr:X}: {e}")

    def write_handle(self, h_process, addr, data):
        try:
            return _pydbg.write_process_memory(h_process, addr, data)
        except OSError as e:
            raise MemError(f"WriteProcessMemory at 0x{addr:X}: {e}")

    def query_handle(self, h_process, addr):
        try:
            return _pydbg.virtual_query_ex(h_process, addr)
        except OSError as e:
            raise MemError(f"VirtualQueryEx at 0x{addr:X}: {e}")

    def protect_handle(self, h_process, addr, size, protect):
        try:
            return _pydbg.virtual_protect_ex(h_process, addr, size, protect)
        except OSError as e:
            raise MemError(f"VirtualProtectEx at 0x{addr:X}: {e}")

    # ── region enumeration and tolerant reads ──

    def regions_handle(self, h_process, start=0, max_addr=0):
        """Enumerate the target's memory regions via VirtualQueryEx.

        Returns a list of region dicts (base_address, allocation_base,
        allocation_protect, region_size, state, protect, type), ascending.
        Unlike query_handle this walks the whole chain, and reaching the end
        of the address space is not an error. A failing VirtualQueryEx is not
        an answer either — it becomes a MemError like every other memory
        operation, instead of a raw OSError escaping the public API.
        """
        try:
            return _pydbg.virtual_query_all(h_process, start, max_addr)
        except OSError as e:
            raise MemError(
                f"VirtualQueryEx walk from 0x{start:X}: {e}") from e

    def read_safe_handle(self, h_process, addr, size, max_bytes=DEFAULT_MAX_READ):
        """Read [addr, addr+size) without losing the readable parts.

        read() raises on the first unreadable page and discards what it already
        read, so callers dumping memory or rebuilding a PE had to hand-roll a
        page-by-page fallback. This walks regions instead, keeps every byte the
        target would give up, and reports the rest as gaps.

        Returns a MemoryRead; never raises for unreadable memory.

        It does refuse an unreasonable *request*, though. 'size' usually comes
        from a header field or a length in the target's own memory, so a
        corrupt one turns into a multi-gigabyte allocation and a read per
        region across the address space, with nothing to say it was a typo.
        Above max_bytes this raises rather than returning a short result:
        MemoryRead.gaps holds (address, size, win32_error) and a policy
        truncation has no win32 error to report, so it would arrive looking
        exactly like uncommitted memory. Pass a larger max_bytes when the
        caller really does mean it.
        """
        if size <= 0:
            return MemoryRead(addr, size, b"", [])
        if max_bytes is not None and size > max_bytes:
            raise MemError(
                f"refusing a {size}-byte read at 0x{addr:X}: over the "
                f"{max_bytes}-byte limit (pass max_bytes= to raise it)")

        end = addr + size
        buf = bytearray(size)
        gaps = []
        cursor = addr

        while cursor < end:
            try:
                region = _pydbg.virtual_query_ex(h_process, cursor)
            except OSError as e:
                gaps.append((cursor, end - cursor, getattr(e, "errno", 0) or 0))
                break

            base = region["base_address"]
            rsize = region["region_size"]
            if rsize <= 0:
                gaps.append((cursor, end - cursor, 0))
                break
            region_end = base + rsize

            stop = min(region_end, end)
            if region["state"] != _MEM_COMMIT:
                # Free or merely reserved: nothing to read, and asking would
                # just produce ERROR_PARTIAL_COPY.
                gaps.append((cursor, stop - cursor, 0))
            else:
                self._read_span(h_process, cursor, stop, buf, addr, gaps)

            if region_end <= cursor:  # defensive: never loop without progress
                break
            cursor = min(region_end, end)

        return MemoryRead(addr, size, bytes(buf), gaps)

    def _read_span(self, h_process, start, stop, buf, origin, gaps):
        """Fill buf[start-origin : stop-origin], degrading to pages on failure."""
        size = stop - start
        data, nread, err = _pydbg.read_process_memory_partial(
            h_process, start, size)
        if nread:
            buf[start - origin:start - origin + nread] = data
        if err == 0 and nread == size:
            return

        # The whole span did not transfer. Retry page by page from where the
        # partial read stopped, so one bad page costs one page rather than the
        # rest of the region.
        cursor = start + nread
        while cursor < stop:
            chunk = min(_PAGE_SIZE, stop - cursor)
            data, nread, err = _pydbg.read_process_memory_partial(
                h_process, cursor, chunk)
            if nread:
                buf[cursor - origin:cursor - origin + nread] = data
            if nread < chunk:
                gaps.append((cursor + nread, chunk - nread, err))
            cursor += chunk

    def teardown(self):
        """Undo nothing: every handle is the session's, every allocation the caller's.

        This manager writes the target, so it belongs in the teardown chain
        (ADR-0004), but it owns no artifact to release: `read`/`write` use the
        session's process handle (released by `Debugger.close()`), and
        `alloc_remote`/`alloc_near` hand the address back to the caller, which
        frees it (`BblInstrumenter._release_setup`, the BBL event buffer).
        Returning () is the honest answer, not a placeholder.
        """
        return ()

    def discard(self):
        """Forget nothing: this manager records nothing to forget.

        `Debugger.terminate_process()` calls this on a killed target. Unlike
        the managers that track what they installed, this one keeps no record
        — reads/writes use the session's handle and allocations belong to the
        caller — so there is nothing to drop.
        """
        return None
