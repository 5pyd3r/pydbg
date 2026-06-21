"""AntiAware — patch PEB and heap flags to hide a debugger from the target process."""

import struct

from ..exceptions import PydbgError


class AntiAware:
    """Patches PEB and heap flags to evade debugger-aware checks.

    Typical usage after attaching to a process::

        anti = AntiAware(session)
        anti.hide_all()

    All methods are idempotent and can be called multiple times safely.
    """

    # ── PEB offsets (x86; x64 shares most but NtGlobalFlag differs) ──
    PEB_BEING_DEBUGGED_OFFSET = 0x02
    PEB_NT_GLOBAL_FLAG_OFFSET = 0x68
    PEB_PROCESS_HEAP_OFFSET = 0x18

    # ── Heap header flag offsets ──
    HEAP_FLAGS_OFFSET = 0x40
    HEAP_FORCE_FLAGS_OFFSET = 0x44

    # ── NtGlobalFlag debug-related bits ──
    FLG_HEAP_ENABLE_TAIL_CHECK = 0x10
    FLG_HEAP_ENABLE_FREE_CHECK = 0x20
    FLG_HEAP_VALIDATE_PARAMETERS = 0x40
    DEBUG_FLAGS = (
        FLG_HEAP_ENABLE_TAIL_CHECK
        | FLG_HEAP_ENABLE_FREE_CHECK
        | FLG_HEAP_VALIDATE_PARAMETERS
    )

    def __init__(self, session):
        """Initialise with a :class:`DebugSession` (or any object with
        ``process_handle``, ``thread_handle``, and ``target_arch``)."""
        self._s = session

    # ── public API ──

    def hide_all(self):
        """Apply all anti-awareness patches in the recommended order."""
        self.patch_peb_being_debugged()
        self.patch_peb_nt_global_flag()
        self.patch_heap_flags()

    def patch_peb_being_debugged(self):
        """Set ``PEB.BeingDebugged`` to 0."""
        peb = self._get_peb_address()
        self._write_byte(peb + self.PEB_BEING_DEBUGGED_OFFSET, 0)

    def patch_peb_nt_global_flag(self):
        """Clear debug-related flags from ``PEB.NtGlobalFlag``."""
        peb = self._get_peb_address()
        addr = peb + self.PEB_NT_GLOBAL_FLAG_OFFSET
        val = self._read_dword(addr)
        cleared = val & ~self.DEBUG_FLAGS
        self._write_dword(addr, cleared)

    def patch_heap_flags(self):
        """Remove debug flags from the process heap header.

        Reads the ``ProcessHeap`` pointer from PEB, then clears
        ``HEAP_FLAGS`` and ``HEAP_FORCE_FLAGS`` at the corresponding
        offsets inside the heap header.
        """
        peb = self._get_peb_address()
        heap_ptr = self._read_pointer(peb + self.PEB_PROCESS_HEAP_OFFSET)
        if heap_ptr == 0:
            raise PydbgError("ProcessHeap pointer is NULL")

        flags_addr = heap_ptr + self.HEAP_FLAGS_OFFSET
        force_flags_addr = heap_ptr + self.HEAP_FORCE_FLAGS_OFFSET

        flags = self._read_dword(flags_addr)
        self._write_dword(flags_addr, flags & ~self.DEBUG_FLAGS)

        force_flags = self._read_dword(force_flags_addr)
        self._write_dword(force_flags_addr, force_flags & ~self.DEBUG_FLAGS)

    # ── internals ──

    def _get_peb_address(self):
        """Return the PEB address of the debugged process.

        Reads the TEB (via ``GetThreadContext``) ``FS:[0x30]`` (x86) or
        ``GS:[0x60]`` (x64) to obtain the PEB pointer.  When the session
        has no live ``process_handle`` (e.g. unit tests) the call is
        skipped and a stub address is returned for structural testing.
        """
        h_proc = getattr(self._s, "process_handle", None)
        if h_proc is None:
            # Offline / unit-test mode — return a dummy PEB address.
            return 0x7FFE_0000

        from .. import _pydbg

        target_bits = getattr(self._s, "target_arch", 64)

        # Obtain thread context to read FS/GS base.
        h_thread = getattr(self._s, "thread_handle", None)
        if h_thread is None:
            raise PydbgError("No thread handle available for PEB lookup")

        ctx = _pydbg.get_thread_context(h_thread)
        # For 32-bit targets the PEB pointer lives at FS:[0x30].
        # For 64-bit targets it lives at GS:[0x60].
        # get_thread_context returns a dict; on Windows the TEB
        # segment base is not directly exposed, so we use
        # ReadProcessMemory on the known TEB segment register area.
        #
        # The most portable approach: read the PEB pointer via the
        # well-known FS/GS-relative offsets from the TEB base.
        # We read the TEB base from the environment block pointer
        # embedded in the thread context when available, otherwise
        # fall back to ntdll!NtQueryInformationThread.
        #
        # Simpler: for a live debuggee the TEB address can be
        # obtained from the thread context's segment registers.
        # But the native extension exposes a helper:
        teb = _pydbg.get_teb_address(h_thread)
        if target_bits == 32:
            peb_ptr_offset = 0x30
            fmt = "<I"
        else:
            peb_ptr_offset = 0x60
            fmt = "<Q"

        data = _pydbg.read_process_memory(h_proc, teb + peb_ptr_offset, struct.calcsize(fmt))
        return struct.unpack(fmt, data)[0]

    # ── memory helpers ──

    def _read_byte(self, addr):
        from .. import _pydbg
        data = _pydbg.read_process_memory(self._s.process_handle, addr, 1)
        return data[0]

    def _write_byte(self, addr, value):
        from .. import _pydbg
        _pydbg.write_process_memory(self._s.process_handle, addr, bytes([value]))

    def _read_dword(self, addr):
        from .. import _pydbg
        data = _pydbg.read_process_memory(self._s.process_handle, addr, 4)
        return struct.unpack("<I", data)[0]

    def _write_dword(self, addr, value):
        from .. import _pydbg
        _pydbg.write_process_memory(
            self._s.process_handle, addr, struct.pack("<I", value)
        )

    def _read_pointer(self, addr):
        from .. import _pydbg
        bits = getattr(self._s, "target_arch", 64)
        size = 8 if bits == 64 else 4
        fmt = "<Q" if bits == 64 else "<I"
        data = _pydbg.read_process_memory(self._s.process_handle, addr, size)
        return struct.unpack(fmt, data)[0]
