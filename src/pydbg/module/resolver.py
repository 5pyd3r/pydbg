"""ModuleResolver — enumerate modules and resolve filenames."""

import struct

from .. import _pydbg
from ..exceptions import MemError

# PE IMAGE_FILE_HEADER.Machine -> architecture label.
_MACHINE_TO_ARCH = {0x14C: "x86", 0x8664: "x64"}

# Optional-header extras we need, expressed as offsets into the PE header.
_NT_FILE_HEADER = 4 + 20          # Signature + IMAGE_FILE_HEADER
_SIZE_OF_IMAGE_OFFSET = 56        # same for PE32 and PE32+
_OPTIONAL_HEADER_SIZE = {0x10B: 96, 0x20B: 112}


class ModuleResolver:
    """Resolves module information for the debugged process."""

    def __init__(self, session):
        self._s = session

    # ── live PE header reads ───────────────────────────────────

    @staticmethod
    def _read_pe_info(h_proc, base):
        """Best-effort (arch, size, name) for the image mapped at 'base'.

        Reads the image's own PE header instead of asking PSAPI, because this
        is the path that still works while the target sits on the loader
        breakpoint — precisely when module information is first wanted, and
        precisely when EnumProcessModulesEx answers ERROR_PARTIAL_COPY. On a
        WOW64 target the 32-bit image is not even mapped that early, so the
        64-bit bootstrap enumeration cannot see it at all.

        'name' comes from the export directory, which is how a DLL records its
        own filename; a main executable usually has no export directory, so ''
        is the normal answer there. Returns ('unknown', 0, '') when nothing
        could be read.
        """
        arch, size, name = "unknown", 0, ""
        try:
            dos = _pydbg.read_process_memory(h_proc, base, 0x40)
            if len(dos) < 0x40 or dos[:2] != b"MZ":
                return arch, size, name
            e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
            # Enough for the signature, the file header, and the data
            # directories of either optional-header flavour.
            nt = _pydbg.read_process_memory(h_proc, base + e_lfanew, 0x100)
            if len(nt) < 0x60 or nt[:4] != b"PE\x00\x00":
                return arch, size, name
            machine = struct.unpack_from("<H", nt, 4)[0]
            arch = _MACHINE_TO_ARCH.get(machine, "unknown")
            size = struct.unpack_from(
                "<I", nt, _NT_FILE_HEADER + _SIZE_OF_IMAGE_OFFSET)[0]
            magic = struct.unpack_from("<H", nt, _NT_FILE_HEADER)[0]
            dir_off = _OPTIONAL_HEADER_SIZE.get(magic)
            if dir_off is not None:
                export_rva = struct.unpack_from(
                    "<I", nt, _NT_FILE_HEADER + dir_off)[0]
                name = ModuleResolver._export_name(h_proc, base, export_rva)
        except (OSError, TypeError, struct.error):
            pass
        return arch, size, name

    @staticmethod
    def _export_name(h_proc, base, export_rva):
        """Module filename from the export directory, or '' if it has none."""
        if not export_rva:
            return ""
        hdr = _pydbg.read_process_memory(h_proc, base + export_rva, 16)
        if len(hdr) < 16:
            return ""
        name_rva = struct.unpack_from("<I", hdr, 12)[0]
        if not name_rva:
            return ""
        raw = _pydbg.read_process_memory(h_proc, base + name_rva, 260)
        end = raw.find(b"\x00")
        if end != -1:
            raw = raw[:end]
        return raw.decode("ascii", errors="replace")

    @classmethod
    def _module_arch(cls, h_proc, base):
        """Determine a module's architecture by reading its PE header machine."""
        return cls._read_pe_info(h_proc, base)[0]

    # ── enumeration ────────────────────────────────────────────

    def _decorate(self, h_process, modules):
        """Fill in arch/size/name for each module dict, in place."""
        for m in modules:
            arch, size, name = self._read_pe_info(h_process, m["base_address"])
            m["arch"] = arch
            if size:
                m["size"] = size
            try:
                m["name"] = _pydbg.get_module_file_name_ex(h_process, m["handle"])
            except OSError:
                # PSAPI has no filename for it; the export directory often does.
                m["name"] = name
        return modules

    def enumerate(self):
        """Return list of loaded modules with handle, base_address, name, arch.

        Each dict: {'handle': int, 'base_address': int, 'name': str,
                    'arch': 'x86' | 'x64' | 'unknown', 'size': int}
        'name' is the full filesystem path to the module file. 'arch' is
        derived from the module's PE header machine field, so WOW64 targets
        yield both 32-bit modules ('x86') and 64-bit modules ('x64').
        """
        return self.enumerate_handle(
            self._s.process_handle, allow_event_fallback=True)

    def enumerate_handle(self, h_process, allow_event_fallback=False):
        """Same as enumerate() but with explicit process handle.

        With allow_event_fallback, a failing EnumProcessModulesEx falls back to
        the module base addresses recorded from debug events, and event-known
        modules missing from the PSAPI result are merged in ('source' marks
        which those are). Both matter around the loader breakpoint: PSAPI
        raises ERROR_PARTIAL_COPY there, and on WOW64 it cannot see the 32-bit
        image until the loader has mapped it.
        """
        try:
            modules = _pydbg.enum_process_modules(h_process)
        except OSError as e:
            if not allow_event_fallback:
                raise MemError(f"EnumProcessModules: {e}")
            modules = []

        self._decorate(h_process, modules)

        if allow_event_fallback:
            self._merge_event_modules(h_process, modules)
        return modules

    def _merge_event_modules(self, h_process, modules):
        """Add modules seen in debug events that PSAPI did not report."""
        recorded = self._s.modules_for(self._s.pid)
        known = {m["base_address"] for m in modules}
        for rec in recorded:
            base = rec["base_address"]
            if not base or base in known:
                continue
            merged = self._decorate(h_process, [dict(rec)])[0]
            modules.append(merged)
            known.add(base)
        modules.sort(key=lambda m: m["base_address"])

    def module_at(self, addr, pid=None):
        """Return the module containing 'addr', or None.

        Consults the base addresses recorded from debug events first: that
        table is filled from CREATE_PROCESS / LOAD_DLL and needs no syscall, so
        it answers while the target is stopped on the loader breakpoint instead
        of raising the way enumerate() does. Falls back to PSAPI when no events
        have been seen (a session that never ran wait_event).
        """
        target_pid = self._s.pid if pid is None else pid
        h_proc = self._handle_for(target_pid)
        if h_proc is None:
            return None

        recorded = self._s.modules_for(target_pid)
        if recorded:
            self._decorate(h_proc, recorded)
            return self._find_containing(recorded, addr)

        modules = self.enumerate_handle(
            h_proc, allow_event_fallback=(target_pid == self._s.pid))
        return self._find_containing(modules, addr)

    @staticmethod
    def _find_containing(modules, addr):
        """First module whose [base, base + size) contains 'addr'."""
        for m in modules:
            size = m.get("size") or 0
            if size and m["base_address"] <= addr < m["base_address"] + size:
                return m
        return None

    def _handle_for(self, pid):
        """Process handle for 'pid', or None if it is not a known process."""
        if pid is None:
            return None
        if pid == self._s.pid:
            return self._s.process_handle
        child = self._s.child_processes.get(pid)
        return child.process_handle if child else None

    def get_filename(self, h_module):
        """Resolve a module handle to its filesystem path."""
        try:
            return _pydbg.get_module_file_name_ex(self._s.process_handle, h_module)
        except OSError as e:
            raise MemError(f"GetModuleFileNameEx: {e}")

    def find_module(self, name):
        """Find a module by name (case-insensitive basename match).

        Args:
            name: Module basename, e.g. 'kernel32.dll'

        Returns:
            dict with handle/base_address/name, or None if not found.
        """
        name_lower = name.lower()
        for m in self.enumerate():
            basename = m.get('name', '').split('\\')[-1].lower()
            if basename == name_lower:
                return m
        return None
