"""ModuleResolver — enumerate modules and resolve filenames.

On a WOW64 target the debugger runs in the 64-bit host while the target's own
images are 32-bit. The unfiltered enumeration reports both tables; a caller
that needs the 32-bit table by itself asks for it with `enumerate(arch=32)`.

That view has a boundary the caller has to plan around: Windows only reports
the 32-bit module table once the WOW64 target has actually mapped its image.
The first loader breakpoint — the 64-bit bootstrap, before the 32-bit image
exists — is too early, exactly the window `_read_pe_info` below warns about,
and there the filtered call still fails with ERROR_PARTIAL_COPY. So
`enumerate(arch=32)` raises MemError instead of returning a short list; the
answer appears once the loader events have mapped the image, at or before the
WX86 loader breakpoint.

The view is selected by the TARGET's architecture (`session.pid_arch`, through
`arch_for_pid`), never by the host's: on this x64 host a 32-bit target's
32-bit view works, and asking that same target for a 64-bit view raises
PydbgError rather than returning an empty list.
"""

import struct

from .. import _pydbg
from ..constants import LIST_MODULES_32BIT, LIST_MODULES_64BIT
from ..exceptions import MemError, PydbgError

# PE IMAGE_FILE_HEADER.Machine -> architecture label.
_MACHINE_TO_ARCH = {0x14C: "x86", 0x8664: "x64"}

# Optional-header extras we need, expressed as offsets into the PE header.
_NT_FILE_HEADER = 4 + 20          # Signature + IMAGE_FILE_HEADER
_SIZE_OF_IMAGE_OFFSET = 56        # same for PE32 and PE32+
_OPTIONAL_HEADER_SIZE = {0x10B: 96, 0x20B: 112}

# EnumProcessModulesEx filter for each module table a caller may request.
_MODULE_VIEW_FLAGS = {32: LIST_MODULES_32BIT, 64: LIST_MODULES_64BIT}

# Accepted spellings of the requested table's architecture. Module dicts label
# their own arch 'x86'/'x64', so those labels are accepted alongside 32/64.
_MODULE_VIEW_ALIASES = {32: 32, "32": 32, "x86": 32,
                        64: 64, "64": 64, "x64": 64}


def _module_view_arch(arch):
    """Normalise a requested module-table architecture; None keeps every table."""
    if arch is None:
        return None
    try:
        return _MODULE_VIEW_ALIASES[arch]
    except (KeyError, TypeError):
        raise ValueError(
            "module view architecture must be None, 32 or 64 "
            f"(or 'x86'/'x64'), not {arch!r}") from None


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

    def enumerate(self, arch=None):
        """Return list of loaded modules with handle, base_address, name, arch.

        Each dict: {'handle': int, 'base_address': int, 'name': str,
                    'arch': 'x86' | 'x64' | 'unknown', 'size': int}
        'name' is the full filesystem path to the module file. 'arch' is
        derived from the module's PE header machine field, so WOW64 targets
        yield both 32-bit modules ('x86') and 64-bit modules ('x64').

        'arch' reads one module table instead of both: 32/'x86' for the
        32-bit table, 64/'x64' for the 64-bit one, None for the historical
        LIST_MODULES_ALL answer. A table the target cannot have raises
        PydbgError rather than returning an empty list — a native 64-bit
        target has no 32-bit modules, and a 32-bit (WOW64) target has no
        64-bit table. See the module docstring for when the 32-bit table
        becomes visible.
        """
        return self.enumerate_handle(
            self._s.process_handle, allow_event_fallback=True, arch=arch)

    def enumerate_handle(self, h_process, allow_event_fallback=False, pid=None,
                         arch=None):
        """Same as enumerate() but with explicit process handle.

        With allow_event_fallback, a failing EnumProcessModulesEx falls back to
        the module base addresses recorded from debug events, and event-known
        modules missing from the PSAPI result are merged in ('source' marks
        which those are). Both matter around the loader breakpoint: PSAPI
        raises ERROR_PARTIAL_COPY there, and on WOW64 it cannot see the 32-bit
        image until the loader has mapped it. The fallback belongs to the
        unfiltered view only: an arch-filtered answer must not contain a
        module whose architecture has not been proven yet, so those calls are
        PSAPI-only and raise MemError until the table exists.

        'pid' names the process h_process belongs to, and is only used to pick
        which event table the fallback merges from; it defaults to the session's
        target, which is the historical behaviour. Passing it matters: the
        event table is per pid, so without it a read of some *other* process
        would merge the target's modules into that process's answer — a
        plausible-looking list of the wrong DLLs at the wrong addresses.

        'arch' is as in enumerate(). It is checked against the session's record
        for 'pid' before any Win32 call, so the table is selected by the
        target's architecture and a mismatch costs nothing.
        """
        view_arch = _module_view_arch(arch)
        if view_arch is not None:
            target_pid = self._s.pid if pid is None else pid
            target_arch = self._s.arch_for_pid(target_pid)
            if target_arch != view_arch:
                raise PydbgError(
                    f"{view_arch}-bit module view requested for a "
                    f"{target_arch}-bit target (pid {target_pid}): a process "
                    "has a module table only for its own architecture")
            try:
                modules = _pydbg.enum_process_modules_ex(
                    h_process, _MODULE_VIEW_FLAGS[view_arch])
            except OSError as e:
                raise MemError(
                    f"EnumProcessModulesEx({view_arch}-bit): {e}") from e
            return self._decorate(h_process, modules)

        try:
            modules = _pydbg.enum_process_modules(h_process)
        except OSError as e:
            if not allow_event_fallback:
                raise MemError(f"EnumProcessModules: {e}")
            modules = []

        self._decorate(h_process, modules)

        if allow_event_fallback:
            self._merge_event_modules(
                h_process, modules, self._s.pid if pid is None else pid)
        return modules

    def _merge_event_modules(self, h_process, modules, pid):
        """Add modules seen in debug events for 'pid' that PSAPI did not report."""
        recorded = self._s.modules_for(pid)
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
            h_proc, allow_event_fallback=(target_pid == self._s.pid),
            pid=target_pid)
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
        """Process handle for 'pid', or None if it is not a known process.

        The lookup itself belongs to ProcessManager, which is also what the
        read and write paths ask; this used to be a fourth, slightly different
        answer to the same question.
        """
        from ..core.process import ProcessManager
        return ProcessManager(self._s).try_handle(pid)

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
