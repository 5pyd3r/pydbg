"""Read-only detection of the state an anti-debug check would observe.

`detect(dbg)` answers one question per row: **would this technique see the
target being debugged right now?** It is a debugging-state report, not a
verdict about the target's intent. `IsDebuggerPresent`,
`CheckRemoteDebuggerPresent` and the `NtQueryInformationProcess` classes report
kernel state that is set by the debugger, so they read True for *every*
debugged process — including `simple_target`, which asks nothing. Only the
0xCC sweep looks at the image itself.

Nothing here writes to the target and no bypass is provided (spec §13.2,
§13.9); timing checks are out of scope. Every check is independent: a query that
fails turns into `detected=False` with the failure in `evidence`, and the
remaining checks still run.

Reading the PEB is what ties the checks to the target: its address comes from
`NtQueryInformationProcess(ProcessBasicInformation)` and its bytes are read
through `Debugger.read_memory` — the same read path every other read-only tool
in the package uses.
"""

import ctypes
import struct
from dataclasses import dataclass

from .exceptions import ProcessError

# ── PEB ────────────────────────────────────────────────────────
# BeingDebugged stayed at 0x02 across both layouts; NtGlobalFlag and
# ImageBaseAddress moved when the pointer-sized fields grew.
_PEB_X64 = {"being_debugged": 0x02, "nt_global_flag": 0xBC,
            "image_base": 0x10}
_PEB_X86 = {"being_debugged": 0x02, "nt_global_flag": 0x68,
            "image_base": 0x08}

# FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK |
# FLG_HEAP_VALIDATE_PARAMETERS. A debugged process is created with these set;
# `ntdll` heap code then behaves differently, which is the point of the check.
NT_GLOBAL_FLAG_DEBUG_MASK = 0x70

# One PE header page is enough for MZ, e_lfanew, the PE signature, and the
# optional header fields read below.
_PE_HEADER_READ = 0x1000
_PEB_READ = 0x100

# DR7 bits 2n/2n+1 are Ln/Gn: a set pair means slot n is a live breakpoint.
_DR_SLOTS = 4

# ── ntdll information classes ────────────────────────────────
PROCESS_BASIC_INFORMATION = 0
PROCESS_DEBUG_PORT = 7
PROCESS_DEBUG_OBJECT_HANDLE = 30
PROCESS_DEBUG_FLAGS = 31
SYSTEM_KERNEL_DEBUGGER_INFORMATION = 0x23

STATUS_PORT_NOT_SET = 0xC0000353
# What a 64-bit caller receives for these two: even a WOW64 target answers the
# 64-bit PROCESS_BASIC_INFORMATION layout, and the package's build policy is
# x64 (see pydbg.HOST_ARCH).
_PROCESS_BASIC_INFORMATION_SIZE = 0x30
_PEB_ADDRESS_OFFSET = 0x08
_ULONG_PTR_SIZE = 8

# What a write of 0xCC looks like in the image: an INT3, which is both a
# software breakpoint and a common anti-debug probe.
_INT3 = 0xCC


@dataclass(frozen=True)
class DebuggerCheck:
    """One technique's answer: a name, its verdict, and the facts behind it.

    'evidence' is deliberately facts, not a sentence about guilt: the value
    read, the status returned, or the reason the query failed. A caller that
    wants to explain the finding has everything it needs; one that only counts
    `detected` does not have to parse prose.
    """

    name: str
    detected: bool
    evidence: str


# ── pure PEB helpers ─────────────────────────────────────────

def peb_offsets(arch):
    """Byte offsets of the PEB fields read here, for 32- or 64-bit targets.

    x86 and x64 have different PEB layouts (NtGlobalFlag is 0x68 vs 0xBC;
    ImageBaseAddress 0x08 vs 0x10), and a WOW64 target uses the 32-bit
    layout. Returning a dict keeps callers naming the field instead of
    carrying the numbers.
    """
    if arch == 64:
        return dict(_PEB_X64)
    if arch == 32:
        return dict(_PEB_X86)
    raise ValueError(f"unsupported target architecture {arch!r}: expected 32 or 64")


def parse_peb(data, arch):
    """Decode the three PEB fields from a raw read of the PEB.

    Raises ValueError for a buffer too short to hold the fields of that
    layout — a partial read is not evidence of anything.
    """
    offsets = peb_offsets(arch)
    pointer = 8 if arch == 64 else 4
    needed = max(offsets["nt_global_flag"] + 4, offsets["image_base"] + pointer)
    if len(data) < needed:
        raise ValueError(
            f"PEB read is {len(data)} bytes; the {arch}-bit layout needs "
            f"{needed}")
    return {
        "being_debugged": data[offsets["being_debugged"]],
        "nt_global_flag": struct.unpack_from(
            "<I", data, offsets["nt_global_flag"])[0],
        "image_base": struct.unpack_from(
            "<Q" if arch == 64 else "<I", data, offsets["image_base"])[0],
    }


# ── pure image helpers ──────────────────────────────────────

def entry_point_from_image(image, image_base):
    """VA of AddressOfEntryPoint from the mapped PE header page, or None.

    'image' is a read starting at 'image_base'; only the headers are looked
    at. Raises ValueError when the bytes are not a PE image whose entry-point
    field can be located, so a caller can tell "no entry point" from "could
    not read one".
    """
    if len(image) < 0x40 or image[:2] != b"MZ":
        raise ValueError("image does not start with an MZ header")
    e_lfanew = struct.unpack_from("<I", image, 0x3C)[0]
    if e_lfanew + 0x2C > len(image):
        raise ValueError(
            f"e_lfanew 0x{e_lfanew:X} points outside the {len(image)}-byte "
            f"header read")
    if image[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError(f"no PE signature at image+0x{e_lfanew:X}")
    optional = e_lfanew + 24          # signature + IMAGE_FILE_HEADER
    magic = struct.unpack_from("<H", image, optional)[0]
    if magic not in (0x10B, 0x20B):   # PE32 / PE32+
        raise ValueError(f"unknown optional-header magic 0x{magic:X}")
    entry_rva = struct.unpack_from("<I", image, optional + 0x10)[0]
    if not entry_rva:
        return None
    return image_base + entry_rva


def scan_int3(data, start=0):
    """Absolute addresses of every 0xCC byte in 'data'.

    Offsets are returned as addresses (start + offset) because that is what a
    caller reports as evidence; a bare index would need the start again.
    """
    return [start + offset for offset, byte in enumerate(data) if byte == _INT3]


def debug_register_state(registers):
    """Facts from one thread's register dict: (nonzero slots, enabled, dr7).

    'slots' are DR0-3 that hold an address; 'enabled' are the slots whose
    DR7 Ln/Gn pair is set. They are reported separately because an address
    left in a disabled slot and an enabled slot with no address mean
    different things.
    """
    slots = tuple(slot for slot in range(_DR_SLOTS)
                  if registers.get(f"dr{slot}", 0))
    dr7 = registers.get("dr7", 0)
    enabled = tuple(slot for slot in range(_DR_SLOTS)
                    if dr7 & (0x3 << (slot * 2)))
    return slots, enabled, dr7


# ── checks (implemented against a read-only probe) ──────────

# How much code before AddressOfEntryPoint the 0xCC sweep covers (spec §13.2).
_ENTRY_SCAN_BYTES = 64

# A software breakpoint and the classic anti-debug probe are the same byte;
# evidence says where it is rather than pretending to know who wrote it.
_INT3_NOTE = ("an INT3 here may be the debugger's own software breakpoint")


def _peb_being_debugged(probe):
    """The PEB byte that `IsDebuggerPresent` and `PEB.BeingDebugged` both read.

    The two rows are two labels on one kernel-backed fact, so they share this
    read and its evidence spelling: (raw byte, PEB offset, "PEB+0xN=0xNN").
    Reading it twice would let the two rows disagree about the same byte.
    """
    offset = peb_offsets(probe.arch)["being_debugged"]
    raw = probe.peb["being_debugged"]
    return raw, offset, f"PEB+0x{offset:X}=0x{raw:02X}"


def _nt_call(query, what, *args, tolerate=()):
    """Run one NT query; return (status, raw bytes) or raise OSError.

    Every `NtQueryInformationProcess`/`NtQuerySystemInformation` site raises
    the same "failed: NTSTATUS 0x..." OSError, so the template lives here
    instead of being copied at each call. 'tolerate' names statuses the check
    handles itself (STATUS_PORT_NOT_SET means "no debug object", not a
    failure); those come back to the caller instead of raising.
    """
    status, raw = query(*args)
    if status != 0 and status not in tolerate:
        raise OSError(f"{what} failed: NTSTATUS 0x{status:08X}")
    return status, raw


def _check_is_debugger_present(probe):
    raw, _offset, fact = _peb_being_debugged(probe)
    return raw != 0, (
        f"{fact} (PEB at 0x{probe.peb_address:X}); "
        f"kernel32!IsDebuggerPresent would return {raw}")


def _check_check_remote_debugger_present(probe):
    present = probe.remote_debugger_present()
    return present != 0, (
        f"CheckRemoteDebuggerPresent(hProcess=0x{probe.process_handle:X}) "
        f"answered BOOL={present}")


def _check_peb_being_debugged(probe):
    raw, _offset, fact = _peb_being_debugged(probe)
    return raw != 0, (
        f"{fact} (PEB at 0x{probe.peb_address:X}, {probe.arch}-bit layout)")


def _check_peb_nt_global_flag(probe):
    offset = peb_offsets(probe.arch)["nt_global_flag"]
    value = probe.peb["nt_global_flag"]
    masked = value & NT_GLOBAL_FLAG_DEBUG_MASK
    return bool(masked), (
        f"PEB+0x{offset:X} = 0x{value:X}; 0x{NT_GLOBAL_FLAG_DEBUG_MASK:X} "
        f"mask leaves 0x{masked:X}")


def _check_process_debug_port(probe):
    status, raw = _nt_call(
        probe.process_info, "NtQueryInformationProcess(ProcessDebugPort)",
        PROCESS_DEBUG_PORT, _ULONG_PTR_SIZE)
    port = int.from_bytes(raw, "little")
    return port != 0, (
        f"ProcessDebugPort=0x{port:X} (NTSTATUS 0x{status:08X}); a user-mode "
        f"debugger sets a non-zero port")


def _check_process_debug_flags(probe):
    status, raw = _nt_call(
        probe.process_info, "NtQueryInformationProcess(ProcessDebugFlags)",
        PROCESS_DEBUG_FLAGS, 4)
    flags = int.from_bytes(raw, "little")
    return flags == 0, (
        f"ProcessDebugFlags={flags} (NTSTATUS 0x{status:08X}); 0 means the "
        f"target is being debugged, so this answer is inverted")


def _check_process_debug_object_handle(probe):
    status, raw = _nt_call(
        probe.process_info,
        "NtQueryInformationProcess(ProcessDebugObjectHandle)",
        PROCESS_DEBUG_OBJECT_HANDLE, _ULONG_PTR_SIZE,
        tolerate=(STATUS_PORT_NOT_SET,))
    if status == STATUS_PORT_NOT_SET:
        return False, (f"NTSTATUS 0x{status:08X} STATUS_PORT_NOT_SET: no "
                       f"debug object is attached")
    handle = int.from_bytes(raw, "little")
    return handle != 0, (
        f"ProcessDebugObjectHandle=0x{handle:X} (NTSTATUS 0x{status:08X})")


def _check_hardware_breakpoints(probe):
    tids = probe.threads()
    if not tids:
        return False, "no thread was found to read debug registers from"
    detected = False
    parts = []
    failures = []
    for tid in tids:
        try:
            registers = probe.registers(tid)
        except Exception as exc:      # one dead thread must not hide the rest
            failures.append(f"tid={tid}: {type(exc).__name__}: {exc}")
            continue
        slots, enabled, dr7 = debug_register_state(registers)
        values = " ".join(
            f"DR{slot}=0x{registers.get(f'dr{slot}', 0):X}"
            for slot in range(_DR_SLOTS))
        parts.append(f"tid={tid} {values} DR7=0x{dr7:X}")
        if slots or enabled:
            detected = True
    evidence = "; ".join(parts + failures)
    if not parts:
        evidence = "no thread context could be read: " + "; ".join(failures)
    return detected, evidence


def _check_int3_scan(probe):
    image_base = probe.peb["image_base"]
    entry = entry_point_from_image(probe.image(), image_base)
    if entry is None:
        return False, "the PE image declares no entry point"
    start = max(entry - _ENTRY_SCAN_BYTES, image_base)
    data = probe.read(start, entry - start)
    hits = scan_int3(data, start)
    if not hits:
        return False, (
            f"no 0xCC in the {len(data)} bytes before entry 0x{entry:X} "
            f"([0x{start:X}, 0x{entry:X}))")
    where = ", ".join(f"entry-{entry - addr}" for addr in hits)
    return True, (
        f"{len(hits)} 0xCC byte(s) at {where} in the {len(data)} bytes "
        f"before entry 0x{entry:X}; {_INT3_NOTE}")


def _check_kernel_debugger_information(probe):
    status, raw = _nt_call(
        probe.system_info,
        "NtQuerySystemInformation(SystemKernelDebuggerInformation)",
        SYSTEM_KERNEL_DEBUGGER_INFORMATION, 2)
    enabled = bool(raw[0]) if len(raw) > 0 else False
    not_present = bool(raw[1]) if len(raw) > 1 else True
    return enabled and not not_present, (
        f"KernelDebuggerEnabled={enabled}, "
        f"KernelDebuggerNotPresent={not_present} "
        f"(NTSTATUS 0x{status:08X}); this is host state, not the target's")


_CHECKS = (
    ("IsDebuggerPresent", _check_is_debugger_present),
    ("CheckRemoteDebuggerPresent", _check_check_remote_debugger_present),
    ("PEB.BeingDebugged", _check_peb_being_debugged),
    ("PEB.NtGlobalFlag", _check_peb_nt_global_flag),
    ("NtQueryInformationProcess(ProcessDebugPort)", _check_process_debug_port),
    ("NtQueryInformationProcess(ProcessDebugFlags)",
     _check_process_debug_flags),
    ("NtQueryInformationProcess(ProcessDebugObjectHandle)",
     _check_process_debug_object_handle),
    ("HardwareBreakpoints", _check_hardware_breakpoints),
    ("INT3Scan", _check_int3_scan),
    ("NtQuerySystemInformation(SystemKernelDebuggerInformation)",
     _check_kernel_debugger_information),
)


def _run_checks(probe):
    """Run every check, converting one failure into that check's evidence.

    Deliberately not short-circuiting: an unreadable PEB must not hide the
    ntdll answers, and a refused thread context must not hide everything
    else. The exception is caught here, not swallowed silently — its type and
    message become evidence.
    """
    checks = []
    for name, check in _CHECKS:
        try:
            detected, evidence = check(probe)
        except Exception as exc:      # one broken query must not hide the rest
            detected = False
            evidence = f"query failed: {type(exc).__name__}: {exc}"
        checks.append(DebuggerCheck(name, bool(detected), evidence))
    return tuple(checks)


# ── public API ─────────────────────────────────────────────

def detect(dbg):
    """Report, per read-only technique, whether the target looks debugged.

    Returns a tuple of `DebuggerCheck` in a fixed order covering
    IsDebuggerPresent, CheckRemoteDebuggerPresent, PEB BeingDebugged and
    NtGlobalFlag, the three NtQueryInformationProcess classes, hardware
    breakpoints (DR0-3/DR7), a 0xCC sweep of the 64 bytes before the entry
    point, and NtQuerySystemInformation(SystemKernelDebuggerInformation).

    The checks measure the *debugging state*, not the target's behaviour: a
    process that never calls an anti-debug API still reports the API classes
    as detected=True while it is being debugged, and every target reports them
    as False once no debugger is attached — whether or not it asked. The
    SystemKernelDebuggerInformation row is host-wide kernel-debugger state,
    not a property of this target.

    Raises ProcessError (a PydbgError) when no target is attached. Any other
    failure is confined to the check that hit it: that check becomes
    detected=False and its evidence names the failure, while the rest still
    run.
    """
    session = getattr(dbg, "_session", None)
    if session is None or session.pid is None:
        raise ProcessError(
            "antidebug.detect() needs an attached target: create_process() "
            "or attach() first")
    return _run_checks(_LiveProbe(dbg))


# ── read-only probe over a live target ──────────────────────

class _Nt:
    """Lazy ctypes bindings for the two ntdll queries and one kernel32 query.

    These are read-only probes with no Cython wrapper, so they are bound the
    way `pydbg.pdb.dbghelp` binds dbghelp: on first use, from a DLL the loader
    already has. Binding them here keeps a detection-only feature from
    requiring a rebuild of the extension.
    """

    def __init__(self):
        self._ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        self._ntdll.NtQueryInformationProcess.argtypes = [
            ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
            ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
        self._ntdll.NtQueryInformationProcess.restype = ctypes.c_long
        self._ntdll.NtQuerySystemInformation.argtypes = [
            ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ulong)]
        self._ntdll.NtQuerySystemInformation.restype = ctypes.c_long
        self._kernel32.CheckRemoteDebuggerPresent.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
        self._kernel32.CheckRemoteDebuggerPresent.restype = ctypes.c_int

    @staticmethod
    def _unsigned(status):
        return status & 0xFFFFFFFF

    def query_process(self, h_process, info_class, size):
        """(NTSTATUS, raw bytes) for one NtQueryInformationProcess call."""
        buffer = ctypes.create_string_buffer(max(size, 1))
        returned = ctypes.c_ulong(0)
        status = self._ntdll.NtQueryInformationProcess(
            ctypes.c_void_p(h_process), info_class, buffer, size,
            ctypes.byref(returned))
        return self._unsigned(status), buffer.raw[:size]

    def query_system(self, info_class, size):
        """(NTSTATUS, raw bytes) for one NtQuerySystemInformation call."""
        buffer = ctypes.create_string_buffer(max(size, 1))
        returned = ctypes.c_ulong(0)
        status = self._ntdll.NtQuerySystemInformation(
            info_class, buffer, size, ctypes.byref(returned))
        return self._unsigned(status), buffer.raw[:size]

    def process_basic_information(self, h_process):
        """PebBaseAddress from NtQueryInformationProcess(ProcessBasicInformation)."""
        _status, raw = _nt_call(
            self.query_process,
            "NtQueryInformationProcess(ProcessBasicInformation)",
            h_process, PROCESS_BASIC_INFORMATION,
            _PROCESS_BASIC_INFORMATION_SIZE)
        return struct.unpack_from("<Q", raw, _PEB_ADDRESS_OFFSET)[0]

    def check_remote_debugger_present(self, h_process):
        """The BOOL kernel32!CheckRemoteDebuggerPresent fills in."""
        present = ctypes.c_int(0)
        ok = self._kernel32.CheckRemoteDebuggerPresent(
            ctypes.c_void_p(h_process), ctypes.byref(present))
        if not ok:
            raise OSError(ctypes.get_last_error(),
                          "CheckRemoteDebuggerPresent failed")
        return present.value


_NT = None


def _ntdll():
    global _NT
    if _NT is None:
        _NT = _Nt()
    return _NT


class _LiveProbe:
    """The read side of `detect` for one live target.

    Everything the checks need is a method here, so the checks themselves are
    pure over a probe and a test can substitute fabricated facts (including
    failures) without a process or the extension.
    """

    def __init__(self, dbg):
        self._dbg = dbg
        self._nt = _ntdll()
        self._peb = None
        self._peb_address = None
        self._image = None
        self.process_handle = dbg._session.process_handle
        self.arch = dbg._session.target_arch

    @property
    def peb_address(self):
        if self._peb_address is None:
            self._peb_address = self._nt.process_basic_information(
                self.process_handle)
        return self._peb_address

    @property
    def peb(self):
        if self._peb is None:
            self._peb = parse_peb(
                self._dbg.read_memory(self.peb_address, _PEB_READ), self.arch)
        return self._peb

    def image(self):
        """The PE header page mapped at the image base named by the PEB."""
        if self._image is None:
            self._image = self._dbg.read_memory(
                self.peb["image_base"], _PE_HEADER_READ)
        return self._image

    def read(self, addr, size):
        return self._dbg.read_memory(addr, size)

    def process_info(self, info_class, size):
        return self._nt.query_process(self.process_handle, info_class, size)

    def system_info(self, info_class, size):
        return self._nt.query_system(info_class, size)

    def remote_debugger_present(self):
        return self._nt.check_remote_debugger_present(self.process_handle)

    def threads(self):
        tids = [thread["tid"] for thread in self._dbg.enumerate_threads()]
        if tids:
            return tids
        tid = self._dbg._session.tid
        return [tid] if tid is not None else []

    def registers(self, tid):
        return self._dbg.get_registers(tid)
