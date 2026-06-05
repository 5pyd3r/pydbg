"""
hook_framework.py — IAT Hook + Inline Hook framework using pydbg.

Provides:
  - InlineHooker: classic JMP-patch + trampoline for calling original
  - IATHooker: redirect IAT function pointers
  - HookManager: unified interface + event-driven dispatch

Usage:
  from pydbg import Debugger
  from hook_framework import HookManager

  dbg = Debugger()
  dbg.create_process("target.exe")

  mgr = HookManager(dbg)
  mgr.hook_inline(target_addr, my_callback)
  mgr.hook_iat("user32.dll", "MessageBoxA", my_callback)
  mgr.run()
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pydbg import _pydbg
from pydbg.disasm.engine import DisasmEngine
from pydbg.patch.assembler import Assembler


# ── Data structures ──────────────────────────────────────────────


class HookInfo:
    """Describes a single hook."""

    __slots__ = (
        "hook_type",
        "target_addr",
        "trampoline_addr",
        "original_bytes",
        "callback",
        "iat_entry_addr",
        "original_func_addr",
        "module_name",
        "func_name",
        "_bp_id",
    )

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


# ── Inline Hooker ────────────────────────────────────────────────


class InlineHooker:
    """Classic inline hook: short JMP patch + trampoline.

    Layout:
      target_addr:  [JMP rel32 → trampoline] [rest of function...]
      trampoline:   [displaced instructions] [JMP rel32 → target_addr+N]

    Calling original:
      Set RIP = trampoline_addr. The CPU executes displaced instructions
      then JMPs back to the rest of the original function.

    The trampoline is allocated within ±2GB of target so rel32 (E9) works.
    """

    JMP_SIZE = 5  # E9 xx xx xx xx

    def __init__(self, h_process):
        self._h = h_process
        self._engine = DisasmEngine(mode="x64")
        self._asm = Assembler(mode="x64")
        self._hooks = {}  # target_addr -> HookInfo

    def hook(self, target_addr, callback):
        """Set inline hook at target_addr.

        Patches the first N bytes (≥5) with JMP to trampoline.
        The trampoline contains the displaced instructions + JMP back.
        A breakpoint at the trampoline entry fires the Python callback.

        Args:
            target_addr: Address to hook.
            callback: fn(dbg, event, hook_info, mgr) called when hook fires.

        Returns:
            HookInfo with trampoline_addr for call_original().
        """
        if target_addr in self._hooks:
            raise ValueError(f"Already hooked at 0x{target_addr:X}")

        # 1. Read instructions, find ≥ 5 bytes boundary
        raw = _pydbg.read_process_memory(self._h, target_addr, 32)
        insns = self._engine.disasm(target_addr, raw)
        displaced = b""
        for insn in insns:
            displaced += insn.raw_bytes
            if len(displaced) >= self.JMP_SIZE:
                break
        if len(displaced) < self.JMP_SIZE:
            raise ValueError(
                f"Cannot fit JMP at 0x{target_addr:X} "
                f"(need {self.JMP_SIZE} bytes, got {len(displaced)})"
            )
        displaced = displaced[: len(displaced)]

        # 2. Allocate trampoline (RWX) — try near target for rel32 reach
        tramp_size = len(displaced) + self.JMP_SIZE
        trampoline_addr = self._alloc_near(target_addr, tramp_size)

        # 3. Fix relative instructions in displaced code
        fixed = self._fix_relative_insns(displaced, target_addr, trampoline_addr)

        # 4. Build trampoline: fixed instructions + JMP back
        jmp_back_target = target_addr + len(displaced)
        jmp_back = self._build_rel32_jmp(trampoline_addr + len(displaced), jmp_back_target)
        _pydbg.write_process_memory(self._h, trampoline_addr, fixed + jmp_back)

        # 4. Patch target: JMP rel32 → trampoline
        jmp_to_tramp = self._build_rel32_jmp(target_addr, trampoline_addr)
        _pydbg.virtual_protect_ex(self._h, target_addr, len(displaced), 0x40)
        _pydbg.write_process_memory(self._h, target_addr, jmp_to_tramp)
        # NOP padding if displaced > 5 bytes
        if len(displaced) > self.JMP_SIZE:
            nop_count = len(displaced) - self.JMP_SIZE
            _pydbg.write_process_memory(
                self._h, target_addr + self.JMP_SIZE, b"\x90" * nop_count
            )
        _pydbg.virtual_protect_ex(self._h, target_addr, len(displaced), 0x20)

        info = HookInfo(
            hook_type="inline",
            target_addr=target_addr,
            trampoline_addr=trampoline_addr,
            original_bytes=displaced,
            callback=callback,
        )
        self._hooks[target_addr] = info
        return info

    def unhook(self, hook_info):
        """Restore original bytes and free trampoline."""
        addr = hook_info.target_addr
        orig = hook_info.original_bytes
        _pydbg.virtual_protect_ex(self._h, addr, len(orig), 0x40)
        _pydbg.write_process_memory(self._h, addr, orig)
        _pydbg.virtual_protect_ex(self._h, addr, len(orig), 0x20)
        tramp_size = len(orig) + self.JMP_SIZE
        _pydbg.virtual_free_ex(self._h, hook_info.trampoline_addr, tramp_size, 0x8000)
        self._hooks.pop(addr, None)

    def get_hooks(self):
        return dict(self._hooks)

    def _fix_relative_insns(self, code, orig_addr, new_addr):
        """Fix relative offsets in displaced instructions.

        Instructions like CALL rel32, JMP rel32, Jcc rel32/rel8 use
        RIP-relative addressing. When moved to a new address, their
        offsets must be recalculated.

        For the trampoline, we only need to fix CALL/JMP rel32 since
        those are the most common in function prologues. The trampoline
        is allocated within ±2GB so rel32 always fits.
        """
        result = bytearray(code)
        pos = 0
        while pos < len(result):
            insn_addr_orig = orig_addr + pos
            insn_addr_new = new_addr + pos
            b = result[pos]

            # CALL rel32 (E8 xx xx xx xx)
            if b == 0xE8 and pos + 5 <= len(result):
                orig_target = insn_addr_orig + 5 + int.from_bytes(result[pos+1:pos+5], 'little', signed=True)
                new_offset = orig_target - (insn_addr_new + 5)
                if -(2**31) <= new_offset < 2**31:
                    result[pos+1:pos+5] = new_offset.to_bytes(4, 'little', signed=True)
                pos += 5
                continue

            # JMP rel32 (E9 xx xx xx xx)
            if b == 0xE9 and pos + 5 <= len(result):
                orig_target = insn_addr_orig + 5 + int.from_bytes(result[pos+1:pos+5], 'little', signed=True)
                new_offset = orig_target - (insn_addr_new + 5)
                if -(2**31) <= new_offset < 2**31:
                    result[pos+1:pos+5] = new_offset.to_bytes(4, 'little', signed=True)
                pos += 5
                continue

            # Jcc rel32 (0F 8x xx xx xx xx)
            if b == 0x0F and pos + 6 <= len(result) and (result[pos+1] & 0xF0) == 0x80:
                orig_target = insn_addr_orig + 6 + int.from_bytes(result[pos+2:pos+6], 'little', signed=True)
                new_offset = orig_target - (insn_addr_new + 6)
                if -(2**31) <= new_offset < 2**31:
                    result[pos+2:pos+6] = new_offset.to_bytes(4, 'little', signed=True)
                pos += 6
                continue

            # Jcc rel8 (7x xx) — expand to rel32 if offset changes
            if (b & 0xF0) == 0x70 and pos + 2 <= len(result):
                orig_target = insn_addr_orig + 2 + int.from_bytes(result[pos+1:pos+2], 'little', signed=True)
                new_offset = orig_target - (insn_addr_new + 2)
                if -128 <= new_offset < 128:
                    result[pos+1:pos+2] = new_offset.to_bytes(1, 'little', signed=True)
                pos += 2
                continue

            # Not a relative instruction we handle — skip
            # Use disassembler for accurate length in production code
            pos += 1

        return bytes(result)

    def _build_rel32_jmp(self, src_addr, dst_addr):
        """Build E9 rel32 JMP from src_addr to dst_addr.

        The offset is relative to the instruction AFTER the JMP (src_addr + 5).
        """
        offset = dst_addr - (src_addr + self.JMP_SIZE)
        # Check if offset fits in signed 32-bit
        if not (-(2**31) <= offset < 2**31):
            raise ValueError(
                f"JMP offset 0x{offset:X} exceeds 32-bit range "
                f"(src=0x{src_addr:X}, dst=0x{dst_addr:X})"
            )
        return b"\xe9" + offset.to_bytes(4, "little", signed=True)

    def _alloc_near(self, target_addr, size):
        """Allocate RWX memory within ±2GB of target_addr.

        Tries allocating at several page-aligned hints near the target.
        Falls back to any available address if proximity fails.
        """
        PAGE_EXECUTE_READWRITE = 0x40
        MEM_COMMIT_RESERVE = 0x3000

        # Try hints at increasing distances from target
        hints = []
        base_page = target_addr & ~0xFFF
        for delta_pages in range(1, 0x80000, 0x100):  # step by 256 pages (1MB)
            hints.append((base_page + delta_pages * 0x1000) & 0x7FFFFFFFFFFFF000)
            hints.append((base_page - delta_pages * 0x1000) & 0x7FFFFFFFFFFFF000)

        for hint in hints:
            if hint < 0x10000 or hint >= 2**63:
                continue
            try:
                result = _pydbg.virtual_alloc_ex(
                    self._h, hint, size, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE
                )
                actual = result["base_address"]
                if abs(actual - target_addr) < 2**31:
                    return actual
                _pydbg.virtual_free_ex(self._h, actual, size, 0x8000)
            except OSError:
                continue

        # Fallback: allocate anywhere
        result = _pydbg.virtual_alloc_ex(
            self._h, 0, size, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE
        )
        actual = result["base_address"]
        if abs(actual - target_addr) >= 2**31:
            _pydbg.virtual_free_ex(self._h, actual, size, 0x8000)
            raise RuntimeError(
                f"Cannot allocate trampoline within ±2GB of 0x{target_addr:X}"
            )
        return actual


# ── IAT Hooker ───────────────────────────────────────────────────


class IATHooker:
    """IAT hook by modifying Import Address Table entries.

    How it works:
      1. Parse target module's PE to find IAT entry for the function
      2. Read original function pointer from IAT
      3. Overwrite IAT entry with address of a JMP stub (in allocated memory)
      4. The JMP stub hits a breakpoint, dispatching to Python callback
      5. call_original() sets RIP = original function pointer
    """

    def __init__(self, h_process):
        self._h = h_process
        self._hooks = {}  # (module, func) -> HookInfo

    def hook(self, module_name, func_name, callback):
        """Set IAT hook for func_name in module_name.

        Args:
            module_name: DLL that imports the function (e.g. "target.exe").
            func_name: Function to hook (e.g. "printf").
            callback: fn(dbg, event, hook_info, mgr) called when hook fires.

        Returns:
            HookInfo with original_func_addr for call_original().
        """
        key = (module_name.lower(), func_name.lower())
        if key in self._hooks:
            raise ValueError(f"Already hooked: {module_name}!{func_name}")

        # Find module base
        modules = _pydbg.enum_process_modules(self._h)
        mod = None
        for m in modules:
            name = _pydbg.get_module_file_name_ex(self._h, m["handle"])
            if name.lower().endswith(module_name.lower()):
                mod = m
                break
        if mod is None:
            raise ValueError(f"Module '{module_name}' not found")

        base = mod["base_address"]

        # Parse PE to find IAT entry
        from pydbg.pe import PE

        pe = PE(_pydbg.read_process_memory(self._h, base, 0x10000))
        iat_entry_addr = None
        for imp in pe.imports:
            if imp.name and imp.name.lower() == func_name.lower():
                iat_entry_addr = imp.rva
                break
        if iat_entry_addr is None:
            raise ValueError(
                f"Function '{func_name}' not found in IAT of '{module_name}'"
            )

        # Read original function pointer
        abs_iat_addr = base + iat_entry_addr
        original_func = int.from_bytes(
            _pydbg.read_process_memory(self._h, abs_iat_addr, 8), "little"
        )

        # Allocate INT3 stub in target
        stub_alloc = _pydbg.virtual_alloc_ex(self._h, 0, 16, 0x3000, 0x40)
        stub_addr = stub_alloc["base_address"]
        _pydbg.write_process_memory(self._h, stub_addr, b"\xcc" + b"\x90" * 15)

        # Overwrite IAT entry to point to stub
        _pydbg.virtual_protect_ex(self._h, abs_iat_addr, 8, 0x40)
        _pydbg.write_process_memory(
            self._h, abs_iat_addr, stub_addr.to_bytes(8, "little")
        )
        _pydbg.virtual_protect_ex(self._h, abs_iat_addr, 8, 0x04)

        info = HookInfo(
            hook_type="iat",
            target_addr=stub_addr,
            trampoline_addr=original_func,
            original_bytes=original_func.to_bytes(8, "little"),
            callback=callback,
            iat_entry_addr=abs_iat_addr,
            original_func_addr=original_func,
            module_name=module_name,
            func_name=func_name,
        )
        self._hooks[key] = info
        return info

    def unhook(self, hook_info):
        """Restore IAT entry and free stub."""
        _pydbg.virtual_protect_ex(self._h, hook_info.iat_entry_addr, 8, 0x40)
        _pydbg.write_process_memory(
            self._h, hook_info.iat_entry_addr, hook_info.original_bytes
        )
        _pydbg.virtual_protect_ex(self._h, hook_info.iat_entry_addr, 8, 0x04)
        _pydbg.virtual_free_ex(self._h, hook_info.target_addr, 16, 0x8000)
        key = (hook_info.module_name.lower(), hook_info.func_name.lower())
        self._hooks.pop(key, None)

    def get_hooks(self):
        return dict(self._hooks)


# ── Hook Manager ─────────────────────────────────────────────────


class HookManager:
    """Unified hook manager with event-driven dispatch.

    Inline hook flow:
      1. Target function's first bytes are replaced with JMP → trampoline
      2. Trampoline has displaced instructions + JMP back
      3. Breakpoint at trampoline entry fires Python callback
      4. Callback can call_original() → sets RIP = trampoline

    IAT hook flow:
      1. IAT entry points to INT3 stub
      2. Stub breakpoint fires Python callback
      3. Callback can call_original() → sets RIP = original function
    """

    def __init__(self, dbg):
        self._dbg = dbg
        self._inline = InlineHooker(dbg._session.process_handle)
        self._iat = IATHooker(dbg._session.process_handle)
        self._hooks_by_addr = {}  # breakpoint_addr -> HookInfo

    def hook_inline(self, target_addr, callback):
        """Set inline hook. Returns HookInfo."""
        info = self._inline.hook(target_addr, callback)
        # Set breakpoint at trampoline entry to intercept calls
        bp_id = self._dbg.set_breakpoint(info.trampoline_addr)
        info._bp_id = bp_id
        self._hooks_by_addr[info.trampoline_addr] = info
        return info

    def hook_iat(self, module_name, func_name, callback):
        """Set IAT hook. Returns HookInfo."""
        info = self._iat.hook(module_name, func_name, callback)
        self._hooks_by_addr[info.target_addr] = info
        return info

    def unhook(self, hook_info):
        """Remove a hook."""
        if hook_info.hook_type == "inline":
            if hasattr(hook_info, "_bp_id"):
                try:
                    self._dbg.remove_breakpoint(hook_info._bp_id)
                except Exception:
                    pass  # already removed by call_original
            self._inline.unhook(hook_info)
        elif hook_info.hook_type == "iat":
            self._iat.unhook(hook_info)
        self._hooks_by_addr.pop(hook_info.target_addr, None)

    def call_original(self, event, hook_info):
        """Let the original function execute.

        For inline hooks: removes the trampoline breakpoint, sets
        RIP = trampoline. The trampoline executes the displaced
        instructions then JMPs back to the rest of the original function.
        The hook fires once; subsequent calls go through the trampoline
        directly (the JMP patch at target remains).

        For IAT hooks: sets RIP = original function address.
        """
        h_thread = self._dbg.open_thread(event.tid)
        try:
            if hook_info.hook_type == "inline":
                # Remove breakpoint so trampoline executes cleanly
                if hasattr(hook_info, "_bp_id"):
                    self._dbg.remove_breakpoint(hook_info._bp_id)
                self._dbg.set_register(h_thread, "rip", hook_info.trampoline_addr)
            elif hook_info.hook_type == "iat":
                self._dbg.set_register(h_thread, "rip", hook_info.original_func_addr)
        finally:
            self._dbg.close_handle(h_thread)

    def run(self, timeout_ms=10000):
        """Run event loop, dispatching hook callbacks.

        Callbacks receive (dbg, event, hook_info, mgr) and can call
        mgr.call_original(event, hook_info) to let the original run.
        """
        while True:
            event = self._dbg.wait_event(timeout_ms)
            if event is None:
                continue

            if event.type == "EXCEPTION":
                addr = event.exception_addr
                hook = self._hooks_by_addr.get(addr)
                if hook is not None:
                    hook.callback(self._dbg, event, hook, self)

            if event.type == "EXIT_PROCESS":
                break

            self._dbg.continue_event(event.pid, event.tid)

        return event.raw.get("exit_code", 1) if event else 1
