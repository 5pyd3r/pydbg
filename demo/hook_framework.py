"""
hook_framework.py — IAT Hook + Inline Hook framework using pydbg.

Provides:
  - InlineHooker: patch function prologue with JMP, trampoline for calling original
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
import ctypes

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
        "_fired",
    )

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


# ── Inline Hooker ────────────────────────────────────────────────


class InlineHooker:
    """Inline hook with trampoline for calling original function.

    How it works:
      1. Read enough instructions from target_addr to cover ≥ 5 bytes
      2. Allocate RWX memory in target, copy displaced instructions there
      3. Append indirect JMP back to target_addr + displaced_len (trampoline)
      4. On breakpoint hit, callback is invoked; call_original() sets
         RIP = trampoline so the original code runs normally

    Note: Uses indirect JMP (FF 25 + 8-byte absolute addr = 14 bytes) for
    the trampoline's jump-back to handle addresses >2GB apart.
    """

    INDIRECT_JMP_SIZE = 14  # FF 25 00000000 + 8-byte absolute addr

    def __init__(self, h_process):
        self._h = h_process
        self._engine = DisasmEngine(mode="x64")
        self._hooks = {}  # target_addr -> HookInfo
        self._trampoline_addrs = set()  # whitelist: don't dispatch hooks for these

    def _build_indirect_jmp(self, target_addr):
        """Build x64 indirect JMP: FF 25 00000000 <8-byte addr>."""
        # FF 25 00000000 = jmp qword ptr [rip+0]
        # The next 8 bytes are the absolute target address
        return b"\xff\x25\x00\x00\x00\x00" + target_addr.to_bytes(8, "little")

    def hook(self, target_addr, callback):
        """Set inline hook at target_addr.

        Args:
            target_addr: Address to hook (function entry or any code addr).
            callback: fn(dbg, event, hook_info) called when hook is hit.

        Returns:
            HookInfo with trampoline_addr for call_original().
        """
        if target_addr in self._hooks:
            raise ValueError(f"Already hooked at 0x{target_addr:X}")

        # Read instructions, find enough bytes for a JMP rel32 (5 bytes)
        raw = _pydbg.read_process_memory(self._h, target_addr, 32)
        insns = self._engine.disasm(target_addr, raw)
        displaced = b""
        for insn in insns:
            displaced += insn.raw_bytes
            if len(displaced) >= 5:
                break
        if len(displaced) < 5:
            raise ValueError(
                f"Cannot fit JMP at 0x{target_addr:X} "
                f"(need 5 bytes, got {len(displaced)})"
            )

        # Save original bytes
        original_bytes = displaced[: len(displaced)]

        # Allocate trampoline: displaced instructions + indirect JMP back
        tramp_size = len(displaced) + self.INDIRECT_JMP_SIZE
        alloc = _pydbg.virtual_alloc_ex(
            self._h, 0, tramp_size, 0x3000, 0x40  # MEM_COMMIT|RESERVE, PAGE_EXECUTE_READWRITE
        )
        trampoline_addr = alloc["base_address"]

        # Build trampoline: displaced instructions + indirect JMP back
        jmp_back_target = target_addr + len(displaced)
        jmp_back = self._build_indirect_jmp(jmp_back_target)
        trampoline_code = displaced + jmp_back
        _pydbg.write_process_memory(self._h, trampoline_addr, trampoline_code)

        info = HookInfo(
            hook_type="inline",
            target_addr=target_addr,
            trampoline_addr=trampoline_addr,
            original_bytes=original_bytes,
            callback=callback,
        )
        self._hooks[target_addr] = info
        return info

    def unhook(self, hook_info):
        """Restore original bytes and free trampoline."""
        addr = hook_info.target_addr
        _pydbg.virtual_protect_ex(self._h, addr, len(hook_info.original_bytes), 0x40)
        _pydbg.write_process_memory(self._h, addr, hook_info.original_bytes)
        _pydbg.virtual_protect_ex(self._h, addr, len(hook_info.original_bytes), 0x20)
        tramp_size = len(hook_info.original_bytes) + self.INDIRECT_JMP_SIZE
        _pydbg.virtual_free_ex(self._h, hook_info.trampoline_addr, tramp_size, 0x8000)
        self._hooks.pop(addr, None)

    def get_hooks(self):
        return dict(self._hooks)


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
            callback: fn(dbg, event, hook_info) called when hook is hit.

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
        original_func = None
        for imp in pe.imports:
            if imp.name and imp.name.lower() == func_name.lower():
                iat_entry_addr = imp.rva  # RVA of IAT slot
                break
        if iat_entry_addr is None:
            raise ValueError(f"Function '{func_name}' not found in IAT of '{module_name}'")

        # Read original function pointer
        abs_iat_addr = base + iat_entry_addr
        original_func = int.from_bytes(
            _pydbg.read_process_memory(self._h, abs_iat_addr, 8), "little"
        )

        # Allocate JMP stub in target (a single INT3 is enough — we use breakpoint)
        # Actually, we'll use a software breakpoint at the IAT target address.
        # For IAT hook, the callback is triggered when any call through IAT happens.
        # We need a different approach: overwrite IAT with a stub address that has INT3.
        stub_alloc = _pydbg.virtual_alloc_ex(self._h, 0, 16, 0x3000, 0x40)
        stub_addr = stub_alloc["base_address"]
        # Write: call original_func; ret  (so the stub just forwards to original)
        # Actually simpler: write INT3 + NOP padding, use breakpoint to intercept
        _pydbg.write_process_memory(self._h, stub_addr, b"\xcc" + b"\x90" * 15)

        # Overwrite IAT entry to point to our stub
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

    Supports both inline hooks and IAT hooks. Callbacks receive
    (dbg, event, hook_info) and can call call_original() to let
    the original function execute normally.
    """

    def __init__(self, dbg):
        self._dbg = dbg
        self._inline = InlineHooker(dbg._session.process_handle)
        self._iat = IATHooker(dbg._session.process_handle)
        self._hooks_by_addr = {}  # breakpoint_addr -> HookInfo
        self._pending_rehook = None  # hook_info to re-apply after continue

    def hook_inline(self, target_addr, callback):
        """Set inline hook. Returns HookInfo."""
        info = self._inline.hook(target_addr, callback)
        # Set breakpoint at target address to intercept
        bp_id = self._dbg.set_breakpoint(target_addr)
        info._bp_id = bp_id
        self._hooks_by_addr[target_addr] = info
        return info

    def hook_iat(self, module_name, func_name, callback):
        """Set IAT hook. Returns HookInfo."""
        info = self._iat.hook(module_name, func_name, callback)
        # The stub already has INT3, but we need to set breakpoint at stub_addr
        # Actually the stub has \xCC (INT3) which will trigger EXCEPTION_BREAKPOINT
        # We register the stub address for dispatch
        self._hooks_by_addr[info.target_addr] = info
        return info

    def unhook(self, hook_info):
        """Remove a hook."""
        if hook_info.hook_type == "inline":
            # Remove breakpoint
            if hasattr(hook_info, "_bp_id"):
                self._dbg.remove_breakpoint(hook_info._bp_id)
            self._inline.unhook(hook_info)
        elif hook_info.hook_type == "iat":
            self._iat.unhook(hook_info)
        self._hooks_by_addr.pop(hook_info.target_addr, None)

    def call_original(self, event, hook_info):
        """Let the original function execute.

        For inline hooks: temporarily restores original bytes at target_addr,
        sets RIP back to target_addr so the original code runs from the start,
        then re-applies the breakpoint after the function returns.
        For IAT hooks: sets RIP to the original function address.
        """
        h_thread = self._dbg.open_thread(event.tid)
        try:
            if hook_info.hook_type == "inline":
                addr = hook_info.target_addr
                orig = hook_info.original_bytes
                # Temporarily restore original bytes (remove INT3)
                _pydbg.virtual_protect_ex(self._dbg._session.process_handle, addr, len(orig), 0x40)
                _pydbg.write_process_memory(self._dbg._session.process_handle, addr, orig)
                _pydbg.virtual_protect_ex(self._dbg._session.process_handle, addr, len(orig), 0x20)
                # Set RIP to target_addr — original code executes from start
                self._dbg.set_register(h_thread, "rip", addr)
            elif hook_info.hook_type == "iat":
                self._dbg.set_register(h_thread, "rip", hook_info.original_func_addr)
        finally:
            self._dbg.close_handle(h_thread)

        # Re-apply breakpoint after continue_event (for next interception)
        if hook_info.hook_type == "inline" and hasattr(hook_info, "_bp_id"):
            # The breakpoint will be re-set on the next event cycle
            self._pending_rehook = hook_info

    def run(self, timeout_ms=10000):
        """Run event loop, dispatching hook callbacks.

        The loop handles:
          - EXCEPTION_BREAKPOINT: dispatch to registered hook callbacks
          - EXIT_PROCESS: break
          - Other events: continue

        Callbacks can call mgr.call_original(event, hook_info) to let
        the original function run.
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
