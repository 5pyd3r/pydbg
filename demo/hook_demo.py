"""
hook_demo.py — Demonstrates inline hook using the hook framework.

Hooks the target process at its entry point before execution begins,
showing that the hook fires and the original function can still run.

Usage:
  python hook_demo.py [--target <path>]
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pydbg import Debugger, _pydbg
from hook_framework import HookManager


# ── Hook callbacks ───────────────────────────────────────────────


def on_entry_point(dbg, event, hook_info, mgr):
    """Inline hook callback: called when the process hits its entry point.

    Logs the RIP, then calls the original so the program runs normally.
    """
    h_thread = dbg.open_thread(event.tid)
    regs = dbg.get_registers(h_thread)
    dbg.close_handle(h_thread)

    print(f"[hook_demo] >>> Entry point hook fired! RIP=0x{regs['rip']:X}")
    print(f"[hook_demo]     RAX=0x{regs['rax']:X}  RCX=0x{regs['rcx']:X}")
    print(f"[hook_demo]     RDX=0x{regs['rdx']:X}  RSP=0x{regs['rsp']:X}")

    # Call original — program continues normally
    mgr.call_original(event, hook_info)
    print("[hook_demo]     -> called original, program continues\n")


# ── Main ─────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="Hook framework demo")
    parser.add_argument(
        "--target",
        default=os.path.join(os.path.dirname(__file__), "..", "build", "tests", "simple_target.exe"),
        help="Path to target executable",
    )
    args = parser.parse_args()

    target = os.path.abspath(args.target)
    if not os.path.isfile(target):
        print(f"[!] Target not found: {target}")
        sys.exit(1)

    print(f"[*] Target: {target}")

    dbg = Debugger()
    pid, tid = dbg.create_process(target)
    print(f"[+] Process created: PID={pid} TID={tid}")

    # Step 1: consume CREATE_PROCESS event, get entry point from it
    entry_addr = None
    event = dbg.wait_event(5000)
    if event and event.type == "CREATE_PROCESS":
        # The CREATE_PROCESS event contains the entry point in raw data
        entry_addr = event.raw.get("base_of_image")
        # For the actual entry point, we need to read the PE header
        # base_of_image is the image base; entry_point = base + AddressOfEntryPoint
        if entry_addr:
            pe_data = dbg.read_memory(entry_addr, 0x1000)
            # Parse e_lfanew from DOS header
            import struct
            e_lfanew = struct.unpack_from('<I', pe_data, 0x3C)[0]
            # Optional header magic at e_lfanew + 24
            opt_magic = struct.unpack_from('<H', pe_data, e_lfanew + 24)[0]
            # Entry point RVA at e_lfanew + 40 (PE32+) or e_lfanew + 40 (PE32)
            entry_rva = struct.unpack_from('<I', pe_data, e_lfanew + 40)[0]
            entry_addr = entry_addr + entry_rva
            print(f"[+] Image base: 0x{event.raw.get('base_of_image'):X}")
            print(f"[+] Entry point: 0x{entry_addr:X}")

    # Step 2: BEFORE continuing, set inline hook at entry point
    if entry_addr:
        mgr = HookManager(dbg)
        print(f"[*] Setting inline hook at entry point (before execution)...")
        hook_info = mgr.hook_inline(entry_addr, on_entry_point)
        print(f"[+] Hook set! Trampoline at 0x{hook_info.trampoline_addr:X}")

    # Step 3: continue — the hook will fire at entry point
    dbg.continue_event(pid, tid)
    print("[*] Continuing execution (hook will fire)...\n")

    # Event loop
    while True:
        event = dbg.wait_event(10000)
        if event is None:
            continue

        if event.type == "EXCEPTION":
            addr = event.exception_addr
            hook = mgr._hooks_by_addr.get(addr)
            if hook is not None and not getattr(hook, '_fired', False):
                hook._fired = True
                hook.callback(dbg, event, hook, mgr)
                # call_original restored bytes + set RIP; skip re-set
                mgr._pending_rehook = None

        if event.type == "EXIT_PROCESS":
            exit_code = event.raw.get("exit_code", 1)
            print(f"\n[hook_demo] Process exited with code {exit_code}")
            break

        dbg.continue_event(event.pid, event.tid)

    # Cleanup
    try:
        mgr.unhook(hook_info)
        print("[hook_demo] Hook removed, cleanup done")
    except OSError:
        pass  # Process already exited, handles are invalid


if __name__ == "__main__":
    main()
