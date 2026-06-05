"""
hook_demo.py — Demonstrates classic inline hook (JMP + trampoline).

Hooks the target process entry point with a JMP patch. The trampoline
contains displaced instructions + JMP back, so call_original() lets
the original function run normally.

Usage:
  python hook_demo.py [--target <path>]
"""

import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pydbg import Debugger
from hook_framework import HookManager


# ── Hook callbacks ───────────────────────────────────────────────


def on_entry_hook(dbg, event, hook_info, mgr):
    """Called every time the hooked function is entered.

    Logs registers, then calls the original via trampoline.
    """
    h_thread = dbg.open_thread(event.tid)
    regs = dbg.get_registers(h_thread)
    dbg.close_handle(h_thread)

    print(f"[hook] Entry point called! RIP=0x{regs['rip']:X}")
    print(f"       RSP=0x{regs['rsp']:X}  RCX=0x{regs['rcx']:X}")

    # Execute original via trampoline (displaced instructions + JMP back)
    mgr.call_original(event, hook_info)


# ── Main ─────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="Inline hook demo")
    parser.add_argument(
        "--target",
        default=os.path.join(
            os.path.dirname(__file__), "..", "build", "tests", "simple_target.exe"
        ),
    )
    args = parser.parse_args()

    target = os.path.abspath(args.target)
    print(f"[*] Target: {target}")

    dbg = Debugger()
    pid, tid = dbg.create_process(target)
    print(f"[+] PID={pid} TID={tid}")

    # Get entry point from CREATE_PROCESS event
    event = dbg.wait_event(5000)
    base = event.raw.get("base_of_image", 0)
    pe_data = dbg.read_memory(base, 0x200)
    e_lfanew = struct.unpack_from("<I", pe_data, 0x3C)[0]
    entry_rva = struct.unpack_from("<I", pe_data, e_lfanew + 40)[0]
    entry_addr = base + entry_rva
    print(f"[+] Entry point: 0x{entry_addr:X}")

    # Set hook BEFORE continuing (JMP patch at entry point)
    mgr = HookManager(dbg)
    info = mgr.hook_inline(entry_addr, on_entry_hook)
    print(f"[+] Hook set: trampoline at 0x{info.trampoline_addr:X}")

    # Continue — hook fires when entry point is reached
    dbg.continue_event(pid, tid)
    print("[*] Running...\n")

    while True:
        event = dbg.wait_event(10000)
        if event is None:
            continue

        if event.type == "EXCEPTION":
            hook = mgr._hooks_by_addr.get(event.exception_addr)
            if hook is not None:
                hook.callback(dbg, event, hook, mgr)

        if event.type == "EXIT_PROCESS":
            print(f"\n[*] Exit code: {event.raw.get('exit_code', 1)}")
            break

        dbg.continue_event(event.pid, event.tid)

    try:
        mgr.unhook(info)
    except OSError:
        pass


if __name__ == "__main__":
    main()
