"""
dll_injector.py — DLL injection using pydbg.

Supports two scenarios:
  1. Inject into a running process by PID
  2. Create process suspended, inject, then resume

Usage:
  python dll_injector.py --pid <PID> --dll <path>         # scenario 1
  python dll_injector.py --exe <path> --dll <path>        # scenario 2
"""

import argparse
import os
import sys
import time

# Add project root to path so pydbg is importable without install
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pydbg import _pydbg


def inject_into_process(h_process, dll_path):
    """Core injection logic: allocate, write, CreateRemoteThread.

    Args:
        h_process: Handle to the target process (PROCESS_ALL_ACCESS).
        dll_path: Absolute path to the DLL to inject.

    Returns:
        Exit code of the remote thread (should be the LoadLibrary return value).
    """
    # Resolve LoadLibraryA in kernel32.dll
    h_kernel32 = _pydbg.get_module_handle("kernel32.dll")
    loadlibrary_addr = _pydbg.get_proc_address(h_kernel32, "LoadLibraryA")

    # Allocate memory in target for the DLL path string (null-terminated)
    dll_path_bytes = dll_path.encode("ascii") + b"\x00"
    alloc = _pydbg.virtual_alloc_ex(
        h_process,
        0,
        len(dll_path_bytes),
        0x3000,  # MEM_COMMIT | MEM_RESERVE
        0x04,    # PAGE_READWRITE
    )
    remote_buf = alloc["base_address"]

    try:
        # Write DLL path into allocated memory
        _pydbg.write_process_memory(h_process, remote_buf, dll_path_bytes)

        # Create remote thread: LoadLibraryA(dll_path)
        tid, h_thread = _pydbg.create_remote_thread(
            h_process, loadlibrary_addr, remote_buf
        )

        # Wait for LoadLibrary to finish
        _pydbg.wait_for_single_object(h_thread, 10000)

        # Get thread exit code (= HMODULE of loaded DLL, 0 on failure)
        exit_code = _pydbg.get_exit_code_thread(h_thread)
        _pydbg.close_handle(h_thread)
        return exit_code

    finally:
        # Free the remote buffer regardless of success/failure
        try:
            _pydbg.virtual_free_ex(h_process, remote_buf, len(dll_path_bytes), 0x8000)
        except OSError:
            pass


def scenario_running(pid, dll_path):
    """Scenario 1: Inject DLL into a running process.

    Opens the process by PID, injects the DLL, and detaches.
    The process continues running with the DLL loaded.
    """
    dll_abs = os.path.abspath(dll_path)
    if not os.path.isfile(dll_abs):
        print(f"[!] DLL not found: {dll_abs}")
        return False

    print(f"[*] Target PID: {pid}")
    print(f"[*] DLL: {dll_abs}")

    h_process = _pydbg.open_process(pid)
    print(f"[+] Opened process handle: 0x{h_process:X}")

    result = inject_into_process(h_process, dll_abs)
    if result != 0:
        print(f"[+] LoadLibrary returned: 0x{result:X} (DLL base address)")
        print("[+] Injection successful!")
    else:
        print("[!] LoadLibrary returned 0 — injection may have failed")

    _pydbg.close_handle(h_process)
    return result != 0


def scenario_suspended(exe_path, dll_path):
    """Scenario 2: Create process suspended, inject DLL, then resume.

    Creates the target process with the main thread suspended,
    injects the DLL (which runs DllMain during LoadLibrary),
    then resumes the main thread so the process starts normally.
    """
    exe_abs = os.path.abspath(exe_path)
    dll_abs = os.path.abspath(dll_path)
    if not os.path.isfile(exe_abs):
        print(f"[!] Executable not found: {exe_abs}")
        return False
    if not os.path.isfile(dll_abs):
        print(f"[!] DLL not found: {dll_abs}")
        return False

    print(f"[*] Executable: {exe_abs}")
    print(f"[*] DLL: {dll_abs}")

    # Create process in suspended state (no debug control)
    pid, tid, h_process, h_thread = _pydbg.create_process_suspended(exe_abs)
    print(f"[+] Process created: PID={pid}, TID={tid}")
    print(f"    h_process=0x{h_process:X}, h_thread=0x{h_thread:X}")

    try:
        # Inject DLL while process is suspended
        result = inject_into_process(h_process, dll_abs)
        if result != 0:
            print(f"[+] LoadLibrary returned: 0x{result:X} (DLL base address)")
            print("[+] Injection successful!")
        else:
            print("[!] LoadLibrary returned 0 — injection may have failed")

        # Resume the main thread — process starts executing
        _pydbg.resume_thread(h_thread)
        print(f"[+] Thread {tid} resumed, process is running")

        return result != 0

    except Exception as e:
        # If injection fails, still resume so the process doesn't hang
        print(f"[!] Error during injection: {e}")
        try:
            _pydbg.resume_thread(h_thread)
        except OSError:
            pass
        return False

    finally:
        _pydbg.close_handle(h_thread)
        _pydbg.close_handle(h_process)


def main():
    parser = argparse.ArgumentParser(
        description="DLL injection via pydbg (CreateRemoteThread + LoadLibraryA)"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pid", type=int, help="Inject into running process by PID")
    group.add_argument("--exe", type=str, help="Create process suspended, inject, resume")
    parser.add_argument("--dll", type=str, required=True, help="Path to DLL to inject")
    args = parser.parse_args()

    if args.pid:
        ok = scenario_running(args.pid, args.dll)
    else:
        ok = scenario_suspended(args.exe, args.dll)

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
