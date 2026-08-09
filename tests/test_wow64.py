"""WOW64 (32-bit target on 64-bit host) integration tests."""

import os
import struct
import sys
import unittest

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_WOW64_TARGET = os.environ.get(
    "TEST_WOW64_TARGET_PATH",
    os.path.join(_TEST_DIR, "target", "simple_target32.exe"),
)
_HAS_TARGET = os.path.exists(TEST_WOW64_TARGET)


def _wow64_available():
    """True only on 64-bit Windows (a 32-bit host cannot debug WOW64)."""
    return struct.calcsize("P") == 8 and sys.platform == "win32"


def _launch(dbg, target=None):
    """Launch target under debug, consume events until first EXCEPTION (loader bp)."""
    pid, tid = dbg.create_process(target or TEST_WOW64_TARGET)
    event = dbg.wait_event(5000)
    if event is not None:
        dbg.continue_event(event.pid, event.tid)
    for _ in range(50):
        event = dbg.wait_event(2000)
        if event is None or event.type == "EXIT_PROCESS":
            break
        if event.type == "EXCEPTION":
            break
        dbg.continue_event(event.pid, event.tid)
    return pid, tid


def _module_by_name(dbg, basename):
    """Return module dict by basename (case-insensitive) or None."""
    for m in dbg.enum_modules():
        if m.get("name", "").split("\\")[-1].lower() == basename.lower():
            return m
    return None


def _export_address(dbg, exe_path, base, name):
    """Resolve exported function's absolute address from the on-disk PE."""
    from pydbg.pe import PE
    pe = PE.from_file(exe_path)
    for exp in pe.exports:
        if exp.name == name:
            return base + exp.rva
    raise AssertionError(f"export {name} not found in {exe_path}")


@unittest.skipUnless(_HAS_TARGET and _wow64_available(),
                     "requires 32-bit target and 64-bit host")
class TestWow64Registers(unittest.TestCase):
    def test_get_registers_returns_x86_names(self):
        from pydbg import Debugger
        from tests.helpers import teardown

        dbg = Debugger()
        try:
            _pid, tid = _launch(dbg)
            h = dbg.open_thread(tid)
            regs = dbg.get_registers(h)
            dbg.close_handle(h)
            self.assertEqual(regs["arch"], "x86")
            self.assertIn("eip", regs)
            self.assertIn("eax", regs)
            self.assertIn("esp", regs)
            self.assertNotIn("rip", regs)
            self.assertLess(regs["eip"], 0x100000000)
        finally:
            teardown(dbg)

    def test_set_register_x86(self):
        from pydbg import Debugger
        from tests.helpers import teardown

        dbg = Debugger()
        try:
            _pid, tid = _launch(dbg)
            h = dbg.open_thread(tid)
            regs = dbg.get_registers(h)
            old = regs["eax"]
            dbg.set_register(h, "eax", 0x12345678)
            regs2 = dbg.get_registers(h)
            dbg.set_register(h, "eax", old)  # restore
            dbg.close_handle(h)
            self.assertEqual(regs2["eax"], 0x12345678)
        finally:
            teardown(dbg)
