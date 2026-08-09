"""WOW64 (32-bit target on 64-bit host) integration tests."""

import os
import struct
import subprocess
import sys
import time
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


def _launch(dbg, target=None, run=False):
    """Launch target under debug.

    run=False (default): consume events until the first EXCEPTION (the loader
    breakpoint) and leave the process paused there. Threads are suspended, so
    register introspection is race-free (used by the register tests).

    run=True: additionally continue past BOTH loader breakpoints — the first
    (EXCEPTION_BREAKPOINT=0x80000003) fires in the 64-bit bootstrap BEFORE the
    32-bit image is mapped, the second (STATUS_WX86_BREAKPOINT=0x4000001F)
    fires in 32-bit ntdll AFTER the image is loaded — until the target's main()
    is running, so a software breakpoint set afterwards actually fires. The
    target's own module becomes enumerable after the first breakpoint.
    """
    from pydbg.exceptions import MemError

    target = target or TEST_WOW64_TARGET
    basename = os.path.basename(target)
    pid, tid = dbg.create_process(target)
    event = dbg.wait_event(5000)
    if event is not None:
        dbg.continue_event(event.pid, event.tid)

    if not run:
        for _ in range(50):
            event = dbg.wait_event(2000)
            if event is None or event.type == "EXIT_PROCESS":
                break
            if event.type == "EXCEPTION":
                break
            dbg.continue_event(event.pid, event.tid)
        return pid, tid

    saw_image = False
    for _ in range(100):
        event = dbg.wait_event(2000)
        if event is None or event.type == "EXIT_PROCESS":
            break
        dbg.continue_event(event.pid, event.tid)
        if event.type == "EXCEPTION":
            # If the main image is already mapped, this is the 32-bit (WX86)
            # loader breakpoint signalling that main() is about to run.
            if saw_image:
                break
            continue
        try:
            if _module_by_name(dbg, basename):
                saw_image = True
        except MemError:
            # Enumeration transiently fails (ERROR_PARTIAL_COPY=299) during
            # the earliest bootstrap events; just keep consuming.
            pass
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


@unittest.skipUnless(_HAS_TARGET and _wow64_available(),
                     "requires 32-bit target and 64-bit host")
class TestWow64SoftwareBreakpoint(unittest.TestCase):
    def test_run_auto_handles_wx86_breakpoint(self):
        from pydbg import Debugger
        from tests.helpers import teardown

        dbg = Debugger()
        try:
            _pid, _tid = _launch(dbg, run=True)
            base = _module_by_name(dbg, os.path.basename(TEST_WOW64_TARGET))["base_address"]
            addr = _export_address(dbg, TEST_WOW64_TARGET, base, "target_add")
            orig = dbg.read_memory(addr, 1)
            bp_id = dbg.set_breakpoint(addr)

            seen = []
            count = [0]
            start = time.time()

            def on_event(event):
                count[0] += 1
                if count[0] > 50 or time.time() - start > 10:
                    return False  # safety bound: fail-fast instead of hanging
                if event.type == "EXCEPTION":
                    seen.append((event.exception_code, event.exception_addr))
                    if event.exception_code in (0x4000001F, 0x80000003):
                        return False  # stop at our breakpoint
                return None

            dbg.run(on_event, timeout_ms=3000)

            self.assertTrue(
                any(c in (0x4000001F, 0x80000003) for c, _ in seen),
                "WX86 breakpoint not delivered via run()",
            )
            # int3 removed at delivery time -> original byte restored
            self.assertEqual(dbg.read_memory(addr, 1), orig)
            dbg.remove_breakpoint(bp_id)
        finally:
            teardown(dbg)

    def test_wx86_single_step_swallowed_and_rearmed(self):
        from pydbg import Debugger
        from tests.helpers import teardown

        dbg = Debugger()
        try:
            _pid, _tid = _launch(dbg, run=True)
            base = _module_by_name(dbg, os.path.basename(TEST_WOW64_TARGET))["base_address"]
            addr = _export_address(dbg, TEST_WOW64_TARGET, base, "target_add")
            orig = dbg.read_memory(addr, 1)
            bp_id = dbg.set_breakpoint(addr)

            hits = []
            ss_seen = []
            count = [0]
            start = time.time()

            def on_event(event):
                count[0] += 1
                if count[0] > 100 or time.time() - start > 15:
                    return False  # safety bound
                if event.type == "EXCEPTION":
                    if event.exception_code in (0x4000001E, 0x80000004):
                        # A single-step reaching the callback means the internal
                        # lifecycle step leaked — it should be swallowed by run().
                        ss_seen.append(event.exception_code)
                    if event.exception_code in (0x4000001F, 0x80000003):
                        hits.append(event.exception_addr)
                        if len(hits) >= 2:
                            return False  # second hit: stop
                        return None  # first hit: continue over it (run() single-steps + re-arms)
                return None

            dbg.run(on_event, timeout_ms=3000)

            # A second hit only fires if run() re-armed the INT3 after the first.
            self.assertGreaterEqual(len(hits), 2,
                                    "breakpoint should hit at least twice (re-arm)")
            self.assertEqual(ss_seen, [], "internal single-step leaked to callback")
            # At delivery time the INT3 is removed -> original byte restored
            self.assertEqual(dbg.read_memory(addr, 1), orig)
            dbg.remove_breakpoint(bp_id)
        finally:
            teardown(dbg)


@unittest.skipUnless(_HAS_TARGET and _wow64_available(),
                     "requires 32-bit target and 64-bit host")
class TestWow64HardwareBreakpoint(unittest.TestCase):
    def test_dr0_execute_breakpoint(self):
        from pydbg import Debugger
        from tests.helpers import teardown

        dbg = Debugger()
        try:
            pid, tid = _launch(dbg, run=True)
            base = _module_by_name(dbg, os.path.basename(TEST_WOW64_TARGET))["base_address"]
            addr = _export_address(dbg, TEST_WOW64_TARGET, base, "target_add")
            h = dbg.open_thread(tid)
            bp_id = dbg.set_hw_breakpoint(addr, "x", 1, 0)

            hit = False
            start = time.time()
            for _ in range(100):
                if time.time() - start > 15:
                    break  # wall-clock bound: fail fast instead of spinning
                ev = dbg.wait_event(2000)
                if ev is None:
                    break
                if ev.type == "EXCEPTION":
                    if ev.exception_code in (0x80000004, 0x4000001E):
                        regs = dbg.get_registers(h)
                        self.assertTrue(regs["dr6"] & 1, "Dr6 slot0 not set")
                        self.assertEqual(regs["eip"], addr)
                        hit = True
                        dbg.brk_hw.clear(0)  # clear before continue (avoid re-trap)
                        dbg.continue_event(ev.pid, ev.tid)
                        break
                dbg.continue_event(ev.pid, ev.tid)
                if ev.type == "EXIT_PROCESS":
                    break
            self.assertTrue(hit, "Dr0 breakpoint was not hit")
            try:
                dbg.remove_breakpoint(bp_id)
            except Exception:
                pass
            dbg.close_handle(h)
        finally:
            teardown(dbg)


@unittest.skipUnless(_HAS_TARGET and _wow64_available(),
                     "requires 32-bit target and 64-bit host")
class TestWow64Modules(unittest.TestCase):
    def test_enum_modules_sees_x86_exe_and_ntdll32(self):
        from pydbg import Debugger
        from tests.helpers import teardown

        dbg = Debugger()
        try:
            _pid, _tid = _launch(dbg, run=True)
            mods = dbg.enum_modules()
            exe = next(
                (m for m in mods
                 if m.get("name", "").split("\\")[-1].lower()
                 == os.path.basename(TEST_WOW64_TARGET).lower()),
                None)
            self.assertIsNotNone(exe, "32-bit exe not enumerated")
            self.assertEqual(exe["arch"], "x86")
            self.assertLess(exe["base_address"], 0x100000000)
            ntdll32 = [m for m in mods
                       if m.get("name", "").endswith("ntdll.dll")
                       and m["arch"] == "x86"]
            self.assertTrue(ntdll32, "32-bit ntdll not enumerated")
            ntdll64 = [m for m in mods
                       if m.get("name", "").endswith("ntdll.dll")
                       and m["arch"] == "x64"]
            self.assertTrue(ntdll64, "64-bit ntdll not enumerated")
        finally:
            teardown(dbg)


@unittest.skipUnless(_HAS_TARGET and _wow64_available(),
                     "requires 32-bit target and 64-bit host")
class TestWow64Attach(unittest.TestCase):
    def test_attach_to_running_x86_target(self):
        from pydbg import Debugger

        proc = subprocess.Popen(
            [TEST_WOW64_TARGET],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        dbg = Debugger()
        h = None
        try:
            dbg.attach(proc.pid)
            self.assertEqual(dbg._session.target_arch, 32)

            tid = None
            event = dbg.wait_event(5000)
            if event is not None:
                tid = event.tid
                dbg.continue_event(event.pid, event.tid)
            for _ in range(50):
                event = dbg.wait_event(2000)
                if event is None or event.type == "EXIT_PROCESS":
                    break
                if tid is None:
                    tid = event.tid
                if event.type == "EXCEPTION":
                    break
                dbg.continue_event(event.pid, event.tid)

            self.assertIsNotNone(tid, "no thread id from attach")
            h = dbg.open_thread(tid)
            regs = dbg.get_registers(h)
            self.assertEqual(regs["arch"], "x86")
            self.assertLess(regs["eip"], 0x100000000)
        finally:
            if h is not None:
                try:
                    dbg.close_handle(h)
                except Exception:
                    pass
            try:
                dbg.detach()
            except Exception:
                pass
            proc.kill()
            proc.wait()
            ph = dbg._session.process_handle
            if ph:
                try:
                    dbg.close_handle(ph)
                except Exception:
                    pass

    def test_attach_hw_breakpoint(self):
        import subprocess
        from pydbg import Debugger

        proc = subprocess.Popen(
            [TEST_WOW64_TARGET],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        dbg = Debugger()
        h = None
        try:
            dbg.attach(proc.pid)
            tid = None
            event = dbg.wait_event(5000)
            if event is not None:
                tid = event.tid
                dbg.continue_event(event.pid, event.tid)
            # Drain like _launch(run=True): continue everything (including the
            # 64-bit bootstrap breakpoints 0x80000003) until the 32-bit image
            # is mapped and the WX86 loader breakpoint 0x4000001F has passed,
            # so main() is running. Setting a hw-bp while the process runs
            # (suspend-first, per the WOW64 quirk in hardware.py) reliably arms
            # Dr0 — setting it while paused at the loader breakpoint does not
            # take effect on WOW64 attach.
            saw_image = False
            for _ in range(50):
                event = dbg.wait_event(2000)
                if event is None or event.type == "EXIT_PROCESS":
                    break
                if tid is None:
                    tid = event.tid
                dbg.continue_event(event.pid, event.tid)
                if event.type == "EXCEPTION":
                    if saw_image:
                        break
                    continue
                try:
                    if _module_by_name(dbg, os.path.basename(TEST_WOW64_TARGET)):
                        saw_image = True
                except Exception:
                    pass

            self.assertIsNotNone(tid)
            # thread_handle must now be set (Fix 1)
            self.assertIsNotNone(dbg._session.thread_handle)

            exe = _module_by_name(dbg, os.path.basename(TEST_WOW64_TARGET))
            self.assertIsNotNone(exe, "32-bit exe not enumerated after attach")
            base = exe["base_address"]
            addr = _export_address(dbg, TEST_WOW64_TARGET, base, "target_add")
            bp_id = dbg.set_hw_breakpoint(addr, "x", 1, 0)
            dbg.continue_event(dbg._session.pid, tid)

            hit = False
            start = time.time()
            for _ in range(100):
                if time.time() - start > 15:
                    break
                ev = dbg.wait_event(2000)
                if ev is None:
                    continue
                if ev.type == "EXCEPTION" and ev.exception_code in (0x80000004, 0x4000001E):
                    h = dbg.open_thread(tid)
                    regs = dbg.get_registers(h)
                    self.assertTrue(regs["dr6"] & 1)
                    self.assertEqual(regs["eip"], addr)
                    hit = True
                    dbg.brk_hw.clear(0)
                    dbg.continue_event(ev.pid, ev.tid)
                    break
                dbg.continue_event(ev.pid, ev.tid)
            self.assertTrue(hit, "Dr0 breakpoint not hit after attach")
            try:
                dbg.remove_breakpoint(bp_id)
            except Exception:
                pass
        finally:
            if h is not None:
                try:
                    dbg.close_handle(h)
                except Exception:
                    pass
            try:
                dbg.detach()
            except Exception:
                pass
            proc.kill()
            proc.wait()


class TestWow64ArchMapping(unittest.TestCase):
    def test_arch_for_tid_falls_back_to_main(self):
        from pydbg.core.session import DebugSession

        s = DebugSession()
        s.target_arch = 32
        s.register_pid_arch(100, 32)
        s.register_tid_arch(200, 64)
        self.assertEqual(s.arch_for_tid(200), 64)
        self.assertEqual(s.arch_for_tid(999), 32)  # fallback to main


@unittest.skipUnless(_wow64_available(), "requires 64-bit host")
class TestWow64ChildProcess(unittest.TestCase):
    def test_cross_arch_child_gets_correct_machine(self):
        from pydbg import Debugger
        from tests.helpers import teardown

        spawn = os.path.join(_TEST_DIR, "target", "spawn_child.exe")
        child = os.path.join(_TEST_DIR, "target", "child_target_x64.exe")
        if not (os.path.exists(spawn) and os.path.exists(child)):
            self.skipTest("spawn_child.exe / child_target_x64.exe not built")
        dbg = Debugger()
        dbg.set_debug_children(True)
        try:
            parent_pid, _ = dbg.create_process(f'"{spawn}" "{child}"')
            child_pid = child_tid = None
            for _ in range(100):
                ev = dbg.wait_event(2000)
                if ev is None:
                    break
                if ev.type == "CREATE_PROCESS" and ev.pid != parent_pid:
                    child_pid = ev.pid
                    child_tid = ev.tid
                    dbg.continue_event(ev.pid, ev.tid)
                    break
                dbg.continue_event(ev.pid, ev.tid)
                if ev.type == "EXIT_PROCESS" and ev.pid == parent_pid:
                    break

            self.assertIsNotNone(child_pid, "x64 child CREATE_PROCESS not seen")
            # parent is WOW64 (32); child_target_x64 is native x64
            self.assertEqual(dbg._session.arch_for_tid(child_tid), 64)
            h = dbg.open_thread(child_tid)
            regs = dbg.get_registers(h)
            dbg.close_handle(h)
            self.assertEqual(regs["arch"], "x64")
            self.assertIn("rip", regs)
            # Drain the child's exit so no orphaned events leak into later
            # tests (same isolation hazard that affects test_child_process).
            # Terminate the child first: it is paused at the loader breakpoint
            # and would not exit within a bounded wait otherwise.
            try:
                dbg.terminate_process(0, pid=child_pid)
            except Exception:
                pass
            for _ in range(50):
                ev = dbg.wait_event(2000)
                if ev is None:
                    break
                dbg.continue_event(ev.pid, ev.tid)
                if ev.type == "EXIT_PROCESS" and ev.pid == child_pid:
                    break
        finally:
            teardown(dbg)
