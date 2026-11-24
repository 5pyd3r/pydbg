"""BblInstrumenter: plan blocks, install detours, drain events, uninstall.

The orchestration layer joins three pieces that were built and tested apart:
the block plan (`cfg_of` plus `take_prefix`/`prefix_is_relocatable` from P30),
the target-side event ring (P31) and the thread-safe patch writer (P32). The
tests here are about *composition*: that a block which cannot host a detour is
still planned and then refused with a reason, that one block's refusal does not
abort the rest, that the ring is allocated once for the whole instrumenter, and
that uninstall restores exactly the bytes install displaced.

Two fakes carry most of it. `FakeAnalysis` answers the CFG questions the way
`AnalysisResult` does (a decoder, an exec filter, a function table) without a
PE and without capstone; `FakeDebugger` owns a memory image, an allocator and a
few threads, so install/uninstall can run without the Cython extension. The live
test at the bottom needs both the extension and a built target, and skips with
the two declared skip families otherwise.
"""

import os
import struct
import unittest
from types import SimpleNamespace
from unittest import mock

from pydbg.disasm.engine import OP_IMM, Instruction, Operand
from pydbg.exceptions import MemError, PydbgError, ThreadError
from pydbg.instrument import bbl
from pydbg.instrument.bbl import BlockPlan, InstallReport
from pydbg.trace.format import BLOCK, TraceEvent

try:
    import keystone  # noqa: F401

    _has_keystone = True
except ImportError:                      # pragma: no cover - environment
    _has_keystone = False

needs_keystone = unittest.skipUnless(
    _has_keystone, "optional dependency: keystone-engine")

# The live target: the same C loop test_instrument.py, test_trace_*.py and the
# probe tests use (meson exports it as TEST_INSTRUMENT_TARGET_PATH).
_TARGET = os.environ.get(
    "TEST_INSTRUMENT_TARGET_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "target", "instrument_target.exe"))

try:
    from pydbg import _pydbg  # noqa: F401

    _has_cython = True
except ImportError:                      # pragma: no cover - environment
    _has_cython = False


BASE = 0x140000000
MODULE = (BASE, 0x10000)

# Where the patched near-allocator puts the stub region: inside ±2GB of BASE,
# which is what the real allocator has to guarantee for the E9 detour.
STUB_REGION = BASE + 0x20000

# How far from the module a 5-byte E9 can reach. Spelled out here rather than
# imported so the allocator's window is checked against the specification, not
# against itself (it is the frozen instrumenter's ±2GB window).
_RELOC_WINDOW = 0x7F000000


def insn(address, size, mnemonic="nop", raw=None, **flags):
    """One decoded instruction: the fields the CFG and the relocator read."""
    return Instruction(address=address, size=size, mnemonic=mnemonic,
                       op_str="", raw_bytes=raw if raw is not None else b"\x90" * size,
                       **flags)


def nops(start, count):
    return [insn(start + offset, 1) for offset in range(count)]


class FakeImage:
    """An exec filter and VA/RVA translation, like `AnalyzedImage`."""

    def __init__(self, base=BASE, exec_ranges=((0x1000, 0x2000),)):
        self.base = base
        self.exec_ranges = tuple(exec_ranges)

    def is_exec(self, rva):
        return any(start <= rva < end for start, end in self.exec_ranges)

    def va_to_rva(self, va):
        return va - self.base


class FakeFunctions:
    """The four function-table questions `cfg_of` asks, and nothing else."""

    def __init__(self, entries):
        self.entries = tuple(entries)

    def functions(self):
        return [SimpleNamespace(rva=entry, size=0, confident=True)
                for entry in self.entries]

    def containing(self, rva):
        preceding = [entry for entry in self.entries if entry <= rva]
        return max(preceding) if preceding else None

    def extent_of(self, entry):
        return 0                 # unbounded: the fake instructions end in `ret`

    def set_exact_extents(self, mapping):
        pass


class FakeDecoder:
    """A decoder that answers from a dict, like `InstructionDecoder`."""

    def __init__(self, instructions):
        self.instructions = {item.address: item for item in instructions}

    def decode_one(self, address):
        return self.instructions.get(address)


def make_result(instructions, entries, exec_ranges=None):
    """An AnalysisResult stand-in: decoder, image and function table."""
    image = FakeImage(exec_ranges=exec_ranges or ((0x1000, 0x2000),))
    return SimpleNamespace(image=image, functions=FakeFunctions(entries),
                           decoder=FakeDecoder(instructions))


class FakeThread:
    """One target thread: its tid, its RIP, and the errors a test injects."""

    def __init__(self, tid, rip=0x7FF000001000):
        self.tid = tid
        self.rip = rip
        self.handle = tid * 0x10
        self.suspend_count = 0
        self.open_error = None
        self.suspend_error = None
        self.context_error = None
        self.resume_error = None


class FakeMemory:
    """A MemoryManager stand-in for the event buffer and stub cleanup.

    Regions are byte-addressed so a test can write the records a stub would
    have appended and then read them through the real `EventBuffer.read()`.
    """

    def __init__(self, next_address=0x20000000):
        self.regions = {}
        self.allocations = []
        self.freed = []
        self.free_error = None
        self._next = next_address

    def alloc_remote(self, size, protect=0x04):
        base = self._next
        self._next += 0x100000
        self.regions[base] = bytearray(size)      # Windows zero-fills
        self.allocations.append(base)
        return base

    def free_remote(self, address):
        self.freed.append(address)
        if self.free_error is not None:
            raise MemError(self.free_error)
        self.regions.pop(address, None)

    def read(self, address, size):
        base, offset = self._locate(address, size)
        return bytes(self.regions[base][offset:offset + size])

    def write(self, address, data):
        base, offset = self._locate(address, len(data))
        self.regions[base][offset:offset + len(data)] = data

    def _locate(self, address, size):
        for base, buffer in self.regions.items():
            if base <= address and address + size <= base + len(buffer):
                return base, address - base
        raise MemError(
            f"no fake region covers 0x{address:X}..0x{address + size:X}")


class FakeDebugger:
    """A debugger-shaped object: code bytes, an allocator and threads."""

    def __init__(self, threads):
        self.threads = {thread.tid: thread for thread in threads}
        self.by_handle = {thread.handle: thread for thread in threads}
        self.memory = FakeMemory()
        self.code = {}
        self.read_calls = []
        self.writes = []
        self.protect_calls = []
        self.suspend_calls = []
        self.resume_calls = []
        self.close_calls = []
        # Errors raised by the next enumerate_threads() calls, in order.
        self.enum_errors = []
        self.original_protect = 0x20            # PAGE_EXECUTE_READ

    # ── code memory ──

    def put(self, address, data):
        for offset, byte in enumerate(data):
            self.code[address + offset] = byte

    def bytes_at(self, address, size):
        return bytes(self.code.get(address + offset, 0)
                     for offset in range(size))

    def read_memory(self, address, size):
        self.read_calls.append((address, size))
        return self.bytes_at(address, size)

    def write_memory(self, address, data):
        self.writes.append((address, bytes(data)))
        self.put(address, data)

    def protect_memory(self, address, size, protect):
        self.protect_calls.append((address, size, protect))
        return self.original_protect

    # ── threads ──

    def enumerate_threads(self):
        if self.enum_errors:
            raise self.enum_errors.pop(0)
        return [{"tid": tid} for tid in sorted(self.threads)]

    def open_thread(self, tid):
        thread = self.threads[tid]
        if thread.open_error is not None:
            raise thread.open_error
        return thread.handle

    def suspend_thread(self, handle):
        thread = self.by_handle[handle]
        self.suspend_calls.append(thread.tid)
        if thread.suspend_error is not None:
            raise thread.suspend_error
        thread.suspend_count += 1

    def resume_thread(self, handle):
        thread = self.by_handle[handle]
        self.resume_calls.append(thread.tid)
        if thread.resume_error is not None:
            raise thread.resume_error
        thread.suspend_count -= 1

    def get_registers(self, handle):
        thread = self.by_handle[handle]
        if thread.context_error is not None:
            raise thread.context_error
        return {"rip": thread.rip}

    def close_handle(self, handle):
        self.close_calls.append(handle)

    # ── assertions ──

    def patches(self):
        """(address, bytes) for writes that landed on the module's code."""
        return [(address, data) for address, data in self.writes
                if BASE <= address < BASE + MODULE[1]]


def _install_fixture(test):
    """Seed one thread, two installable blocks and the stub allocator."""
    test.thread = FakeThread(7)
    test.dbg = FakeDebugger([test.thread])
    test.dbg.put(BASE + 0x1000, b"\x90" * 6 + b"\xC3")
    test.dbg.put(BASE + 0x1100, b"\x48\x89\xD8\x48\x89\xC8\xC3")
    instructions = (nops(0x1000, 6) + [insn(0x1006, 1, "ret", is_ret=True)]
                    + [insn(0x1100, 3, "mov", raw=b"\x48\x89\xD8"),
                       insn(0x1103, 3, "mov", raw=b"\x48\x89\xC8"),
                       insn(0x1106, 1, "ret", is_ret=True)])
    test.result = make_result(instructions, [0x1000, 0x1100])
    test.alloc_calls = []

    def alloc_near(dbg, near, size):
        test.alloc_calls.append((near, size))
        return STUB_REGION

    patcher = mock.patch.object(bbl, "alloc_near", side_effect=alloc_near)
    patcher.start()
    test.addCleanup(patcher.stop)


@needs_keystone
class TestInstall(unittest.TestCase):
    """install() is per-block: one refusal never stops the rest."""

    def setUp(self):
        _install_fixture(self)

    def instrumenter(self, **kwargs):
        return bbl.BblInstrumenter(self.dbg, module=MODULE,
                                   result=self.result, **kwargs)

    def test_installable_blocks_get_a_detour_and_a_stub(self):
        report = self.instrumenter().install()

        self.assertEqual(report, InstallReport(
            installed=(0x1000, 0x1100), refused=(), warnings=()))
        first, second = self.dbg.patches()
        self.assertEqual(first, (BASE + 0x1000, first[1]))
        self.assertEqual(first[1][0], 0xE9)
        self.assertEqual(len(first[1]), 5, "one prefix, one E9")
        self.assertEqual(second[0], BASE + 0x1100)
        self.assertEqual(len(second[1]), 6,
                         "a two-instruction prefix is displaced whole")
        self.assertEqual(second[1][0], 0xE9)
        self.assertEqual(second[1][5:], b"\x90",
                         "the bytes after the E9 are NOP padding the stub "
                         "falls through on the way back to block + 5")

    def test_the_stub_region_is_allocated_once_near_the_module(self):
        self.instrumenter().install()

        self.assertEqual(len(self.alloc_calls), 1)
        near, size = self.alloc_calls[0]
        self.assertEqual(near, BASE)
        # 2 stubs: prologue + prefix + the 14-byte absolute jump back.
        self.assertGreaterEqual(size, 2 * (112 + 5 + 14))

    def test_the_event_buffer_is_allocated_once_for_the_whole_install(self):
        self.instrumenter().install()

        self.assertEqual(len(self.dbg.memory.allocations), 1,
                         "a per-block ring would scatter the events")

    def test_each_stub_carries_its_block_rva_and_jump_back(self):
        self.instrumenter().install()

        stub_writes = [(address, data) for address, data in self.dbg.writes
                       if address >= STUB_REGION]
        self.assertEqual(len(stub_writes), 2)
        first = stub_writes[0][1]
        self.assertIn(struct.pack("<I", 0x1000), first)
        self.assertEqual(struct.unpack("<Q", first[-8:])[0], BASE + 0x1000 + 5)
        second = stub_writes[1][1]
        self.assertIn(struct.pack("<I", 0x1100), second)
        self.assertEqual(struct.unpack("<Q", second[-8:])[0], BASE + 0x1100 + 5)
        self.assertEqual(stub_writes[1][0],
                         STUB_REGION + len(first),
                         "stubs share the one region")

    def test_the_original_bytes_are_read_before_the_detour_is_written(self):
        self.instrumenter().install()

        self.assertEqual(self.dbg.read_calls,
                         [(BASE + 0x1000, 5), (BASE + 0x1100, 6)])
        addresses = [address for address, _ in self.dbg.writes]
        self.assertLess(addresses.index(BASE + 0x1000),
                        addresses.index(BASE + 0x1100))

    def test_a_block_that_cannot_host_a_detour_is_refused_with_its_reason(self):
        self.dbg.put(BASE + 0x1020, b"\xE9\x00\x00\x00\x00")
        self.dbg.put(BASE + 0x1040, b"\x48\x89\xD8\xC3")
        result = make_result(
            nops(0x1000, 6) + [insn(0x1006, 1, "ret", is_ret=True)]
            + [insn(0x1020, 5, "jmp", raw=b"\xE9\x00\x00\x00\x00",
                    is_jmp=True)]
            + [insn(0x1040, 3, "mov", raw=b"\x48\x89\xD8"),
               insn(0x1043, 1, "ret", is_ret=True)],
            [0x1000, 0x1020, 0x1040])
        instrumenter = bbl.BblInstrumenter(self.dbg, module=MODULE,
                                           result=result)

        report = instrumenter.install()

        self.assertEqual(report.installed, (0x1000,))
        self.assertEqual([rva for rva, _ in report.refused], [0x1020, 0x1040])
        self.assertEqual(len(report.installed) + len(report.refused), 3,
                         "no planned block may be silently skipped")
        for rva, reason in report.refused:
            self.assertTrue(reason, f"block 0x{rva:X} was refused without one")
        by_rva = dict(report.refused)
        self.assertIn("jmp", by_rva[0x1020])
        self.assertIn("5", by_rva[0x1040])
        self.assertEqual(self.dbg.bytes_at(BASE + 0x1020, 5),
                         b"\xE9\x00\x00\x00\x00")

    def test_a_thread_inside_one_window_refuses_only_that_block(self):
        self.thread.rip = BASE + 0x1002

        report = self.instrumenter().install()

        self.assertEqual(report.installed, (0x1100,))
        self.assertEqual(len(report.refused), 1)
        rva, reason = report.refused[0]
        self.assertEqual(rva, 0x1000)
        self.assertIn("target busy", reason)
        self.assertEqual(self.dbg.bytes_at(BASE + 0x1000, 5),
                         b"\x90\x90\x90\x90\x90",
                         "a refused block must not be written")

    def test_a_thread_enumeration_failure_refuses_one_block_not_the_install(self):
        self.dbg.enum_errors = [ThreadError("cannot enumerate threads")]

        report = self.instrumenter().install()

        self.assertEqual(report.installed, (0x1100,),
                         "the next block must still be attempted")
        self.assertEqual(len(report.refused), 1)
        self.assertEqual(report.refused[0][0], 0x1000)
        self.assertIn("cannot enumerate threads", report.refused[0][1])

    def test_a_missing_module_base_refuses_every_planned_block(self):
        dbg = SimpleNamespace(enum_modules=lambda: [])

        report = bbl.BblInstrumenter(dbg, result=self.result).install()

        self.assertEqual(report.installed, ())
        self.assertEqual([rva for rva, _ in report.refused], [0x1000, 0x1100])
        for _, reason in report.refused:
            self.assertIn("module base", reason)

    def test_inside_the_window_counts_as_a_busy_block_on_uninstall(self):
        """TargetBusy on cleanup keeps the detour, and frees nothing under it."""
        instrumenter = self.instrumenter()
        instrumenter.install()
        self.thread.rip = BASE + 0x1000 + 4

        warnings = instrumenter.uninstall()

        self.assertIn("target busy", warnings[0])
        self.assertIn("kept", warnings[-1],
                      "the caller must know the memory outlived the detour")
        self.assertEqual(self.dbg.memory.freed, [],
                         "the ring must outlive the detours that point into it")
        self.assertEqual(self.dbg.bytes_at(BASE + 0x1000, 1), b"\xE9")

    def test_install_is_idempotent(self):
        instrumenter = self.instrumenter()

        first = instrumenter.install()
        second = instrumenter.install()

        self.assertEqual(first, second)
        self.assertEqual(len(self.dbg.patches()), 2)


@needs_keystone
class TestInstallSetupFailures(unittest.TestCase):
    """A shared-resource failure becomes one reason per block, not an abort."""

    def setUp(self):
        _install_fixture(self)

    def test_a_missing_keystone_refuses_the_installable_blocks(self):
        with mock.patch.object(bbl, "keystone", None):
            report = bbl.BblInstrumenter(
                self.dbg, module=MODULE, result=self.result).install()

        self.assertEqual(report.installed, ())
        self.assertEqual([rva for rva, _ in report.refused], [0x1000, 0x1100])
        for _, reason in report.refused:
            self.assertIn("keystone-engine", reason)
        self.assertEqual(self.dbg.memory.allocations, [],
                         "nothing can be recorded, so nothing is allocated")

    def test_a_failed_stub_allocation_frees_the_ring_and_refuses_the_blocks(self):
        with mock.patch.object(
                bbl, "alloc_near",
                side_effect=PydbgError("no free region within 2GB")):
            report = bbl.BblInstrumenter(
                self.dbg, module=MODULE, result=self.result).install()

        self.assertEqual(report.installed, ())
        self.assertEqual([rva for rva, _ in report.refused], [0x1000, 0x1100])
        for _, reason in report.refused:
            self.assertIn("stub memory", reason)
        self.assertEqual(len(self.dbg.memory.allocations), 1)
        self.assertEqual(self.dbg.memory.freed, self.dbg.memory.allocations)


class TestPlan(unittest.TestCase):
    """plan() keeps what install needs, not just the block starts."""

    def test_a_plain_block_is_one_plan_with_its_prefix_and_instruction_list(self):
        instructions = nops(0x1000, 6) + [insn(0x1006, 1, "ret", is_ret=True)]
        result = make_result(instructions, [0x1000])

        plans = bbl.BblInstrumenter(None, result=result).plan()

        self.assertEqual(plans, (BlockPlan(
            rva=0x1000,
            span=7,                       # six NOPs and the ret
            instruction_rvas=(0x1000, 0x1001, 0x1002, 0x1003, 0x1004,
                              0x1005, 0x1006),
            prefix_size=5,                # five one-byte NOPs cover the detour
            relocatable=True,
        ),))

    def test_a_branch_prefix_is_kept_but_marked_unrelocatable(self):
        """It is refused at install time, not silently dropped from the plan."""
        instructions = [insn(0x1020, 5, "jmp", raw=b"\xE9\x00\x00\x00\x00",
                             is_jmp=True)]
        result = make_result(instructions, [0x1020])

        plans = bbl.BblInstrumenter(None, result=result).plan()

        self.assertEqual(len(plans), 1)
        self.assertEqual(plans[0].rva, 0x1020)
        self.assertEqual(plans[0].prefix_size, 5)
        self.assertFalse(plans[0].relocatable)

    def test_a_block_shorter_than_the_detour_is_kept_with_no_prefix(self):
        instructions = [insn(0x1040, 3, "mov", raw=b"\x48\x89\xD8"),
                        insn(0x1043, 1, "ret", is_ret=True)]
        result = make_result(instructions, [0x1040])

        plans = bbl.BblInstrumenter(None, result=result).plan()

        self.assertEqual(len(plans), 1)
        self.assertEqual(plans[0].rva, 0x1040)
        self.assertEqual(plans[0].span, 4)
        self.assertEqual(plans[0].prefix_size, 0,
                         "there is no detour-sized prefix to displace")
        self.assertFalse(plans[0].relocatable)

    def test_two_instructions_make_a_prefix_longer_than_five_bytes(self):
        instructions = [insn(0x1100, 3, "mov", raw=b"\x48\x89\xD8"),
                        insn(0x1103, 3, "mov", raw=b"\x48\x89\xC8"),
                        insn(0x1106, 1, "ret", is_ret=True)]
        result = make_result(instructions, [0x1100])

        plans = bbl.BblInstrumenter(None, result=result).plan()

        self.assertEqual(plans[0].prefix_size, 6)
        self.assertEqual(plans[0].span, 7)
        self.assertTrue(plans[0].relocatable)

    def test_block_starts_are_deduplicated_across_functions(self):
        """A jump target belongs to its own function and to the one jumping."""
        jcc = insn(0x1060, 2, "je", raw=b"\x74\x20", is_jmp=True, is_cond=True,
                   operands=(Operand(kind=OP_IMM, imm=BASE + 0x1080),))
        instructions = ([jcc] + nops(0x1062, 1) + [insn(0x1063, 1, "ret", is_ret=True)]
                        + nops(0x1080, 4) + [insn(0x1084, 1, "ret", is_ret=True)])
        result = make_result(instructions, [0x1060, 0x1080])

        plans = bbl.BblInstrumenter(None, result=result).plan()

        self.assertEqual([plan.rva for plan in plans],
                         [0x1060, 0x1062, 0x1080])
        self.assertEqual(len({plan.rva for plan in plans}), len(plans))

    def test_blocks_outside_an_executable_section_are_not_planned(self):
        instructions = nops(0x1000, 6) + [insn(0x1006, 1, "ret", is_ret=True)]
        result = make_result(instructions, [0x1000],
                             exec_ranges=((0x2000, 0x3000),))

        self.assertEqual(bbl.BblInstrumenter(None, result=result).plan(), ())

    def test_max_blocks_truncates_before_a_block_is_added(self):
        instructions = nops(0x1000, 6) + [insn(0x1006, 1, "ret", is_ret=True)]
        result = make_result(instructions, [0x1000])

        plans = bbl.BblInstrumenter(None, result=result, max_blocks=0).plan()

        self.assertEqual(plans, (), "a budget of zero plans exactly nothing")

    def test_an_explicit_block_list_overrides_the_cfg_source(self):
        instructions = nops(0x1000, 6) + [insn(0x1006, 1, "ret", is_ret=True)]
        result = make_result(instructions, [0x1000])

        plans = bbl.BblInstrumenter(
            None, result=result, blocks=[0x1006, 0x1000, 0x1000]).plan()

        self.assertEqual([plan.rva for plan in plans], [0x1000, 0x1006])

    def test_an_unattached_debugger_plans_nothing_instead_of_raising(self):
        dbg = SimpleNamespace(enum_modules=lambda: [])

        self.assertEqual(bbl.BblInstrumenter(dbg).plan(), ())

    def test_plan_is_computed_once(self):
        instructions = nops(0x1000, 6) + [insn(0x1006, 1, "ret", is_ret=True)]
        result = make_result(instructions, [0x1000])
        instrumenter = bbl.BblInstrumenter(None, result=result)

        first = instrumenter.plan()
        result.decoder.instructions.clear()

        self.assertEqual(instrumenter.plan(), first)


# The v1 record, spelled out here rather than imported: the ring layout in
# event_buffer is the writer's contract, and a test that reuses its struct
# cannot catch a writer/reader disagreement.
_RECORD = struct.Struct("<B3xIIQQQ")
_HEADER_SIZE = 32
_HEAD_OFFSET = 20
_SLOT_SIZE = _RECORD.size


@needs_keystone
class TestEvents(unittest.TestCase):
    """events() drains the target ring, newest-bounded, and clears it."""

    def setUp(self):
        _install_fixture(self)

    def install(self, max_events=100_000):
        instrumenter = bbl.BblInstrumenter(
            self.dbg, module=MODULE, result=self.result,
            max_events=max_events)
        instrumenter.install()
        return instrumenter

    def write_records(self, records):
        """Append records the way the stub does, then bump the head."""
        ring = self.dbg.memory.allocations[0]
        for count, event in enumerate(records):
            slot = ring + _HEADER_SIZE + count * _SLOT_SIZE
            self.dbg.memory.write(slot, _RECORD.pack(
                event.kind, event.tid, event.rva, event.ts, event.a, event.b))
        self.dbg.memory.write(ring + _HEAD_OFFSET,
                              struct.pack("<I", len(records)))

    def test_records_come_back_as_the_trace_events_the_stub_wrote(self):
        instrumenter = self.install()
        records = (
            TraceEvent(kind=BLOCK, tid=0, rva=0x1000, ts=0, a=7, b=0),
            TraceEvent(kind=BLOCK, tid=0, rva=0x1100, ts=0, a=3, b=0),
        )
        self.write_records(records)

        self.assertEqual(instrumenter.events(), records)

    def test_a_second_events_call_sees_only_what_is_new(self):
        instrumenter = self.install()
        self.write_records((TraceEvent(kind=BLOCK, tid=0, rva=0x1000,
                                       ts=0, a=7),))

        self.assertEqual(len(instrumenter.events()), 1)
        self.assertEqual(instrumenter.events(), ())

    def test_events_are_truncated_to_max_events(self):
        instrumenter = self.install(max_events=3)
        records = tuple(TraceEvent(kind=BLOCK, tid=0, rva=0x1000 + index,
                                   ts=0, a=index) for index in range(4))
        self.write_records(records)

        events = instrumenter.events()

        self.assertEqual(len(events), 3)
        self.assertEqual([event.a for event in events], [0, 1, 2],
                         "the budget keeps the first events, like BblTracer")

    def test_a_zero_budget_returns_nothing_without_touching_the_ring(self):
        instrumenter = self.install(max_events=0)
        self.write_records((TraceEvent(kind=BLOCK, tid=0, rva=0x1000,
                                       ts=0, a=7),))

        self.assertEqual(instrumenter.events(), ())


@needs_keystone
class TestUninstall(unittest.TestCase):
    """uninstall() restores exactly what install displaced, then frees."""

    def setUp(self):
        _install_fixture(self)
        self.originals = {
            BASE + 0x1000: self.dbg.bytes_at(BASE + 0x1000, 5),
            BASE + 0x1100: self.dbg.bytes_at(BASE + 0x1100, 6),
        }
        self.instrumenter = bbl.BblInstrumenter(
            self.dbg, module=MODULE, result=self.result)
        self.instrumenter.install()
        self.dbg.writes.clear()

    def test_the_displaced_bytes_are_restored_in_install_order(self):
        warnings = self.instrumenter.uninstall()

        self.assertEqual(warnings, ())
        self.assertEqual(self.dbg.patches(), [
            (BASE + 0x1000, self.originals[BASE + 0x1000]),
            (BASE + 0x1100, self.originals[BASE + 0x1100]),
        ])
        self.assertEqual(self.dbg.bytes_at(BASE + 0x1000, 5),
                         self.originals[BASE + 0x1000])
        self.assertEqual(self.dbg.bytes_at(BASE + 0x1100, 6),
                         self.originals[BASE + 0x1100])

    def test_the_ring_and_the_stub_region_are_released_in_that_order(self):
        ring = self.dbg.memory.allocations[0]

        self.instrumenter.uninstall()

        self.assertEqual(self.dbg.memory.freed, [ring, STUB_REGION])
        self.assertEqual(self.instrumenter.events(), ())

    def test_a_byte_changed_under_us_is_reported_and_left_alone(self):
        self.dbg.put(BASE + 0x1000, b"\xCC")

        warnings = self.instrumenter.uninstall()

        self.assertTrue(any("bytes changed under us" in warning
                            for warning in warnings), warnings)
        self.assertEqual(self.dbg.bytes_at(BASE + 0x1000, 1), b"\xCC",
                         "a changed byte must not be silently overwritten")
        self.assertEqual(self.dbg.bytes_at(BASE + 0x1100, 6),
                         self.originals[BASE + 0x1100],
                         "the other block is still restored")

    def test_a_second_uninstall_is_a_no_op(self):
        self.instrumenter.uninstall()
        self.dbg.writes.clear()

        self.assertEqual(self.instrumenter.uninstall(), ())
        self.assertEqual(self.dbg.writes, [])

    def test_uninstall_without_an_install_is_a_no_op(self):
        instrumenter = bbl.BblInstrumenter(
            self.dbg, module=MODULE, result=self.result)

        self.assertEqual(instrumenter.uninstall(), ())

    def test_a_ring_that_cannot_be_released_is_reported_and_retried(self):
        self.dbg.memory.free_error = "access denied"

        first = self.instrumenter.uninstall()

        self.assertTrue(any(warning.startswith("event buffer:")
                            for warning in first), first)
        self.dbg.memory.free_error = None
        self.dbg.writes.clear()

        self.assertEqual(self.instrumenter.uninstall(), ())

    def test_install_works_again_after_a_clean_uninstall(self):
        self.instrumenter.uninstall()

        report = self.instrumenter.install()

        self.assertEqual(report.installed, (0x1000, 0x1100))
        self.assertEqual(self.dbg.bytes_at(BASE + 0x1000, 1), b"\xE9")


class TestStubHint(unittest.TestCase):
    """The pure half of the near allocator: where inside a free region to ask."""

    def test_the_window_is_the_frozen_plus_or_minus_2gb(self):
        self.assertEqual(bbl._RELOC_WINDOW, _RELOC_WINDOW)

    def test_an_aligned_free_region_is_used_as_is(self):
        region = {"base_address": BASE + 0x100000, "region_size": 0x10000}

        self.assertEqual(bbl._stub_hint(region, BASE, 0x1000),
                         BASE + 0x100000)

    def test_a_misaligned_region_base_is_rounded_up(self):
        region = {"base_address": BASE + 0x100123, "region_size": 0x20000}

        self.assertEqual(bbl._stub_hint(region, BASE, 0x1000),
                         BASE + 0x110000)

    def test_a_region_smaller_than_the_request_is_rejected(self):
        region = {"base_address": BASE + 0x100000, "region_size": 0x800}

        self.assertIsNone(bbl._stub_hint(region, BASE, 0x1000))

    def test_a_hint_that_would_leave_the_window_is_clamped(self):
        high = BASE + _RELOC_WINDOW
        region = {"base_address": high - 0x8000, "region_size": 0x10000}

        hint = bbl._stub_hint(region, BASE, 0x1000)

        self.assertEqual(hint, high - 0x1000)

    def test_a_clamp_that_falls_before_the_region_is_rejected(self):
        high = BASE + _RELOC_WINDOW
        region = {"base_address": high - 0x100, "region_size": 0x20000}

        self.assertIsNone(bbl._stub_hint(region, BASE, 0x8000))


class TestRingCapacity(unittest.TestCase):
    """The slot count is a power of two at or above the event budget."""

    def test_the_capacity_holds_the_budget_and_stays_a_power_of_two(self):
        for budget, expected in ((0, 1), (1, 1), (2, 2), (3, 4),
                                 (100_000, 131_072)):
            with self.subTest(budget=budget):
                capacity = bbl._ring_capacity(budget)
                self.assertEqual(capacity, expected)
                self.assertEqual(capacity & (capacity - 1), 0)
                self.assertGreaterEqual(capacity, max(1, budget))


class TestPublicName(unittest.TestCase):
    """The instrumenter is reachable through the package's lazy facade."""

    def test_bbl_instrumenter_is_a_lazy_public_name(self):
        from pydbg import instrument

        self.assertIn("BblInstrumenter", instrument.__all__)
        self.assertIn("BblInstrumenter", dir(instrument))
        self.assertIs(instrument.BblInstrumenter, bbl.BblInstrumenter)


@needs_keystone
@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
@unittest.skipUnless(os.path.isfile(_TARGET), "target not built: " + _TARGET)
class TestLiveInstrumenter(unittest.TestCase):
    """A real target runs a detoured block, reports it, and gets its bytes back."""

    def test_a_live_block_records_an_event_and_restores_its_bytes(self):
        from pydbg.analysis import analyze_process
        from pydbg.analysis.cfg import cfg_of
        from pydbg.trace.format import BLOCK as BLOCK_KIND
        from tests.helpers import (
            create_debugger, entry_point, export_address, module_base, teardown,
        )

        dbg, pid, tid = create_debugger(_TARGET)
        try:
            module = dbg.enum_modules()[0]
            base = module_base(dbg)
            entry_rva = entry_point(dbg) - base
            add_rva = export_address(dbg, _TARGET, "add_numbers") - base
            result = analyze_process(dbg._session, base,
                                     module_size=module["size"])

            # The blocks of the entry function are the ones the target must
            # walk after we resume; add_numbers itself is left alone so
            # run_until can use it as the stop address without landing inside
            # an installed window.
            planner = bbl.BblInstrumenter(
                dbg, module=module, result=result, max_blocks=256,
                max_events=256)
            plans = planner.plan()
            self.assertGreater(len(plans), 0, "the target planned no blocks")
            entry_cfg = cfg_of(result, entry_rva)
            entry_blocks = ({block.rva for block in entry_cfg.blocks.values()}
                            if entry_cfg is not None else set())
            chosen = [plan for plan in plans if plan.relocatable
                      and plan.rva != add_rva and plan.rva in entry_blocks]
            if not chosen:
                # The entry function was fully unrelocatable; fall back to
                # anything that can host a detour, so the run still proves
                # the channel rather than skipping silently.
                chosen = [plan for plan in plans
                          if plan.relocatable and plan.rva != add_rva]
            self.assertTrue(chosen, "no block can host a detour")
            chosen = chosen[:16]

            instrumenter = bbl.BblInstrumenter(
                dbg, module=module, result=result,
                blocks=[plan.rva for plan in chosen], max_events=256)
            planned = instrumenter.plan()
            originals = {base + plan.rva: dbg.read_memory(
                base + plan.rva, plan.prefix_size)
                for plan in planned if plan.prefix_size}

            report = instrumenter.install()
            self.assertTrue(report.installed, report.refused)

            dbg.continue_event(pid, tid)
            dbg.run_until(add_rva + base, max_wait_ms=10000,
                          max_idle_timeouts=3)

            events = instrumenter.events()
            self.assertTrue(events, "the detoured blocks recorded no event")
            for event in events:
                self.assertEqual(event.kind, BLOCK_KIND)
                self.assertEqual(event.tid, 0, "the stub cannot know a tid")
                self.assertEqual(event.ts, 0, "the stub cannot know a ts")
            self.assertTrue({event.rva for event in events}
                            & set(report.installed),
                            "an event names a block that was never installed")

            self.assertEqual(instrumenter.uninstall(), ())
            for plan in planned:
                address = base + plan.rva
                if plan.rva not in report.installed:
                    continue
                self.assertEqual(dbg.read_memory(address, plan.prefix_size),
                                 originals[address],
                                 f"block 0x{plan.rva:X} was not restored")
            self.assertEqual(instrumenter.events(), ())
        finally:
            teardown(dbg)


if __name__ == "__main__":
    unittest.main()
