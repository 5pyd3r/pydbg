"""The pure half of BBL detours: what 5 bytes get displaced and how they move.

A detour overwrites five bytes at a block entry, so those five bytes have to run
somewhere else without changing what they mean. That is a property of *bytes*,
not of a process: everything here takes already-decoded instructions and returns
bytes, and the assertions decode the result again with capstone and ask whether
it still addresses the same memory. No target, no threads, no process memory.

The stub itself is assembled with keystone -- an optional extra -- so the tests
that need it skip with `optional dependency: keystone-engine`; the relocation
tests must pass without it.
"""

import struct
import unittest
from dataclasses import dataclass

try:
    import keystone
except ImportError:                      # pragma: no cover - env decides
    keystone = None

from pydbg.instrument import stub as stub_module
from pydbg.disasm.engine import (
    OP_IMM,
    OP_MEM,
    REG_RIP,
    DisasmEngine,
    Instruction,
    Operand,
)
from pydbg.exceptions import PydbgError
from pydbg.instrument.bbl import (
    RECORD_SIZE,
    STUB_PROLOGUE_SIZE,
    UnsupportedInstruction,
    build_stub,
    prefix_is_relocatable,
    relocate_prefix,
    take_prefix,
)

BLOCK = 0x140001000
# A stub region inside ±2GB of the module, like the real allocator must pick.
STUB = 0x150000000
# Where build_stub's prologue ends, i.e. where the relocated prefix is placed.
PREFIX_AT = STUB + STUB_PROLOGUE_SIZE

BLOCK_RVA = 0x1010
COUNT = 3
RESUME = 0x140001015                    # module base + BLOCK_RVA + 5

# The v1 record, spelled out here rather than imported: `<` inserts no
# alignment padding, so a test that assumed 8-byte-aligned Q fields would
# happily agree with a stub that wrote them in the wrong place.
V1_RECORD = struct.Struct("<B3xIIQQQ")

needs_keystone = unittest.skipUnless(
    keystone is not None, "optional dependency: keystone-engine")

_ENGINES = {}


def decode(data, address=BLOCK):
    """Decode bytes with capstone, through the same wrapper production uses."""
    engine = _ENGINES.get("x64")
    if engine is None:
        engine = _ENGINES["x64"] = DisasmEngine(mode="x64")
    return tuple(engine.disasm(address, data))


def rip_operand(insn):
    """The one RIP-relative memory operand of a decoded instruction."""
    operands = [op for op in insn.operands if op.is_rip_relative]
    if len(operands) != 1:
        raise AssertionError(f"expected one RIP-relative operand, got {operands}")
    return operands[0]


def rip_target(insn):
    """Where a decoded RIP-relative instruction actually points."""
    return insn.address + insn.size + rip_operand(insn).mem_disp


def reg_name(reg_id):
    """capstone's name for a register id, so assertions read like the listing."""
    return _ENGINES["x64"].reg_name(reg_id)


@dataclass(frozen=True)
class Sink:
    """The event-buffer layout EventBuffer (P31) hands to the stub builder."""

    address: int        # slot area
    head_address: int   # u32 slot counter
    capacity: int       # power of two
    slot_size: int      # bytes per slot, the v1 record size


SINK = Sink(address=0x151000000, head_address=0x150FFFFF4,
            capacity=4096, slot_size=RECORD_SIZE)


class TestTakePrefix(unittest.TestCase):

    def test_one_instruction_long_enough_is_the_whole_prefix(self):
        """A 7-byte instruction already covers a 5-byte detour; nothing follows."""
        insns = decode(bytes.fromhex("488b0534120000"))
        self.assertEqual([insn.size for insn in insns], [7])

        prefix = take_prefix(insns, BLOCK)

        self.assertEqual(len(prefix), 1)
        self.assertEqual(prefix[0].mnemonic, "mov")

    def test_short_instructions_accumulate_until_five_bytes(self):
        """push rbp / mov rbp,rsp is 4 bytes: one more instruction is needed."""
        # push rbp; mov rbp, rsp; sub rsp, 0x20
        insns = decode(bytes.fromhex("554889e54883ec20"))

        prefix = take_prefix(insns, BLOCK)

        self.assertEqual([insn.mnemonic for insn in prefix], ["push", "mov", "sub"])
        covered = sum(insn.size for insn in prefix)
        self.assertGreaterEqual(covered, 5)
        # The claim is "the shortest such set", not merely "a long enough set".
        self.assertLess(covered - prefix[-1].size, 5)

    def test_a_block_shorter_than_the_detour_is_refused(self):
        """Two one-byte instructions cannot host a 5-byte JMP."""
        insns = decode(bytes.fromhex("55c3"))     # push rbp; ret

        with self.assertRaises(UnsupportedInstruction) as caught:
            take_prefix(insns, BLOCK)

        self.assertEqual(caught.exception.rva, BLOCK)
        self.assertIn("5", str(caught.exception))

    def test_prefix_must_start_at_the_block_entry(self):
        """Displacing instructions at some other address is not a detour."""
        insns = decode(bytes.fromhex("488b0534120000"), BLOCK + 4)

        with self.assertRaises(UnsupportedInstruction) as caught:
            take_prefix(insns, BLOCK)

        self.assertEqual(caught.exception.rva, BLOCK)

    def test_an_instruction_list_with_a_gap_is_refused(self):
        """Bytes skipped between instructions would be neither moved nor run."""
        first = decode(bytes.fromhex("55"))
        second = decode(bytes.fromhex("4883ec20"), BLOCK + 5)

        with self.assertRaises(UnsupportedInstruction) as caught:
            take_prefix(first + second, BLOCK)

        self.assertEqual(caught.exception.rva, BLOCK + 5)

    def test_an_empty_instruction_list_is_refused(self):
        with self.assertRaises(UnsupportedInstruction) as caught:
            take_prefix((), BLOCK)

        self.assertEqual(caught.exception.rva, BLOCK)
        self.assertIsInstance(caught.exception, PydbgError)


class TestPrefixIsRelocatable(unittest.TestCase):

    # A displaced branch would still be a branch to where it pointed, which is
    # now a different relative distance: the whole prefix must be refused.
    _BRANCHES = {
        "call rel32": "e800000000",
        "jmp rel32": "e900000000",
        "je rel8": "7405",
        "ret": "c3",
        "retf": "cb",
        "iret": "cf",
        "loop": "e2fe",
        "loope": "e1fe",
        "loopne": "e0fe",
        "jrcxz": "e3fe",
        "jmp qword ptr [rip]": "ff2500000000",
        "call rax": "ffd0",
    }

    def test_branches_and_returns_are_not_relocatable(self):
        for name, encoded in self._BRANCHES.items():
            with self.subTest(kind=name):
                self.assertFalse(prefix_is_relocatable(decode(bytes.fromhex(encoded))))

    def test_plain_and_rip_relative_instructions_are_relocatable(self):
        # push rbp; mov rax, [rip+0x1234]; sub rsp, 0x20
        insns = decode(bytes.fromhex("55488b05341200004883ec20"))
        self.assertEqual([insn.mnemonic for insn in insns],
                         ["push", "mov", "sub"])

        self.assertTrue(prefix_is_relocatable(insns))


class TestRelocatePrefix(unittest.TestCase):
    """The displaced bytes must mean the same thing at their new address."""

    def test_a_rip_relative_load_still_reads_the_same_address(self):
        # mov rax, [rip+0x1234] -- target is the end of the instruction plus disp
        insns = decode(bytes.fromhex("488b0534120000"))
        original_target = BLOCK + 7 + 0x1234

        relocated = relocate_prefix(insns, STUB)

        self.assertEqual(len(relocated), 7)
        moved = decode(relocated, PREFIX_AT)
        self.assertEqual(len(moved), 1)
        self.assertEqual(moved[0].mnemonic, "mov")
        self.assertEqual(rip_target(moved[0]), original_target)

    def test_a_rip_relative_store_keeps_its_immediate(self):
        """The disp32 is not the last field when an immediate follows it."""
        # mov dword ptr [rip+0x1234], 1
        insns = decode(bytes.fromhex("c7053412000001000000"))
        original_target = BLOCK + 10 + 0x1234

        relocated = relocate_prefix(insns, STUB)

        self.assertEqual(len(relocated), 10)
        moved = decode(relocated, PREFIX_AT)[0]
        self.assertEqual(rip_target(moved), original_target)
        immediates = [op.imm for op in moved.operands if op.kind == OP_IMM]
        self.assertEqual(immediates, [1])

    def test_a_short_immediate_form_keeps_its_immediate(self):
        """add qword ptr [rip+0x1234], 1 encodes imm8 for an 8-byte operand."""
        insns = decode(bytes.fromhex("4883053412000001"))
        original_target = BLOCK + 8 + 0x1234

        relocated = relocate_prefix(insns, STUB)

        self.assertEqual(len(relocated), 8)
        moved = decode(relocated, PREFIX_AT)[0]
        self.assertEqual(rip_target(moved), original_target)
        self.assertEqual([op.imm for op in moved.operands if op.kind == OP_IMM], [1])

    def test_a_backward_rip_relative_reference_is_rewritten(self):
        """The displacement is signed: -0x1000, not 0xFFFFF000."""
        # mov rax, [rip-0x1000]
        insns = decode(bytes.fromhex("488b0500f0ffff"))
        self.assertEqual(rip_operand(insns[0]).mem_disp, -0x1000)
        original_target = BLOCK + 7 - 0x1000

        moved = decode(relocate_prefix(insns, STUB), PREFIX_AT)[0]

        self.assertEqual(rip_target(moved), original_target)

    def test_bytes_without_a_rip_relative_operand_are_copied_verbatim(self):
        # push rbp; mov rbp, rsp; sub rsp, 0x20
        original = bytes.fromhex("554889e54883ec20")

        self.assertEqual(relocate_prefix(decode(original), STUB), original)

    def test_each_instruction_is_relocated_at_its_own_offset(self):
        # sub rsp, 0x20; mov rax, [rip+0x1234]
        insns = decode(bytes.fromhex("4883ec20488b0534120000"))
        self.assertEqual([insn.size for insn in insns], [4, 7])

        relocated = relocate_prefix(insns, STUB)

        moved = decode(relocated, PREFIX_AT)
        self.assertEqual([insn.size for insn in moved], [4, 7])
        self.assertEqual(moved[0].raw_bytes, bytes.fromhex("4883ec20"))
        self.assertEqual(rip_target(moved[1]), BLOCK + 11 + 0x1234)

    def test_a_branch_in_the_prefix_is_refused(self):
        """rel8/rel32 rewriting is out of scope, so the relocator says no."""
        insns = decode(bytes.fromhex("e800000000"))     # call rel32

        with self.assertRaises(UnsupportedInstruction) as caught:
            relocate_prefix(insns, STUB)

        self.assertEqual(caught.exception.rva, BLOCK)
        self.assertEqual(caught.exception.mnemonic, "call")

    def test_a_displacement_out_of_int32_reach_is_refused(self):
        """A stub more than 2GB away cannot address the old memory at all."""
        insns = decode(bytes.fromhex("488b0534120000"))
        far_stub = 0x7FFF00000000

        with self.assertRaises(UnsupportedInstruction) as caught:
            relocate_prefix(insns, far_stub)

        self.assertEqual(caught.exception.rva, BLOCK)
        self.assertIn("range", caught.exception.reason)

    def test_bytes_that_do_not_match_the_decoded_size_are_refused(self):
        """A hand-built Instruction whose bytes and size disagree is not rewritten."""
        insn = decode(bytes.fromhex("488b0534120000"))[0]
        insn.size = 6

        with self.assertRaises(UnsupportedInstruction) as caught:
            relocate_prefix((insn,), STUB)

        self.assertEqual(caught.exception.rva, BLOCK)

    def test_a_displacement_absent_from_the_bytes_is_refused(self):
        """If the declared disp cannot be located, nothing is guessed."""
        insn = decode(bytes.fromhex("488b0534120000"))[0]
        insn = Instruction(
            address=insn.address, size=insn.size, mnemonic=insn.mnemonic,
            op_str=insn.op_str, raw_bytes=insn.raw_bytes,
            operands=(Operand(kind=OP_MEM, size=8, mem_base=REG_RIP,
                              mem_disp=0x2222),))

        with self.assertRaises(UnsupportedInstruction) as caught:
            relocate_prefix((insn,), STUB)

        self.assertEqual(caught.exception.rva, BLOCK)


class TestRvaDomain(unittest.TestCase):
    """Refusals name RVAs even when the decoder addresses instructions by VA.

    A live `InstructionDecoder` returns instructions addressed at
    `module_base + rva`; `BlockPlan.rva` and the stub's record are RVAs. The
    `address_base` each function takes is how the two spaces stay separated:
    relocation math keeps using the decoder's addresses, the refusal reports
    what the caller planned.
    """

    ADDRESS_BASE = 0x7FF700000000
    RVA = 0x1024

    def va(self, rva=0):
        return self.ADDRESS_BASE + self.RVA + rva

    def test_a_short_block_reports_its_rva(self):
        insns = decode(bytes.fromhex("55c3"), self.va())   # push rbp; ret

        with self.assertRaises(UnsupportedInstruction) as caught:
            take_prefix(insns, self.RVA, address_base=self.ADDRESS_BASE)

        self.assertEqual(caught.exception.rva, self.RVA)
        self.assertNotIn(f"0x{self.va():X}", str(caught.exception),
                         "the refusal leaked the decoder's VA")

    def test_a_prefix_that_starts_elsewhere_reports_the_block_rva(self):
        # The instruction starts at rva 0x1024, but the block was entered at
        # 0x1020: the refusal is about the planned entry, not the instruction.
        insns = decode(bytes.fromhex("488b0534120000"), self.va())

        with self.assertRaises(UnsupportedInstruction) as caught:
            take_prefix(insns, self.RVA - 4, address_base=self.ADDRESS_BASE)

        self.assertEqual(caught.exception.rva, self.RVA - 4)
        self.assertIn("0x1024", str(caught.exception))

    def test_a_gap_reports_the_instruction_rva(self):
        first = decode(bytes.fromhex("55"), self.va())
        second = decode(bytes.fromhex("4883ec20"), self.va(5))

        with self.assertRaises(UnsupportedInstruction) as caught:
            take_prefix(first + second, self.RVA,
                        address_base=self.ADDRESS_BASE)

        self.assertEqual(caught.exception.rva, self.RVA + 5)

    def test_a_branch_refusal_reports_the_instruction_rva(self):
        insns = decode(bytes.fromhex("e800000000"), self.va())

        with self.assertRaises(UnsupportedInstruction) as caught:
            relocate_prefix(insns, STUB, address_base=self.ADDRESS_BASE)

        self.assertEqual(caught.exception.rva, self.RVA)
        self.assertEqual(caught.exception.mnemonic, "call")
        self.assertIn("rva 0x1024", str(caught.exception))
        self.assertNotIn(f"0x{self.va():X}", str(caught.exception))


class TestBuildStubRefusals(unittest.TestCase):
    """What the builder refuses before it assembles anything (keystone-free)."""

    def test_without_keystone_it_says_which_dependency_is_missing(self):
        # The check lives in the module that assembles; `bbl` only re-exports.
        saved = stub_module.keystone
        stub_module.keystone = None
        self.addCleanup(setattr, stub_module, "keystone", saved)

        with self.assertRaises(PydbgError) as caught:
            build_stub(SINK, BLOCK_RVA, COUNT, b"\x90" * 5, RESUME)

        self.assertEqual(str(caught.exception), "keystone-engine not installed")

    def test_record_fields_that_do_not_fit_the_v1_record_are_refused(self):
        cases = {
            "rva above u32": dict(block_rva=1 << 32),
            "negative rva": dict(block_rva=-1),
            "count above the imm32 store": dict(count=1 << 31),
            "negative count": dict(count=-1),
            "resume outside u64": dict(resume=1 << 64),
        }
        for name, change in cases.items():
            arguments = dict(block_rva=BLOCK_RVA, count=COUNT, resume=RESUME)
            arguments.update(change)
            with self.subTest(field=name):
                with self.assertRaises(PydbgError):
                    build_stub(SINK, arguments["block_rva"], arguments["count"],
                               b"\x90" * 5, arguments["resume"])

    def test_a_sink_that_cannot_hold_the_record_is_refused(self):
        """A wrong ring shape would write a record over the next slot's bytes."""
        for name, sink in {
            "capacity zero": Sink(SINK.address, SINK.head_address, 0, 36),
            "capacity not a power of two":
                Sink(SINK.address, SINK.head_address, 1000, 36),
            "slot smaller than the record":
                Sink(SINK.address, SINK.head_address, 1024, 20),
        }.items():
            with self.subTest(sink=name):
                with self.assertRaises(PydbgError):
                    build_stub(sink, BLOCK_RVA, COUNT, b"\x90" * 5, RESUME)


@needs_keystone
class TestBuildStub(unittest.TestCase):
    """The stub's shape, checked by decoding the bytes capstone will execute."""

    def prefix(self):
        # push rbp; mov rbp, rsp; sub rsp, 0x20 -- five bytes or more, no RIP.
        return relocate_prefix(decode(bytes.fromhex("554889e54883ec20")), STUB)

    def stub(self):
        return build_stub(SINK, BLOCK_RVA, COUNT, self.prefix(), RESUME)

    def test_it_is_the_prologue_then_the_prefix_then_a_jump_back(self):
        relocated = self.prefix()
        stub = build_stub(SINK, BLOCK_RVA, COUNT, relocated, RESUME)

        self.assertEqual(len(stub), STUB_PROLOGUE_SIZE + len(relocated) + 14)
        code = stub[:-8]                      # the jump's target is data
        decoded = decode(code, STUB)
        self.assertEqual(sum(insn.size for insn in decoded), len(code))

        tail = decoded[-1]
        self.assertEqual(tail.mnemonic, "jmp")
        self.assertIsNotNone(rip_operand(tail))
        self.assertEqual(struct.unpack("<Q", stub[-8:])[0], RESUME)

    def test_the_relocated_prefix_runs_where_the_relocator_put_it(self):
        """The seam: STUB_PROLOGUE_SIZE is real, not just a number in a test."""
        # mov rax, [rip+0x1234], whose target must survive the move.
        prefix = decode(bytes.fromhex("488b0534120000"))
        relocated = relocate_prefix(prefix, STUB)

        stub = build_stub(SINK, BLOCK_RVA, 1, relocated, RESUME)

        moved = decode(stub[STUB_PROLOGUE_SIZE:], PREFIX_AT)
        self.assertEqual(moved[0].mnemonic, "mov")
        self.assertEqual(rip_target(moved[0]), BLOCK + 7 + 0x1234)

    def test_it_writes_exactly_one_v1_block_record(self):
        """Rebuild the slot the stub writes and unpack it as the v1 reader would.

        The record is written by instructions, not by literal bytes, so the
        stores are decoded and replayed into a 36-byte slot. `<B3xIIQQQ` then
        says what the three qwords mean -- no offsets are assumed here, which is
        how a stub that wrote ts/a/b 4 bytes too far would still be caught.
        """
        self.assertEqual(RECORD_SIZE, 36)
        self.assertEqual(V1_RECORD.size, 36)

        slot = bytearray(RECORD_SIZE)
        for insn in decode(self.stub()[:-8], STUB):
            memories = [op for op in insn.operands if op.kind == OP_MEM]
            immediates = [op for op in insn.operands if op.kind == OP_IMM]
            if len(memories) != 1 or not immediates:
                continue
            if reg_name(memories[0].mem_base) != "rcx":
                continue
            width = memories[0].size
            offset = memories[0].mem_disp
            self.assertGreaterEqual(offset, 0)
            self.assertLessEqual(offset + width, RECORD_SIZE,
                                 "the stub writes past the slot")
            slot[offset:offset + width] = (
                immediates[0].imm & ((1 << (8 * width)) - 1)
            ).to_bytes(width, "little")

        self.assertEqual(V1_RECORD.unpack(bytes(slot)),
                         (1, 0, BLOCK_RVA, 0, COUNT, 0))

    def test_the_slot_comes_from_a_locked_increment_of_the_head_counter(self):
        decoded = decode(self.stub()[:STUB_PROLOGUE_SIZE], STUB)
        # capstone 5 folds the `lock` prefix into the mnemonic ("lock xadd").
        xadds = [insn for insn in decoded
                 if insn.mnemonic.split()[-1] == "xadd"]
        self.assertEqual(len(xadds), 1)
        xadd = xadds[0]

        self.assertEqual(xadd.raw_bytes[0], 0xF0)        # the lock prefix
        memories = [op for op in xadd.operands if op.kind == OP_MEM]
        self.assertEqual([reg_name(op.mem_base) for op in memories], ["r8"])
        self.assertEqual([reg_name(op.reg) for op in xadd.operands
                          if op.kind != OP_MEM], ["eax"])

        # The old count is masked to a power-of-two ring index, then scaled.
        self.assertEqual(len([i for i in decoded if i.mnemonic == "and"]), 1)
        self.assertEqual(len([i for i in decoded if i.mnemonic == "imul"]), 1)

    def test_two_blocks_differ_only_in_the_values_they_write(self):
        """Same sink => same shape; the rva and count stores are the only diff."""
        other_rva, other_count = 0x2000, 7
        other_resume = 0x140002005
        relocated = self.prefix()
        first = build_stub(SINK, BLOCK_RVA, COUNT, relocated, RESUME)
        second = build_stub(SINK, other_rva, other_count, relocated,
                            other_resume)

        self.assertEqual(len(first), len(second))
        decoded_first = decode(first[:-8], STUB)
        decoded_second = decode(second[:-8], STUB)
        self.assertEqual([insn.size for insn in decoded_first],
                         [insn.size for insn in decoded_second])

        changed = [(a, b) for a, b in zip(decoded_first, decoded_second)
                   if a.raw_bytes != b.raw_bytes]
        # Only the record's rva and count stores differ; everything else --
        # prologue, relocated prefix, jump -- is byte-identical.
        self.assertEqual(len(changed), 2)
        values = []
        for left, right in changed:
            left_imm = [op.imm for op in left.operands if op.kind == OP_IMM]
            right_imm = [op.imm for op in right.operands if op.kind == OP_IMM]
            self.assertEqual(len(left_imm), 1)
            values.append((left_imm[0], right_imm[0]))
        self.assertEqual(sorted(values),
                         sorted([(BLOCK_RVA, other_rva), (COUNT, other_count)]))

        self.assertEqual(struct.unpack("<Q", first[-8:])[0], RESUME)
        self.assertEqual(struct.unpack("<Q", second[-8:])[0], other_resume)

    def test_a_high_sink_address_does_not_change_the_shape(self):
        """The absolute-address immediates are always the same ten bytes."""
        low = self.stub()
        prefix = self.prefix()
        high = build_stub(Sink(address=0x7FF6A0000000,
                               head_address=0x7FF69FFFFFF4,
                               capacity=4096, slot_size=RECORD_SIZE),
                          BLOCK_RVA, COUNT, prefix, RESUME)

        self.assertEqual(len(low), len(high))
        self.assertEqual(len(high), STUB_PROLOGUE_SIZE + len(prefix) + 14)


if __name__ == "__main__":
    unittest.main()
