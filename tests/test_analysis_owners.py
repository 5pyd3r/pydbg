"""Tests for ownership — the bounded queries over the decode.

What is under test is not "can pydbg find a function". It is whether an answer
that used to be produced by a heuristic at the call site can now be produced by
something that says which of several findings it is: an address past everything
the analysis claimed is not the same as one inside a function, and neither is
the same as one outside the image. Every test here fails when the answer
collapses back to a bare None or to the nearest preceding start.

The fixture is the shape this was built for, reproduced end to end: a jump
table embedded in .text whose scan produces an instruction that straddles the
table's last byte, so the byte after the table is decoded as the tail of a
displacement and never becomes a boundary of its own.
"""

import unittest

from tests.pe_builder import PEBuilder

IMAGE_BASE = 0x400000
TEXT_RVA = 0x1000
# The entry is not at the section's first byte, so that .text has a mapped
# region *before* the first function start — otherwise "before the first
# start" and "outside the image" are the same address and the two findings
# cannot be told apart in a test.
ENTRY_RVA = TEXT_RVA + 0x10
TABLE_RVA = 0x1040
TABLE_COUNT = 6
TABLE_STRIDE = 4
TABLE_END = TABLE_RVA + TABLE_COUNT * TABLE_STRIDE          # 0x1058
# A non-executable section past everything the analysis will claim. Addresses
# here are mapped (so not "unmapped") and owned by nothing (so "after"), and
# its bytes will not decode (so "never_decoded" with a reason of its own).
DATA_RVA = 0x2000
UNDECODABLE = b"\xff" * 0x100

# A second function, reached by a call from the first. Without it there is one
# start and every address past its extent is "after" — "gap" needs a following
# start for the span to end at, so the kind would have no producer here.
SECOND_RVA = 0x1080
# The instruction that names the table. `jmp dword ptr [eax*4 + 0x401040]` —
# the displacement is an absolute VA, which is what makes it a TABLE reference.
SWITCH_JMP = b"\xff\x24\x85" + (IMAGE_BASE + TABLE_RVA).to_bytes(4, "little")
# `call 0x1080` — the only reason a second start exists.
CALL_SECOND = b"\xe8" + (SECOND_RVA - (ENTRY_RVA + 5)).to_bytes(4, "little")
# The entry function ends at the ret. The sweep stops here, which is what
# leaves the table for an explicit scan to reach — the same division of labour
# the real analysis had, where the table's bytes were decoded by a scan and not
# by the descent.
ENTRY_BODY = CALL_SECOND + SWITCH_JMP + b"\xc3"

# The bytes after the table. `55` is what the straddling instruction swallows:
# `push ebp; mov ebp, esp; sub esp, 0x10; ret`.
AFTER_TABLE = (TABLE_END, b"\x55\x8b\xec\x83\xec\x10\xc3")
# `xor eax, eax; ret`.
SECOND_BODY = b"\x31\xc0\xc3"

NOP = b"\x90"


def _pointer(rva):
    return (IMAGE_BASE + rva).to_bytes(4, "little")


def build_image(table_values, after=AFTER_TABLE):
    """Entry function, a jump table, a second function, and a non-exec section."""
    code = bytearray(NOP * (ENTRY_RVA - TEXT_RVA))
    code += ENTRY_BODY
    code += NOP * (TABLE_RVA - TEXT_RVA - len(code))
    assert len(code) == TABLE_RVA - TEXT_RVA, len(code)
    for value in table_values:
        code += _pointer(value)
    after_rva, after_bytes = after
    assert TEXT_RVA + len(code) == after_rva, hex(TEXT_RVA + len(code))
    code += after_bytes
    code += NOP * (SECOND_RVA - TEXT_RVA - len(code))
    assert len(code) == SECOND_RVA - TEXT_RVA, len(code)
    code += SECOND_BODY
    builder = PEBuilder(magic=0x10B, image_base=IMAGE_BASE,
                        entry_rva=ENTRY_RVA)
    builder.add_section(".text", bytes(code), TEXT_RVA)
    builder.add_section(".rdata", UNDECODABLE, DATA_RVA,
                        characteristics=0x40000040)
    return builder.build()


def analyze(table_values=None, after=AFTER_TABLE):
    from pydbg.analysis import analyze_bytes
    values = table_values if table_values is not None else default_table()
    return analyze_bytes(build_image(values, after=after))


def default_table():
    """Five entries to a round RVA, one whose low byte is 0x3D.

    The low byte is load-bearing, and this is the recipe the real image
    followed: the straddling instruction is `00 3D <disp32>`, so the final
    entry's first byte has to be 0x3D for the walk to reach it. A table of
    arbitrary pointers does not reproduce the shape — the walk lands on a slot
    boundary and every byte after the table is a boundary again.
    """
    return [TEXT_RVA + 0x10] * (TABLE_COUNT - 1) + [TEXT_RVA + 0x3D]


class TestTheFixture(unittest.TestCase):
    """The control the rest of the file depends on.

    If the straddling instruction stops being produced — a changed target RVA,
    a capstone update — then every assertion about it below would still pass
    while testing nothing, because `instruction_interior` is also the answer
    for an ordinary mid-instruction byte. So the fixture asserts its own shape
    rather than assuming it.
    """

    def test_the_scan_straddles_the_table_end(self):
        result = analyze()
        result.scan(TABLE_RVA, TABLE_END + 8)
        covering = result.decoder.enclosing_instruction(TABLE_END)
        self.assertIsNotNone(covering, "nothing covers the byte after the table")
        self.assertLess(covering, TABLE_END,
                        "the covering instruction does not start inside the "
                        "table, so this fixture is not the shape under test")
        self.assertGreater(covering + result.decoder.size_of(covering),
                           TABLE_END,
                           "the covering instruction does not cross the end")

    def test_the_byte_is_covered_but_is_not_a_start(self):
        """The control a naive boundary_of dies on.

        `is_decoded` is false at TABLE_END — no instruction *starts* there —
        and an implementation that stops at that test reports `never_decoded`.
        The whole point is that something covers it: the walk-back is what
        separates "not a boundary" from "not decoded", and those are different
        findings about the same byte.
        """
        result = analyze()
        result.scan(TABLE_RVA, TABLE_END + 8)
        self.assertFalse(result.decoder.is_decoded(TABLE_END))
        self.assertIsNotNone(result.decoder.enclosing_instruction(TABLE_END))
        found = result.boundary_of(TABLE_END)
        self.assertEqual(found.kind, "instruction_interior")
        self.assertEqual(found.offset, TABLE_END - found.start)


class TestBoundaryOf(unittest.TestCase):
    """Which of three findings an address gets, including the two controls."""

    def setUp(self):
        self.result = analyze()

    def test_an_instruction_start_says_so(self):
        """The positive control. Without it every interior assertion below
        would also pass on a boundary_of that never reports a start."""
        edge = self.result.boundary_of(ENTRY_RVA)
        self.assertEqual(edge.kind, "instruction_start")
        self.assertEqual(edge.offset, 0)
        self.assertEqual(edge.start, ENTRY_RVA)
        self.assertEqual(edge.size, len(CALL_SECOND))

    def test_a_byte_inside_an_instruction_is_interior(self):
        """The control that a broken walk-back kills."""
        found = self.result.boundary_of(ENTRY_RVA + 1)
        self.assertEqual(found.kind, "instruction_interior")
        self.assertEqual(found.start, ENTRY_RVA)
        self.assertEqual(found.offset, 1)

    def test_unmapped_and_undecoded_are_different_reasons(self):
        """Two causes, two strings — and neither is invented in this module."""
        outside = self.result.boundary_of(IMAGE_BASE)
        self.assertEqual(outside.kind, "never_decoded")
        self.assertEqual(outside.reason, "not in any mapped section")

        # 0xff with modrm 0xff selects no instruction (group 5, /7). Mapped,
        # and it does not decode — a different finding from "not mapped at
        # all", which is why the reason travels rather than being a boolean.
        self.assertIsNone(self.result.decoder.decode_one(DATA_RVA))
        inside = self.result.boundary_of(DATA_RVA)
        self.assertEqual(inside.kind, "never_decoded")
        self.assertIsNotNone(inside.reason)
        self.assertNotEqual(inside.reason, outside.reason)

    def test_a_mapped_address_nobody_tried_has_no_reason(self):
        """The third cause: never attempted is not the same as failed."""
        found = self.result.boundary_of(TEXT_RVA + 4)
        self.assertEqual(found.kind, "never_decoded")
        self.assertIsNone(found.reason)

    def test_boundary_names_the_owning_function(self):
        found = self.result.boundary_of(ENTRY_RVA)
        self.assertEqual(found.owner, ENTRY_RVA)
        self.assertIn(found.owner_kind, ("start", "body"))


class TestOwnerOf(unittest.TestCase):
    """The bounded query, against the unbounded one it replaces."""

    def setUp(self):
        self.result = analyze()

    def test_a_start_and_a_body(self):
        self.assertEqual(self.result.functions.owner_of(ENTRY_RVA),
                         (ENTRY_RVA, "start"))
        _, kind = self.result.functions.owner_of(ENTRY_RVA + 2)
        self.assertEqual(kind, "body")

    def test_past_the_last_function_is_after_not_the_last_function(self):
        """The defect this query exists to fix, pinned with its contrast.

        `containing` is unbounded on purpose and still answers with the last
        start no matter how far past it the address is. The two answers are
        asserted in the same test so the difference is a fact in the suite
        rather than a comment in the source.
        """
        tail = DATA_RVA
        self.assertEqual(self.result.functions.owner_of(tail), (None, "after"))
        self.assertIsNotNone(self.result.functions.containing(tail),
                             "containing is expected to stay unbounded")
        self.assertIsNone(self.result.function_of(tail))

    def test_outside_the_image_is_unmapped_not_after(self):
        """Two ways of having no owner, and they are different findings."""
        self.assertEqual(self.result.functions.owner_of(IMAGE_BASE),
                         (None, "unmapped"))
        self.assertEqual(self.result.functions.owner_of(TEXT_RVA + 4),
                         (None, "before"))

    def test_function_of_agrees_with_owner_of_everywhere(self):
        """No address is owned by a function the public query disowns."""
        for rva in range(TEXT_RVA, TABLE_END):
            owner, kind = self.result.functions.owner_of(rva)
            self.assertEqual(self.result.function_of(rva), owner, hex(rva))
            self.assertEqual(kind in ("start", "body", "gap"),
                             owner is not None, hex(rva))


class TestSlotTables(unittest.TestCase):
    """A table is an object, not a pile of data references."""

    def setUp(self):
        self.result = analyze()

    def test_the_switch_instruction_yields_one_table(self):
        self.assertEqual(len(self.result.slot_tables), 1)
        table = self.result.slot_tables[0]
        self.assertEqual(table.base, TABLE_RVA)
        self.assertEqual(table.count, TABLE_COUNT)
        self.assertEqual(table.stride, TABLE_STRIDE)
        self.assertEqual(table.kind, "jump_table")
        self.assertEqual(table.referrer, ENTRY_RVA + len(CALL_SECOND))
        self.assertFalse(table.truncated)

    def test_an_aligned_slot_reports_its_index(self):
        table, index = self.result.container_of(TABLE_RVA + 2 * TABLE_STRIDE)
        self.assertEqual((table.base, index), (TABLE_RVA, 2))

    def test_an_unaligned_byte_names_the_table_without_inventing_an_index(self):
        """The byte the feature exists for is mid-slot, and still nameable.

        Withholding the whole answer here — the stricter reading — would make
        the table unavailable for exactly the address that motivated the
        query, since a pseudo-instruction decoded out of a table starts where
        the walk happens to land rather than on a slot boundary.
        """
        table, index = self.result.container_of(TABLE_RVA + 3)
        self.assertEqual(table.base, TABLE_RVA)
        self.assertIsNone(index)

    def test_an_address_outside_every_table_has_no_container(self):
        self.assertIsNone(self.result.container_of(ENTRY_RVA))

    def test_every_table_kind_is_declared_and_only_one_is_produced(self):
        """The bite test, stated as a denominator rather than as a shape.

        A run of code pointers is not a jump table, and the kinds must not be
        merged by shape. `pointer_run` is therefore declared with **no
        producer**, and that is asserted here as a current fact rather than
        left for a reader to discover — a declared kind that silently acquires
        the other's meaning is how two different claims start sharing a name.
        """
        from pydbg.analysis.model import SLOT_TABLE_KINDS
        result = analyze()
        produced = {table.kind for table in result.slot_tables}
        self.assertEqual(produced, {"jump_table"})
        self.assertTrue(produced <= set(SLOT_TABLE_KINDS))
        self.assertEqual(set(SLOT_TABLE_KINDS) - produced, {"pointer_run"},
                         "pointer_run gained a producer; this test and the "
                         "docstring on SLOT_TABLE_KINDS both need updating")

    def test_every_table_names_the_instruction_that_revealed_it(self):
        result = analyze()
        self.assertTrue(result.slot_tables)
        for table in result.slot_tables:
            self.assertIsNotNone(table.referrer)


class TestTheStraddledByte(unittest.TestCase):
    """The shape from the real image, asserted all at once.

    A scan that decodes the table's bytes as instructions reports near-total
    coverage while losing the boundary at TABLE_END. Three claims together are
    what make the loss visible: the coverage figure still looks like success,
    the byte is decoded, and the instruction decoding it belongs to the table.
    """

    def setUp(self):
        self.result = analyze()
        self.scan = self.result.scan(TABLE_RVA, TABLE_END + 8)

    def test_coverage_looks_like_success(self):
        """The figure that made this shape invisible, kept as a claim.

        A scan over the table's own bytes reports essentially complete
        coverage of them — which is true, and is why nothing looked wrong.
        """
        self.assertEqual(self.scan.coverage_percent(), 100.0)
        self.assertTrue(self.scan.is_complete())

    def test_the_byte_after_the_table_is_instruction_interior(self):
        found = self.result.boundary_of(TABLE_END)
        self.assertEqual(found.kind, "instruction_interior")
        self.assertLess(found.start, TABLE_END)
        self.assertGreaterEqual(found.start + found.size, TABLE_END)

    def test_that_instruction_is_attributed_to_the_table(self):
        found = self.result.boundary_of(TABLE_END)
        container = self.result.container_of(found.start)
        self.assertIsNotNone(container)
        self.assertEqual(container[0].base, TABLE_RVA)

    def test_ownership_does_not_call_it_a_function_start(self):
        """The other half of the cost: a slot value is not an entry point."""
        found = self.result.boundary_of(TABLE_END)
        self.assertNotEqual(found.owner_kind, "start")
        self.assertNotIn(found.start, self.result.functions.starts)


class TestClassifyRange(unittest.TestCase):
    """The denominator behind any ownership claim."""

    def setUp(self):
        self.result = analyze()

    def test_a_range_of_real_code_is_fully_owned(self):
        end = ENTRY_RVA + len(CALL_SECOND) + len(SWITCH_JMP)
        report = self.result.classify_range(ENTRY_RVA, end)
        self.assertTrue(report.is_fully_owned(), report.render())
        self.assertEqual(report.instruction_starts, 2)
        self.assertEqual(report.unowned_after, 0)
        self.assertFalse(report.truncated)

    def test_the_unowned_tail_has_a_size(self):
        """`after` is a count, not an absence — that is the whole point."""
        report = self.result.classify_range(DATA_RVA, DATA_RVA + 0x100)
        self.assertEqual(report.bytes_by_kind["after"], 0x100)
        self.assertFalse(report.is_fully_owned())

    def test_a_truncated_range_never_claims_full_ownership(self):
        report = self.result.classify_range(ENTRY_RVA, ENTRY_RVA + 0x2000,
                                            limit=16)
        self.assertTrue(report.truncated)
        self.assertFalse(report.is_fully_owned())


class TestReceiverOf(unittest.TestCase):
    """Where a base register came from, and where the walk gave up."""

    def _analyze(self, body, at=0x1040):
        """An image whose entry function runs 'body' then pads out and returns."""
        code = bytearray(body)
        code += b"\x90" * (at - ENTRY_RVA - len(code))
        code += b"\x55\x8b\xec\xc3"
        builder = PEBuilder(magic=0x10B, image_base=IMAGE_BASE,
                            entry_rva=ENTRY_RVA)
        builder.add_section(".text", bytes(code), ENTRY_RVA)
        from pydbg.analysis import analyze_bytes
        return analyze_bytes(builder.build())

    # Each body ends with `mov eax, [ecx+0x3D]`, which is the access whose base
    # register is being asked about. The site is the `mov`'s own RVA.
    CASES = {
        # name: (body, offset of the access)
        "constant": (b"\xb9" + (IMAGE_BASE + 0x1000).to_bytes(4, "little")
                     + b"\x8b\x41\x3d", 5),
        "loaded_from_slot": (b"\x8b\x4e\x18" + b"\x8b\x41\x3d", 3),
        "loaded_from_stack": (b"\x8b\x4d\xfc" + b"\x8b\x41\x3d", 3),
        "branch": (b"\xb9" + (IMAGE_BASE + 0x1000).to_bytes(4, "little")
                   + b"\x75\x02" + b"\x8b\x41\x3d", 7),
        "read_modify_write": (b"\xba" + (IMAGE_BASE + 0x1000).to_bytes(4, "little")
                              + b"\x03\xca" + b"\x8b\x41\x3d", 7),
    }

    def _note(self, name):
        from pydbg.analysis import receiver_of
        body, offset = self.CASES[name]
        return receiver_of(self._analyze(body), ENTRY_RVA + offset)

    def test_a_register_loaded_from_a_constant(self):
        note = self._note("constant")
        self.assertEqual(note.base_reg, "ecx")
        self.assertEqual(note.fact, "constant")
        self.assertTrue(note.determined)
        self.assertIsNone(note.stopped_at)

    def test_a_register_loaded_from_a_slot(self):
        note = self._note("loaded_from_slot")
        self.assertEqual(note.base_reg, "ecx")
        self.assertEqual(note.fact, "loaded_from_slot")
        self.assertEqual(note.source_rva, ENTRY_RVA)
        self.assertTrue(note.determined)

    def test_a_register_from_the_stack_is_not_a_slot(self):
        note = self._note("loaded_from_stack")
        self.assertEqual(note.fact, "loaded_from_stack")
        self.assertNotEqual(note.fact, "loaded_from_slot")

    def test_control_flow_makes_the_walk_refuse(self):
        """Same shape, one branch: the answer must not survive it.

        Without this the linear walk would attribute a value established on
        one path to an access on another, which is the failure mode a
        hand-written discriminator has and reports just as confidently.
        """
        note = self._note("branch")
        self.assertEqual(note.fact, "unknown")
        self.assertFalse(note.determined)
        self.assertIsNotNone(note.stopped_at)

    def test_a_read_modify_write_does_not_inherit_its_source(self):
        """`add ecx, edx` is not `mov ecx, edx`; the bite test for the walk."""
        note = self._note("read_modify_write")
        self.assertEqual(note.fact, "unknown")
        self.assertFalse(note.determined)
        self.assertIsNotNone(note.stopped_at)

    def test_every_fact_is_a_declared_one_and_they_differ(self):
        """No caller can receive a class name dressed as a provenance fact."""
        from pydbg.analysis import DETERMINED_FACTS, RECEIVER_FACTS
        seen = {}
        for name in self.CASES:
            note = self._note(name)
            self.assertIsNotNone(note, name)
            self.assertIn(note.fact, RECEIVER_FACTS, name)
            seen[name] = note.fact
        self.assertEqual(seen["constant"], "constant")
        self.assertEqual(seen["loaded_from_slot"], "loaded_from_slot")
        self.assertNotEqual(seen["loaded_from_slot"], seen["constant"])
        self.assertEqual(seen["branch"], "unknown")
        self.assertEqual(seen["read_modify_write"], "unknown")
        # Same fact, different reason: the two refusals are not one finding.
        self.assertNotEqual(self._note("branch").stopped_at,
                            self._note("read_modify_write").stopped_at)
        self.assertTrue(DETERMINED_FACTS <= set(RECEIVER_FACTS))
        self.assertNotIn("unknown", DETERMINED_FACTS)
        self.assertNotIn("moved_from_register", DETERMINED_FACTS)

    def test_the_walk_records_what_it_looked_at(self):
        """The audit trail a hand-written discriminator does not have."""
        note = self._note("loaded_from_slot")
        self.assertEqual(note.evidencing, (ENTRY_RVA,))

    def test_there_is_no_class_of(self):
        """The refusal is the design, so its absence is asserted."""
        import pydbg.analysis as analysis
        import pydbg.analysis.owners as owners
        for module in (analysis, owners):
            self.assertFalse(hasattr(module, "class_of"))


class TestTheDeclaredKindsHaveProducers(unittest.TestCase):
    """A kind that is declared and never produced is a missing answer class."""

    def test_owner_kinds_and_owned_set_agree(self):
        """The duplicated constant in model.py cannot drift."""
        from pydbg.analysis import OWNER_KINDS
        from pydbg.analysis.functions import _OWNED
        from pydbg.analysis.model import _OWNED_KINDS
        self.assertEqual(set(_OWNED), set(_OWNED_KINDS))
        self.assertTrue(_OWNED <= set(OWNER_KINDS))

    def test_the_fixture_produces_every_owner_kind(self):
        result = analyze()
        seen = {result.functions.owner_of(rva)[1]
                for rva in range(TEXT_RVA, TABLE_END + 8)}
        seen.add(result.functions.owner_of(DATA_RVA)[1])       # after
        seen.add(result.functions.owner_of(TEXT_RVA + 4)[1])   # before
        seen.add(result.functions.owner_of(IMAGE_BASE)[1])     # unmapped
        from pydbg.analysis import OWNER_KINDS
        self.assertEqual(seen, set(OWNER_KINDS))

    def test_the_fixture_produces_every_boundary_kind(self):
        result = analyze()
        result.scan(TABLE_RVA, TABLE_END + 8)
        seen = {result.boundary_of(rva).kind
                for rva in range(TEXT_RVA, TABLE_END + 8)}
        seen.add(result.boundary_of(IMAGE_BASE).kind)
        seen.add(result.boundary_of(DATA_RVA).kind)
        from pydbg.analysis import BOUNDARY_KINDS
        self.assertEqual(seen, set(BOUNDARY_KINDS))


if __name__ == "__main__":
    unittest.main()
