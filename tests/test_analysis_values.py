"""Tests for value sets — the lattice, and what its refusals must not become.

What is under test is not "can pydbg compute a value set". It is whether the
answers that carry no information can be told apart from the answers that do.
The hand-written analysis this replaces was wrong twice, both times invisibly:
one version read an immediate through the wrong operand-kind constant, the
other reported `UNBOUNDED` for a set it had not worked out. Neither failed
loudly, so the tests here are written as separations — `NONE` is not
`UNMODELED`, `UNMODELED` is not `UNBOUNDED`, and a union that has no single
form says so instead of picking one.
"""

import unittest

from tests.pe_builder import PEBuilder

IMAGE_BASE = 0x400000
TEXT_RVA = 0x1000
DATA_RVA = 0x2000
ADDR = DATA_RVA

RET = b"\xc3"
NOP = b"\x90"


def _store_imm(value):
    """`mov dword ptr [ADDR], value` — an absolute store, 10 bytes."""
    return b"\xc7\x05" + (IMAGE_BASE + ADDR).to_bytes(4, "little") + \
        value.to_bytes(4, "little")


def _store_reg():
    """`mov dword ptr [ADDR], eax` — 6 bytes; the source is not determined."""
    return b"\x89\x05" + (IMAGE_BASE + ADDR).to_bytes(4, "little")


def _add_imm(value=1):
    """`add dword ptr [ADDR], value` — a read-modify-write, 7 bytes."""
    return b"\x83\x05" + (IMAGE_BASE + ADDR).to_bytes(4, "little") + \
        bytes((value,))


def _cmp_imm(value):
    """`cmp dword ptr [ADDR], value` — 7 bytes."""
    return b"\x83\x3d" + (IMAGE_BASE + ADDR).to_bytes(4, "little") + \
        bytes((value,))


def build(body, entry_rva=TEXT_RVA):
    builder = PEBuilder(magic=0x10B, image_base=IMAGE_BASE,
                        entry_rva=entry_rva)
    code = bytes(body) + RET
    builder.add_section(".text", code, TEXT_RVA)
    builder.add_section(".data", b"\x00" * 0x100, DATA_RVA,
                        characteristics=0xC0000040)
    return builder.build()


def analyze(body):
    from pydbg.analysis import analyze_bytes
    return analyze_bytes(build(body))


class TestTheFixture(unittest.TestCase):
    """The control the store encodings rest on.

    Every writer assertion below names an RVA and a value read out of these
    bytes. If an encoding drifts — a wrong opcode, a displacement written in
    the wrong endianness — the stores would land somewhere else and the tests
    would report "no writer found", which is also what a broken scan reports.
    So the fixture checks that the decoded operand resolves to the address it
    was built for, rather than trusting the byte strings.
    """

    def test_the_store_resolves_to_the_intended_address(self):
        from pydbg.analysis.refs import memory_address
        result = analyze(_store_imm(1))
        insn = result.decoder.decode_one(TEXT_RVA)
        self.assertIsNotNone(insn)
        self.assertEqual(insn.mnemonic, "mov")
        resolved = [memory_address(insn, op, result.image)
                    for op in insn.operands if op.kind == 3]
        self.assertIn(ADDR, resolved)

    def test_the_fixture_has_a_section_covering_the_address(self):
        result = analyze(_store_imm(1))
        self.assertTrue(result.image.is_mapped(ADDR))
        self.assertIsNotNone(result.image.section_of(ADDR))


def _kinds_from_analysis():
    """Every Bound the analysis itself produces, across the fixtures."""
    from pydbg.analysis import value_set_of
    bodies = [
        _store_imm(1) + _store_imm(3),                                # SET
        _store_imm(1) + _store_imm(3) + _cmp_imm(0x29) + b"\x77\x02",  # RANGE
        _store_imm(1) + _store_reg(),                                 # UNMODELED
        _add_imm(1),                                                  # UNMODELED
        b"\xff\xd6",                                                  # call esi
    ]
    from pydbg.analysis import ValueSet, narrow_by_guards
    kinds = {value_set_of(analyze(body), ADDR).kind for body in bodies}
    # A guard drops excluded values from a SET, so the three forms above are
    # what an image alone produces. RANGE needs a range to intersect with,
    # which is a caller's input — see TestGuardNarrowing.
    kinds.add(narrow_by_guards(analyze(bodies[1]), ADDR,
                               base=ValueSet.of_range(0, 0xFF)).kind)
    # An address nothing writes: the fourth decided form, and the one a
    # "no writer" implementation would report for every fixture above.
    kinds.add(value_set_of(analyze(_store_imm(1)), DATA_RVA + 0x80).kind)
    return kinds


def _set_of(result, **kwargs):
    from pydbg.analysis import value_set_of
    return value_set_of(result, ADDR, **kwargs)


class TestTheLattice(unittest.TestCase):
    """The laws, each pinned, including the two the defects broke."""

    def setUp(self):
        from pydbg.analysis import Bound, ValueSet
        self.Bound = Bound
        self.ValueSet = ValueSet

    def test_none_is_bottom(self):
        one = self.ValueSet.of_value(1, 0x10)
        self.assertEqual(self.ValueSet().widen(one), one)
        self.assertEqual(one.widen(self.ValueSet()), one)

    def test_two_sets_union(self):
        joined = self.ValueSet.of_value(1, 0x10).widen(
            self.ValueSet.of_value(3, 0x20))
        self.assertEqual(joined.kind, self.Bound.SET)
        self.assertEqual(joined.values, frozenset((1, 3)))

    def test_a_set_inside_a_range_collapses_to_the_range(self):
        joined = self.ValueSet.of_value(7, 0x10).widen(
            self.ValueSet.of_range(5, 9))
        self.assertEqual(joined.kind, self.Bound.RANGE)
        self.assertEqual((joined.lo, joined.hi), (5, 9))

    def test_a_set_outside_a_range_is_not_forced_into_one(self):
        """The third form, which is why UNREPRESENTABLE exists.

        Every writer here was modelled, and the union is still not one
        interval. Reporting UNMODELED would claim a writer was missed;
        reporting UNBOUNDED is the defect this replaces.
        """
        joined = self.ValueSet.of_value(1, 0x10).widen(
            self.ValueSet.of_range(5, 9))
        self.assertEqual(joined.kind, self.Bound.UNREPRESENTABLE)
        self.assertEqual(len(joined.parts), 2)
        self.assertNotIn(joined.kind, (self.Bound.UNMODELED,
                                       self.Bound.UNBOUNDED))

    def test_an_unmodelled_writer_survives_the_join_and_accumulates(self):
        """The second defect, as an executable test.

        A union of "I know 1" with "I do not know" is not "unbounded": the
        first list is evidence and the second is a gap, and the answer has to
        carry both. Collapse the unmodelled side into UNBOUNDED and this goes
        red — which is the point of writing it down.
        """
        known = self.ValueSet.of_value(1, 0x10)
        gap = self.ValueSet.of_unmodeled([(0x20, "not modelled")])
        joined = known.widen(gap)
        self.assertEqual(joined.kind, self.Bound.UNMODELED)
        self.assertEqual(joined.writers_modeled(), 1)
        self.assertEqual(joined.writers_total(), 2)
        self.assertNotEqual(joined.kind, self.Bound.UNBOUNDED)

        again = joined.widen(self.ValueSet.of_unmodeled([(0x30, "also not")]))
        self.assertEqual(len(again.unmodeled), 2)
        self.assertEqual(again.writers_modeled(), 1)

    def test_unbounded_cannot_be_reached_by_giving_up(self):
        """The only constructor demands writers and a reason."""
        with self.assertRaises(ValueError):
            self.ValueSet.unbounded(reason=None, writers=((0x10, "x"),))
        with self.assertRaises(ValueError):
            self.ValueSet.unbounded(reason="because", writers=())
        self.assertEqual(
            self.ValueSet.unbounded("every writer admits any value",
                                    ((0x10, "x"),)).kind,
            self.Bound.UNBOUNDED)


class TestKindsAreSeparable(unittest.TestCase):
    """The separations stated as value inequalities, not as prose."""

    def setUp(self):
        from pydbg.analysis import ValueSet
        self.ValueSet = ValueSet

    def test_none_and_unmodeled_are_different_things(self):
        """"Nothing writes it" and "I could not see the writers" differ."""
        from pydbg.analysis import Bound
        none = self.ValueSet(kind=Bound.NONE)
        unmodeled = self.ValueSet.of_unmodeled([(0x10, "gap")])
        self.assertNotEqual(none.kind, unmodeled.kind)
        self.assertNotEqual(none, unmodeled)
        self.assertNotEqual(none.render(), unmodeled.render())
        # Both are "could be anything" to a caller asking whether it is
        # possible, which is exactly why may_contain must not be used for
        # claims that something is impossible.
        # The separation runs the opposite way to the naive reading: `NONE`
        # can say no — it decided that nothing writes the address — while
        # `UNMODELED` cannot say anything at all.
        self.assertFalse(none.may_contain(0))
        self.assertTrue(unmodeled.may_contain(0))
        self.assertTrue(none.is_decided())
        self.assertFalse(unmodeled.is_decided())

    def test_contains_refuses_where_may_contain_answers(self):
        unmodeled = self.ValueSet.of_unmodeled([(0x10, "gap")])
        with self.assertRaises(ValueError):
            unmodeled.contains(0)
        self.assertTrue(unmodeled.may_contain(0))

    def test_a_decided_empty_set_is_still_a_decision(self):
        from pydbg.analysis import Bound
        none = self.ValueSet(kind=Bound.NONE)
        self.assertTrue(none.is_decided())
        self.assertFalse(none.contains(1))
        self.assertFalse(none.may_contain(1))


class TestWritesTo(unittest.TestCase):
    """The scan, against fixtures whose writer RVAs are hand-counted."""

    def test_two_immediates_give_exactly_those_values(self):
        """The test that dies when the immediate is read through a wrong
        operand-kind constant: the set comes out plausible and different."""
        result = analyze(_store_imm(1) + _store_imm(3))
        value = _set_of(result)
        self.assertEqual(value.kind.name, "SET")
        self.assertEqual(value.values, frozenset((1, 3)))
        self.assertTrue(value.is_decided())
        self.assertTrue(value.contains(1))
        self.assertFalse(value.contains(2))
        self.assertEqual([rva for rva, _ in value.writers],
                         [TEXT_RVA, TEXT_RVA + 10])
        self.assertEqual(value.unmodeled, ())

    def test_an_address_nobody_writes_is_none_not_unmodeled(self):
        result = analyze(_store_imm(1))
        from pydbg.analysis import value_set_of
        value = value_set_of(result, DATA_RVA + 0x80)
        self.assertEqual(value.kind.name, "NONE")
        self.assertTrue(value.is_decided())
        self.assertEqual(value.values, frozenset())
        self.assertEqual(value.writers_total(), 0)

    def test_an_undetermined_source_keeps_the_writer_it_did_model(self):
        """The second defect's shape: a gap must not swallow the evidence."""
        result = analyze(_store_imm(1) + _store_reg())
        value = _set_of(result)
        self.assertEqual(value.kind.name, "UNMODELED")
        self.assertFalse(value.is_decided())
        self.assertNotEqual(value.kind.name, "UNBOUNDED")
        with self.assertRaises(ValueError):
            value.contains(0)
        self.assertEqual(value.writers_modeled(), 1)
        self.assertEqual(value.writers_total(), 2)
        self.assertEqual([rva for rva, _ in value.unmodeled],
                         [TEXT_RVA + 10])
        self.assertIn("register", value.unmodeled[0][1])

    def test_a_read_modify_write_is_not_its_operand(self):
        """`add [addr], 1` does not make the value 1; the bite test."""
        result = analyze(_add_imm(1))
        value = _set_of(result)
        self.assertEqual(value.kind.name, "UNMODELED")
        self.assertNotEqual(value.values, frozenset((1,)))
        self.assertEqual(value.writers_modeled(), 0)

    def test_an_address_written_only_by_an_unresolved_call(self):
        """The boundary shape: an implementation counting only the writers it
        modelled would report a confident NONE here."""
        result = analyze(b"\xff\xd6")            # call esi
        value = _set_of(result)
        self.assertEqual(value.kind.name, "UNMODELED")
        self.assertEqual(value.writers_modeled(), 0)
        self.assertGreaterEqual(value.writers_total(), 1)

    def test_calls_can_be_left_out_only_by_asking(self):
        result = analyze(_store_imm(1) + b"\xff\xd6")
        with_calls = _set_of(result)
        without = _set_of(result, include_unresolved_calls=False)
        self.assertEqual(with_calls.kind.name, "UNMODELED")
        self.assertEqual(without.kind.name, "SET")
        self.assertEqual(without.values, frozenset((1,)))


class TestGuardNarrowing(unittest.TestCase):
    """`RANGE` needs a producer, and this is it."""

    def test_a_guard_drops_the_values_it_excludes(self):
        body = _store_imm(0) + _store_imm(0x40) + _cmp_imm(0x29) + b"\x77\x02"
        result = analyze(body)
        from pydbg.analysis import narrow_by_guards
        narrowed = narrow_by_guards(result, ADDR)
        self.assertEqual(narrowed.kind.name, "SET")
        self.assertEqual(narrowed.values, frozenset((0,)))
        self.assertTrue(narrowed.contains(0))
        self.assertFalse(narrowed.contains(0x40))

    def test_a_guard_over_a_range_intersects_rather_than_unions(self):
        """The direction that matters: narrowing must not widen.

        Joining the constrained range back with the unconstrained writers
        would report values the guard forbids — an analysis reporting more
        than the code can hold, which reads as a richer answer rather than as
        a bug.
        """
        from pydbg.analysis import Bound, ValueSet, narrow_by_guards
        body = _store_imm(0) + _store_imm(0x40) + _cmp_imm(0x29) + b"\x77\x02"
        result = analyze(body)
        narrowed = narrow_by_guards(result, ADDR,
                                    base=ValueSet.of_range(0, 0xFF))
        self.assertEqual(narrowed.kind, Bound.RANGE)
        self.assertEqual((narrowed.lo, narrowed.hi), (0, 0x29))
        self.assertFalse(narrowed.may_contain(0x40))

    def test_without_the_guard_the_writers_are_all_there(self):
        """The control: the same writers, unguarded, exclude nothing."""
        result = analyze(_store_imm(0) + _store_imm(0x40))
        value = _set_of(result)
        self.assertEqual(value.kind.name, "SET")
        self.assertTrue(value.contains(0x40))

    def test_the_other_direction_bounds_from_below(self):
        """`jbe`'s fallthrough is `> limit`, so it excludes the low values.

        Reading `ja`/`jg` as "the guard for too-big" and stopping there is the
        natural first pass, and it leaves half of the range-check idiom
        unrepresentable. The answer stays a SET rather than becoming a RANGE
        because the writers are known: naming a range wider than the values
        actually written would be the opposite failure.
        """
        from pydbg.analysis import narrow_by_guards
        body = _store_imm(0) + _store_imm(0x40) + _cmp_imm(0x29) + \
            bytes((0x76, 0x02))
        result = analyze(body)
        narrowed = narrow_by_guards(result, ADDR)
        self.assertEqual(narrowed.kind.name, "SET")
        self.assertEqual(narrowed.values, frozenset((0x40,)))


class TestTheDeclaredFormsHaveProducers(unittest.TestCase):
    """A form declared and never produced is a missing answer class."""

    def test_no_analysis_fixture_reports_unbounded(self):
        """The strongest available statement that "truly unbounded" is a
        reasoned finding rather than a synonym for "I gave up"."""
        from pydbg.analysis import Bound
        self.assertNotIn(Bound.UNBOUNDED, _kinds_from_analysis())

    def test_every_form_is_produced_somewhere_except_the_one_declared(self):
        from pydbg.analysis import Bound, ValueSet
        produced = _kinds_from_analysis()
        # UNREPRESENTABLE is a fact about a union, so it comes from `widen`
        # rather than from any single image.
        produced.add(ValueSet.of_value(1, 0x10).widen(
            ValueSet.of_range(5, 9)).kind)
        expected_missing = {Bound.UNBOUNDED}
        self.assertEqual(set(Bound) - produced, expected_missing,
                         "a declared form gained or lost a producer; this "
                         "test and the module docstring both need updating")

    def test_the_bracket_idiom_intersects_both_bounds(self):
        """`cmp/ja` then `cmp/ja` is a range check, and both halves count.

        Modelling only the upper half — the shape a first pass naturally takes,
        since `ja` reads like "the guard for too-big" — leaves the idiom
        unrepresentable, and a range is the example the gap itself gives.
        """
        from pydbg.analysis import Bound, ValueSet, narrow_by_guards
        body = _cmp_imm(5) + bytes((0x72, 0x04)) + _cmp_imm(0x29) + \
            bytes((0x77, 0x00))
        result = analyze(body)
        narrowed = narrow_by_guards(result, ADDR,
                                    base=ValueSet.of_range(0, 0xFF))
        self.assertEqual(narrowed.kind, Bound.RANGE)
        self.assertEqual((narrowed.lo, narrowed.hi), (5, 0x29))
        self.assertFalse(narrowed.may_contain(4))
        self.assertFalse(narrowed.may_contain(0x2A))
        self.assertTrue(narrowed.may_contain(5))

    def test_two_unrelated_guard_chains_refuse_rather_than_combine(self):
        """Combining guards from different paths narrows past what the code
        allows, which turns "possible" into "impossible" silently."""
        from pydbg.analysis import ValueSet, narrow_by_guards
        far = NOP * 0x40
        body = (_cmp_imm(5) + bytes((0x72, 0x02)) + far + _cmp_imm(0x29) + bytes((0x77, 0x02)))
        result = analyze(body)
        base = ValueSet.of_range(0, 0xFF)
        self.assertEqual(narrow_by_guards(result, ADDR, base=base), base)

    def test_decided_and_undecided_partition_the_enum(self):
        from pydbg.analysis.values import DECIDED, UNDECIDED
        from pydbg.analysis import Bound
        self.assertEqual(DECIDED | UNDECIDED, set(Bound))
        self.assertEqual(DECIDED & UNDECIDED, set())

    def test_unrepresentable_prints_every_part(self):
        """The antidote to "the set I computed is not the set the note
        claimed": a union with no single form names all of its parts."""
        from pydbg.analysis import ValueSet
        joined = ValueSet.of_value(1, 0x10).widen(ValueSet.of_range(5, 9))
        rendered = joined.render()
        self.assertIn("0x1", rendered)
        self.assertIn("0x5", rendered)
        self.assertIn("0x9", rendered)


class TestScopeIsReported(unittest.TestCase):
    """An answer's scope travels with it."""

    def test_unresolved_writes_are_counted_next_to_the_answer(self):
        from pydbg.analysis import value_set_of
        # A store through a base register: a write to *some* address that this
        # analysis cannot tie to ADDR, and must not pretend it can.
        body = _store_imm(1) + b"\x89\x43\x04"        # mov [ebx+4], eax
        result = analyze(body)
        value = value_set_of(result, ADDR)
        self.assertEqual(value.values, frozenset((1,)))
        self.assertGreaterEqual(value.unresolved_writes, 1)
        self.assertIn("scope", value.render())


if __name__ == "__main__":
    unittest.main()
