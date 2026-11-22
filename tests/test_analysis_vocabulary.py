"""#84 — each piece of analysis vocabulary has one definition.

The failure this guards against is not a crash. A duplicated constant works
until one copy changes, and the tests that kept two copies aligned were
themselves the symptom: when two definitions are the same set, the second one
is not needed. Same for a field or constant nothing assigns: it reads as a
fact the analysis knows, and it is not one.
"""

import unittest


class TestOwnerVocabulary(unittest.TestCase):

    def test_owner_kinds_are_defined_once_and_imported(self):
        from pydbg.analysis import functions, model
        from pydbg.analysis import OWNED_KINDS, OWNER_KINDS

        self.assertIs(OWNER_KINDS, model.OWNER_KINDS)
        self.assertIs(OWNED_KINDS, model.OWNED_KINDS)
        # functions.py re-exports the public tuple for callers that imported it
        # from there; it is the same object, not a second definition.
        self.assertIs(functions.OWNER_KINDS, model.OWNER_KINDS)
        self.assertFalse(hasattr(functions, "_OWNED"))

    def test_owned_kinds_are_the_function_owning_subset(self):
        from pydbg.analysis import OWNED_KINDS, OWNER_KINDS

        self.assertTrue(OWNED_KINDS <= set(OWNER_KINDS))
        for kind in ("after", "before", "unmapped"):
            self.assertNotIn(kind, OWNED_KINDS)


class TestXrefKind(unittest.TestCase):
    """Xref.kind is a RefKind; an unknown kind is refused, not filtered."""

    def test_the_int_form_is_stored_as_the_enum_member(self):
        from pydbg.analysis import RefKind, Xref

        self.assertIs(Xref(0x2000, int(RefKind.MEM)).kind, RefKind.MEM)

    def test_an_unknown_kind_is_rejected_at_construction(self):
        from pydbg.analysis import Xref

        with self.assertRaises(ValueError):
            Xref(0x2000, 99)

    def test_asking_for_an_unknown_kind_is_refused(self):
        from pydbg.analysis import AnalysisResult, RefKind, Xref

        result = AnalysisResult(
            image=None, functions=None,
            xrefs={0x1000: (Xref(0x2000, RefKind.BRANCH),)})
        with self.assertRaises(ValueError):
            result.xrefs_of(0x1000, 99)

    def test_every_stored_kind_is_returned_without_a_filter(self):
        """The old query dropped kinds outside the enum instead of refusing."""
        from pydbg.analysis import AnalysisResult, RefKind, Xref

        stored = tuple(Xref(0x2000 + index, kind)
                       for index, kind in enumerate(RefKind))
        result = AnalysisResult(image=None, functions=None,
                                xrefs={0x1000: stored})
        self.assertEqual(result.ref_kinds_of(0x1000), tuple(sorted(RefKind)))


class TestNoDeadVocabulary(unittest.TestCase):

    def test_stats_have_no_counter_that_is_never_assigned(self):
        from pydbg.analysis import AnalysisStats

        self.assertFalse(hasattr(AnalysisStats(), "nameable"))

    def test_names_have_no_source_without_a_producer(self):
        from pydbg.analysis import names

        for dead in ("SOURCE_SYMBOL", "SOURCE_DERIVED"):
            self.assertFalse(hasattr(names, dead), dead)


if __name__ == "__main__":
    unittest.main()
