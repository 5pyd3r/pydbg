"""Tests for the OEP-hint queries (spec §11.5).

Everything here is a fact query. The aggregator sorts and merges; these tests
therefore assert on the facts and the merging, never on a preferred candidate.
"""

import dataclasses
import struct
import unittest
from types import SimpleNamespace
from unittest import mock

import pydbg.dump.oep as oep_module
from pydbg.dump import (
    OepCandidate, executable_ranges_outside_functions, oep_candidates,
    tls_callbacks, watch_writes,
)
from pydbg.pe import PE
from tests.pe_builder import PEBuilder

RVA_TEXT = 0x1000
RVA_RDATA = 0x2000
RVA_TLS_HDR = 0x2000
RVA_TLS_CALLBACKS = 0x2040
IMAGE_BASE = 0x140000000


def build_tls_image(callback_offsets=(0x1000, 0x1010)):
    """A PE32+ whose TLS callbacks point at IMAGE_BASE + each offset."""
    builder = PEBuilder(image_base=IMAGE_BASE)
    builder.add_section(".text", b"\x90" * 0x100, RVA_TEXT)

    callbacks = [IMAGE_BASE + offset for offset in callback_offsets]
    array = b"".join(struct.pack("<Q", va) for va in callbacks)
    array += struct.pack("<Q", 0)

    values = (IMAGE_BASE + 0x1000, IMAGE_BASE + 0x2000, IMAGE_BASE + 0x3000,
              IMAGE_BASE + RVA_TLS_CALLBACKS, 0, 0)
    header = struct.pack("<QQQQII", *values)

    rdata = bytearray(0x400)
    offset = RVA_TLS_HDR - RVA_RDATA
    rdata[offset:offset + len(header)] = header
    offset = RVA_TLS_CALLBACKS - RVA_RDATA
    rdata[offset:offset + len(array)] = array
    builder.add_section(".rdata", bytes(rdata), RVA_RDATA, 0x40000040)
    builder.add_dir(9, RVA_TLS_HDR, len(header))
    return builder.build(), callbacks


def build_plain_image():
    builder = PEBuilder(image_base=IMAGE_BASE)
    builder.add_section(".text", b"\x90" * 0x100, RVA_TEXT)
    return builder.build()


def build_pdata_image(entries):
    builder = PEBuilder(image_base=IMAGE_BASE)
    builder.add_section(".text", b"\x90" * 0x100, RVA_TEXT)
    payload = b"".join(
        struct.pack("<III", begin, end, 0) for begin, end in entries)
    builder.add_section(".pdata", payload, 0x2200, 0x40000040)
    builder.add_dir(3, 0x2200, len(payload))
    return builder.build()


class TestTlsCallbacks(unittest.TestCase):

    def test_matches_the_parsed_tls_directory(self):
        data, callbacks = build_tls_image()

        pe = PE(data)

        self.assertEqual(tls_callbacks(pe), tuple(pe.tls.callbacks))
        self.assertEqual(tls_callbacks(pe), tuple(callbacks))

    def test_no_tls_directory_returns_an_empty_tuple(self):
        self.assertEqual(tls_callbacks(PE(build_plain_image())), ())

    def test_an_callback_outside_the_image_names_the_base_requirement(self):
        data, _ = build_tls_image(callback_offsets=(0x9000,))

        with self.assertRaises(ValueError) as caught:
            tls_callbacks(PE(data))

        message = str(caught.exception)
        self.assertIn("va_base", message)
        self.assertIn("runtime base", message)


def fake_result(entries=(), starts=()):
    """An AnalysisResult-shaped object: only the two queries' inputs."""
    exception_entries = [
        SimpleNamespace(begin_rva=begin, end_rva=end)
        for begin, end in entries
    ]
    pe = SimpleNamespace(exception_entries=exception_entries)
    image = SimpleNamespace(pe=pe)
    return SimpleNamespace(image=image,
                           functions=SimpleNamespace(starts=set(starts)))


class TestExecutableRangesOutsideFunctions(unittest.TestCase):

    def test_ranges_whose_begin_is_not_a_start_are_returned(self):
        result = fake_result(
            entries=((0x1000, 0x1100), (0x2000, 0x2100), (0x3000, 0x3100)),
            starts=(0x1000, 0x3000))

        self.assertEqual(executable_ranges_outside_functions(result),
                         ((0x2000, 0x2100),))

    def test_no_pdata_is_an_empty_tuple(self):
        self.assertEqual(
            executable_ranges_outside_functions(fake_result()), ())

    def test_overlapping_ranges_are_merged(self):
        result = fake_result(entries=((0x2000, 0x2200), (0x2100, 0x2300)))

        self.assertEqual(executable_ranges_outside_functions(result),
                         ((0x2000, 0x2300),))

    def test_a_start_inside_but_not_at_the_begin_keeps_the_range(self):
        result = fake_result(entries=((0x2000, 0x2200),), starts=(0x2100,))

        self.assertEqual(executable_ranges_outside_functions(result),
                         ((0x2000, 0x2200),))

    def test_degenerate_entries_are_dropped(self):
        result = fake_result(entries=((0x2000, 0x2000), (0x2100, 0x2000)))

        self.assertEqual(executable_ranges_outside_functions(result), ())


class TestWatchWrites(unittest.TestCase):
    """The wrapper owns arming and disarming; the summary passes through."""

    def test_returns_the_summary_and_disarms(self):
        summary = object()
        dbg = object()
        with mock.patch.object(oep_module, 'MemoryWatch') as watch_cls:
            watch = watch_cls.return_value
            watch.run.return_value = summary

            found = watch_writes(dbg, 0x1000, 8, tid=7)

        self.assertIs(found, summary)
        watch_cls.assert_called_once_with(dbg, 0x1000, 8, tid=7)
        watch.arm.assert_called_once_with()
        watch.run.assert_called_once_with()
        watch.disarm.assert_called_once_with()

    def test_disarms_when_the_run_raises(self):
        with mock.patch.object(oep_module, 'MemoryWatch') as watch_cls:
            watch = watch_cls.return_value
            watch.run.side_effect = RuntimeError("boom")

            with self.assertRaises(RuntimeError):
                watch_writes(object(), 0x1000)

        watch.disarm.assert_called_once_with()


class TestOepCandidateRecord(unittest.TestCase):

    def test_fields_are_only_facts(self):
        names = {field.name for field in dataclasses.fields(OepCandidate)}

        self.assertEqual(names, {"rva", "source", "evidence"})
        for name in names:
            for word in ("score", "probab", "likely", "rank"):
                self.assertNotIn(word, name.lower())

    def test_a_string_evidence_is_wrapped_as_one_fact(self):
        candidate = OepCandidate(0x1000, "tls", "callback at 0x1000")

        self.assertEqual(candidate.evidence, ("callback at 0x1000",))
        self.assertEqual(candidate.sources, ("tls",))

    def test_merged_sources_are_kept_in_order(self):
        candidate = OepCandidate(0x1000, ("watched", "tls"), ("a", "b"))

        self.assertEqual(candidate.source, "watched+tls")
        self.assertEqual(candidate.sources, ("watched", "tls"))


class TestOepCandidates(unittest.TestCase):

    def test_empty_input_returns_an_empty_tuple(self):
        self.assertEqual(oep_candidates(PE(build_plain_image())), ())

    def test_tls_and_watched_at_the_same_rva_merge_into_one_candidate(self):
        data, callbacks = build_tls_image()
        pe = PE(data)
        rva = callbacks[0] - pe.va_base

        candidates = oep_candidates(pe, watched=((rva, "3 writes hit it"),))
        found = [candidate for candidate in candidates
                 if candidate.rva == rva]

        self.assertEqual(len(found), 1)
        candidate = found[0]
        self.assertEqual(candidate.sources, ("tls", "watched"))
        self.assertEqual(candidate.source, "tls+watched")
        self.assertTrue(any(f"0x{rva:X}" in fact
                            for fact in candidate.evidence))
        self.assertTrue(any("3 writes" in fact
                            for fact in candidate.evidence))

    def test_a_tls_evidence_names_the_rva(self):
        data, callbacks = build_tls_image()
        pe = PE(data)

        candidates = oep_candidates(pe)

        for candidate in candidates:
            self.assertTrue(any(f"0x{candidate.rva:X}" in fact
                                for fact in candidate.evidence))
        self.assertEqual(sorted(candidate.rva for candidate in candidates),
                         sorted(va - pe.va_base for va in callbacks))

    def test_candidates_are_sorted_by_rva(self):
        candidates = oep_candidates(
            PE(build_plain_image()),
            watched=((0x3000, "late"), (0x1000, "early")))

        self.assertEqual([candidate.rva for candidate in candidates],
                         [0x1000, 0x3000])

    def test_a_pdata_gap_becomes_a_candidate_at_the_range_begin(self):
        pe = PE(build_pdata_image(((0x1000, 0x1100), (0x2000, 0x2100))))
        result = SimpleNamespace(
            image=SimpleNamespace(pe=pe),
            functions=SimpleNamespace(starts={0x1000}))

        candidates = oep_candidates(result)

        self.assertEqual([candidate.rva for candidate in candidates],
                         [0x2000])
        self.assertEqual(candidates[0].sources, ("pdata-gap",))
        self.assertTrue(any("0x2000" in fact
                            for fact in candidates[0].evidence))
        self.assertTrue(any(".pdata" in fact
                            for fact in candidates[0].evidence))

    def test_a_pe_alone_yields_no_pdata_gap_candidates(self):
        pe = PE(build_pdata_image(((0x1000, 0x1100),)))

        self.assertEqual(oep_candidates(pe), ())
