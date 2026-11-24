"""Tests for the OEP-hint queries (spec §11.5).

Everything here is a fact query. The aggregator sorts and merges; these tests
therefore assert on the facts and the merging, never on a preferred candidate.
"""

import dataclasses
import struct
import unittest
from types import SimpleNamespace
from unittest import mock

from pydbg.dump import (
    OepCandidate, WatchResult, executable_ranges_outside_functions,
    oep_candidates, tls_callbacks, watch_writes, watched_facts,
)
from pydbg.pe import PE
from pydbg.trace import TraceSummary
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


def fake_result(entries=(), starts=(), exec_ranges=((0x1000, 0x4000),)):
    """An AnalysisResult-shaped object: only the two queries' inputs."""
    exception_entries = [
        SimpleNamespace(begin_rva=begin, end_rva=end)
        for begin, end in entries
    ]
    pe = SimpleNamespace(exception_entries=exception_entries)
    image = SimpleNamespace(pe=pe, exec_ranges=tuple(exec_ranges))
    return SimpleNamespace(image=image,
                           functions=SimpleNamespace(starts=set(starts)))


def result_for(pe, starts=()):
    """An AnalysisResult shape over a real PE, with its executable sections."""
    image = SimpleNamespace(
        pe=pe,
        exec_ranges=tuple((section.virtual_address,
                           section.virtual_address + section.span)
                          for section in pe.sections if section.is_executable))
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

    def test_a_record_outside_every_executable_range_is_not_returned(self):
        result = fake_result(
            entries=((0x2000, 0x2100), (0x5000, 0x5100)),
            exec_ranges=((0x1000, 0x4000),))

        self.assertEqual(executable_ranges_outside_functions(result),
                         ((0x2000, 0x2100),))

    def test_a_range_is_clipped_to_the_executable_part(self):
        result = fake_result(entries=((0x3F00, 0x4200),),
                             exec_ranges=((0x1000, 0x4000),))

        self.assertEqual(executable_ranges_outside_functions(result),
                         ((0x3F00, 0x4000),))

    def test_a_pdata_record_in_a_non_executable_section_is_dropped(self):
        pe = PE(build_pdata_image(((0x2200, 0x2280),)))

        self.assertEqual(
            executable_ranges_outside_functions(result_for(pe)), ())


class TestWatchWrites(unittest.TestCase):
    """The wrapper owns arming and disarming; summary and cleanup pass through."""

    def test_returns_the_summary_and_disarms(self):
        summary = object()
        dbg = object()
        with mock.patch('pydbg.trace.watch.MemoryWatch') as watch_cls:
            watch = watch_cls.return_value
            watch.run.return_value = summary
            watch.disarm.return_value = ()

            found = watch_writes(dbg, 0x1000, 8, tid=7)

        self.assertIsInstance(found, WatchResult)
        self.assertIs(found.summary, summary)
        self.assertEqual(found.warnings, ())
        watch_cls.assert_called_once_with(dbg, 0x1000, 8, tid=7)
        watch.arm.assert_called_once_with()
        watch.run.assert_called_once_with()
        watch.disarm.assert_called_once_with()

    def test_the_disarm_warnings_are_returned_not_dropped(self):
        with mock.patch('pydbg.trace.watch.MemoryWatch') as watch_cls:
            watch = watch_cls.return_value
            watch.run.return_value = object()
            watch.disarm.return_value = ('breakpoint left',)

            found = watch_writes(object(), 0x1000)

        self.assertEqual(found.warnings, ('breakpoint left',))

    def test_disarms_when_the_run_raises(self):
        with mock.patch('pydbg.trace.watch.MemoryWatch') as watch_cls:
            watch = watch_cls.return_value
            watch.run.side_effect = RuntimeError("boom")

            with self.assertRaises(RuntimeError):
                watch_writes(object(), 0x1000)

        watch.disarm.assert_called_once_with()


def watch_summary(*writes):
    """A TraceSummary shaped like the one MemoryWatch.run returns."""
    return TraceSummary(
        events=sum(count for _, count in writes), blocks=0, reason=None,
        elapsed_ns=0, mem_writes=tuple(writes))


class TestWatchedFacts(unittest.TestCase):
    """The write facts §11.5 promised: which address was hit, and how often."""

    def test_a_write_hit_becomes_an_rva_and_a_count_fact(self):
        summary = watch_summary((IMAGE_BASE + 0x1010, 3))

        self.assertEqual(watched_facts(summary, module_base=IMAGE_BASE),
                         ((0x1010, "write@0x140001010x3"),))

    def test_no_recorded_writes_is_an_empty_tuple(self):
        summary = TraceSummary(
            events=0, blocks=0, reason=None, elapsed_ns=0)

        self.assertEqual(
            watched_facts(summary, module_base=IMAGE_BASE), ())

    def test_the_facts_feed_oep_candidates(self):
        summary = watch_summary((IMAGE_BASE + 0x1000, 2))

        candidates = oep_candidates(
            PE(build_plain_image()),
            watched=watched_facts(summary, module_base=IMAGE_BASE))

        self.assertEqual([candidate.rva for candidate in candidates], [0x1000])
        self.assertEqual(candidates[0].sources, ("watched",))
        self.assertIn("write@0x140001000x2", candidates[0].evidence)


class TestOepCandidateRecord(unittest.TestCase):

    def test_fields_are_only_facts(self):
        names = {field.name for field in dataclasses.fields(OepCandidate)}

        self.assertEqual(names, {"rva", "sources", "evidence"})
        for name in names:
            for word in ("score", "probab", "likely", "rank"):
                self.assertNotIn(word, name.lower())

    def test_source_is_the_first_of_the_sources(self):
        candidate = OepCandidate(0x1000, ("watched", "tls"), ("a", "b"))

        self.assertEqual(candidate.sources, ("watched", "tls"))
        self.assertEqual(candidate.source, "watched")

    def test_source_is_read_only(self):
        candidate = OepCandidate(0x1000, ("tls",))

        with self.assertRaises(dataclasses.FrozenInstanceError):
            candidate.source = "watched"

    def test_a_string_source_is_one_source(self):
        candidate = OepCandidate(0x1000, "tls", "callback at 0x1000")

        self.assertEqual(candidate.sources, ("tls",))
        self.assertEqual(candidate.source, "tls")
        self.assertEqual(candidate.evidence, ("callback at 0x1000",))

    def test_empty_sources_are_refused(self):
        with self.assertRaises(ValueError):
            OepCandidate(0x1000, (), ())


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
        self.assertEqual(candidate.source, "tls")
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
        pe = PE(build_pdata_image(((0x1000, 0x1100), (0x1040, 0x1080))))
        result = result_for(pe, starts={0x1000})

        candidates = oep_candidates(result)

        self.assertEqual([candidate.rva for candidate in candidates],
                         [0x1040])
        self.assertEqual(candidates[0].sources, ("pdata-gap",))
        self.assertTrue(any("0x1040" in fact
                            for fact in candidates[0].evidence))
        self.assertTrue(any(".pdata" in fact
                            for fact in candidates[0].evidence))

    def test_a_pe_alone_yields_no_pdata_gap_candidates(self):
        pe = PE(build_pdata_image(((0x1000, 0x1100),)))

        self.assertEqual(oep_candidates(pe), ())
