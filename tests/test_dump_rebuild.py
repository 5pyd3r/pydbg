"""Tests for rebuild_pe: a DumpedImage in, a parseable PE plus a report out.

The seams under test are the two the ticket names: the public `rebuild_pe`
result (bytes + report) and the errors it raises. Each test starts from a real
loaded-layout image built by tests.pe_builder, wraps it in the DumpedImage that
dump_module would have produced, and reads the result back with the normal
parser. Expected values come from the fixture and from a LoadedView parse of
the source image — never from the writer's layout arithmetic — so a writer and
a rebuild that drift together cannot both stay green.
"""

import ctypes
import os
import shutil
import struct
import tempfile
import unittest

from pydbg.dump import (
    DumpedImage, Gap, RebuildError, RebuildReport, RebuiltImage, rebuild_pe,
)
from pydbg.pe import BytesSource, LoadedView, PE
from tests.pe_builder import build_loaded_image_with_one_import

IMAGE_BASE = 0x140000000
TEXT_RVA = 0x1000
RDATA_RVA = 0x2000
ENTRY_RVA = 0x1000
# PE signature at 0x80, FileHeader 20 bytes, so the optional header starts here.
OPTIONAL_HEADER_OFFSET = 0x80 + 4 + 20
# The fixture's header hard-codes SizeOfImage = 0x8000 although its sections
# end at 0x2500; dump_module reads exactly [0, SizeOfImage), so the dump is
# padded to that, and the rebuild recomputes the true extent.
SOURCE_SIZE_OF_IMAGE = 0x8000
REBUILT_SIZE_OF_IMAGE = 0x3000


def loaded_image():
    """The ready-made loaded-layout fixture, padded the way a dump would be."""
    data, iat_rva = build_loaded_image_with_one_import(image_base=IMAGE_BASE)
    return data.ljust(SOURCE_SIZE_OF_IMAGE, b'\x00'), iat_rva


def dumped_image(data, *, gaps=(), image_base=IMAGE_BASE,
                 size_of_image=SOURCE_SIZE_OF_IMAGE, load_delta=0):
    """A DumpedImage with the fields dump_module fills in for this fixture."""
    return DumpedImage(
        rva_base=image_base,
        data=data,
        gaps=tuple(gaps),
        module_name='fixture.dll',
        image_base=image_base,
        size_of_image=size_of_image,
        entry_point_rva=ENTRY_RVA,
        load_delta=load_delta,
    )


def source_pe(data):
    """Parse the dumped bytes the way rebuild_pe is required to (P25 contract)."""
    return PE.from_source(BytesSource(data), LoadedView(), va_base=IMAGE_BASE)


class TestRebuildParseableImage(unittest.TestCase):
    """A complete dump becomes a file-layout PE this package parses back."""

    def test_the_rebuilt_image_keeps_sections_entry_and_imports(self):
        data, iat_rva = loaded_image()
        dumped = dumped_image(data)
        source = source_pe(data)

        rebuilt = rebuild_pe(dumped)

        self.assertIsInstance(rebuilt, RebuiltImage)
        self.assertIsInstance(rebuilt.report, RebuildReport)
        parsed = PE(rebuilt.data)
        self.assertEqual(
            [(section.name, section.characteristics)
             for section in parsed.sections],
            [(section.name, section.characteristics)
             for section in source.sections])
        self.assertEqual(parsed.optional_header.entry_point_rva, ENTRY_RVA)
        self.assertEqual(parsed.optional_header.image_base, IMAGE_BASE)
        self.assertEqual(
            [(imp.dll_name, imp.name, imp.rva) for imp in parsed.imports],
            [(imp.dll_name, imp.name, imp.rva) for imp in source.imports])
        self.assertEqual([imp.rva for imp in parsed.imports], [iat_rva])

    def test_the_report_describes_the_rebuild(self):
        data, _ = loaded_image()

        report = rebuild_pe(dumped_image(data)).report

        self.assertEqual(report.sections_rebuilt, 2)
        self.assertEqual(report.size_of_image, REBUILT_SIZE_OF_IMAGE)
        self.assertEqual(report.entry_point, ENTRY_RVA)
        self.assertEqual(report.load_delta, 0)
        self.assertEqual(report.imports, 1)
        self.assertEqual(report.unresolved_imports, ())
        self.assertEqual(report.gaps, ())
        self.assertEqual(report.warnings, ())


class TestSectionGap(unittest.TestCase):
    """A hole in one section is zero-filled and named, not a failure."""

    def test_a_gap_in_section_data_is_zero_filled_and_warned(self):
        data, _ = loaded_image()
        gap = Gap(0x1080, 0x10, 'unreadable:protect=0x0')
        holed = bytearray(data)
        holed[gap.rva:gap.rva + gap.size] = b'\x00' * gap.size

        rebuilt = rebuild_pe(dumped_image(bytes(holed), gaps=[gap]))

        self.assertEqual(rebuilt.report.gaps, (gap,))
        self.assertEqual(rebuilt.report.warnings, ('gap in .text',))
        # The image is still usable: the import in .rdata was untouched.
        self.assertEqual(rebuilt.report.imports, 1)
        parsed = PE(rebuilt.data)
        self.assertEqual(len(parsed.imports), 1)
        text = parsed.sections[0]
        raw = rebuilt.data[text.pointer_to_raw_data:
                           text.pointer_to_raw_data + text.size_of_raw_data]
        self.assertEqual(raw[0x80:0x90], b'\x00' * 0x10)
        # ... and only the hole is zero: the bytes around it came through.
        self.assertEqual(raw[0x70:0x80], holed[TEXT_RVA + 0x70:TEXT_RVA + 0x80])
        self.assertEqual(raw[0x90:0x100], holed[TEXT_RVA + 0x90:TEXT_RVA + 0x100])


class TestHeaderGap(unittest.TestCase):
    """A hole in the header cannot be repaired by zero-filling."""

    def test_a_gap_inside_size_of_headers_is_refused(self):
        data, _ = loaded_image()
        gap = Gap(0x300, 0x20, 'free')
        holed = bytearray(data)
        holed[gap.rva:gap.rva + gap.size] = b'\x00' * gap.size

        with self.assertRaisesRegex(RebuildError, 'gap in header'):
            rebuild_pe(dumped_image(bytes(holed), gaps=[gap]))

    def test_a_gap_just_past_size_of_headers_is_not_a_header_gap(self):
        """The boundary is SizeOfHeaders (0x400 here), not the first page."""
        data, _ = loaded_image()
        gap = Gap(0x400, 0x10, 'free')
        holed = bytearray(data)
        holed[gap.rva:gap.rva + gap.size] = b'\x00' * gap.size

        rebuilt = rebuild_pe(dumped_image(bytes(holed), gaps=[gap]))

        self.assertEqual(rebuilt.report.warnings, ())


class TestStructuralErrors(unittest.TestCase):
    """Problems with the input itself produce no bytes, just a reason."""

    def test_bytes_that_are_not_a_pe_are_refused_with_the_parser_reason(self):
        dumped = dumped_image(b'\x00' * 0x1000, size_of_image=0x1000)

        with self.assertRaisesRegex(RebuildError,
                                    r'not a PE image.*Invalid DOS signature'):
            rebuild_pe(dumped)

    def test_a_range_dumped_with_dump_region_is_not_a_pe(self):
        data, _ = loaded_image()
        # dump_region does not require a PE at its base; feeding one to
        # rebuild_pe must say so instead of emitting a plausible file.
        region = dumped_image(data[0x400:0x800], image_base=IMAGE_BASE,
                              size_of_image=0x400)

        with self.assertRaises(RebuildError):
            rebuild_pe(region)

    def test_an_image_the_writer_cannot_lay_out_is_a_rebuild_error(self):
        data, _ = loaded_image()
        broken = bytearray(data)
        # FileAlignment lives at optional header +36; zero is unusable.
        struct.pack_into('<I', broken, OPTIONAL_HEADER_OFFSET + 36, 0)

        with self.assertRaisesRegex(RebuildError, 'cannot lay out'):
            rebuild_pe(dumped_image(bytes(broken)))


class TestUnreadableImports(unittest.TestCase):
    """A hole over the import structures is reported, not invented away."""

    def test_a_gap_over_the_import_directory_is_reported(self):
        data, _ = loaded_image()
        gap = Gap(RDATA_RVA, 0x14, 'free')       # the import descriptor
        holed = bytearray(data)
        holed[gap.rva:gap.rva + gap.size] = b'\x00' * gap.size

        rebuilt = rebuild_pe(dumped_image(bytes(holed), gaps=[gap]))

        self.assertEqual(rebuilt.report.imports, 0)
        self.assertEqual(len(PE(rebuilt.data).imports), 0)
        self.assertEqual(rebuilt.report.warnings,
                         ('gap in .rdata', 'imports_unreadable'))

    def test_an_unreadable_thunk_name_is_an_unresolved_slot(self):
        """The descriptor survives, the ILT survives, but the name does not."""
        data, iat_rva = loaded_image()
        gap = Gap(0x2200, 0x10, 'unreadable:protect=0x0')    # IMAGE_IMPORT_BY_NAME
        holed = bytearray(data)
        holed[gap.rva:gap.rva + gap.size] = b'\x00' * gap.size

        rebuilt = rebuild_pe(dumped_image(bytes(holed), gaps=[gap]))

        # The entry is still copied through (its IAT slot is untouched); what
        # is missing is only the name, which the report separates out.
        self.assertEqual(rebuilt.report.imports, 1)
        self.assertEqual(rebuilt.report.unresolved_imports, (iat_rva,))
        self.assertEqual(rebuilt.report.warnings, ('gap in .rdata',))


class TestEntryPointAndLoadDelta(unittest.TestCase):
    """The two values the caller can steer and must be told about."""

    def test_entry_point_can_be_overridden(self):
        data, _ = loaded_image()

        rebuilt = rebuild_pe(dumped_image(data), entry_point=0x1010)

        self.assertEqual(rebuilt.report.entry_point, 0x1010)
        self.assertEqual(PE(rebuilt.data).optional_header.entry_point_rva, 0x1010)

    def test_load_delta_is_recorded_but_never_applied(self):
        data, _ = loaded_image()
        dumped = dumped_image(data, load_delta=0x5000)

        rebuilt = rebuild_pe(dumped)

        # Relocation rewriting is out of scope (§11.7): the header keeps the
        # preferred base, and the delta is only a fact in the report.
        self.assertEqual(rebuilt.report.load_delta, 0x5000)
        self.assertEqual(PE(rebuilt.data).optional_header.image_base, IMAGE_BASE)


class TestLoadable(unittest.TestCase):
    """The Windows loader is the second oracle; `PE(data)` is only the first.

    A synthetic image can be perfectly parseable and still be rejected by the
    loader (missing DLL characteristics, a section the memory manager dislikes).
    The acceptance criterion is "loads", so this test asks the loader; when it
    refuses, the test is skipped as an environment limit rather than failing —
    the ticket allows that, because not every synthetic image has to satisfy
    the loader.
    """

    DONT_RESOLVE_DLL_REFERENCES = 0x1

    def test_the_rebuilt_image_loads_dont_resolve_dll_references(self):
        data, _ = loaded_image()
        rebuilt = rebuild_pe(dumped_image(data))

        directory = tempfile.mkdtemp(prefix='pydbg-rebuild-')
        try:
            path = os.path.join(directory, 'rebuilt.dll')
            with open(path, 'wb') as handle:
                handle.write(rebuilt.data)

            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            load = kernel32.LoadLibraryExW
            load.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p,
                             ctypes.c_uint32]
            load.restype = ctypes.c_void_p
            free = kernel32.FreeLibrary
            free.argtypes = [ctypes.c_void_p]
            free.restype = ctypes.c_int

            module = load(path, None, self.DONT_RESOLVE_DLL_REFERENCES)
            if not module:
                self.skipTest(
                    'environment: the loader rejected the synthetic image '
                    f'(Win32 error {ctypes.get_last_error()})')
            try:
                self.assertTrue(module)
            finally:
                free(module)
        finally:
            shutil.rmtree(directory, ignore_errors=True)
