"""Tests for the PE writer: loaded-layout bytes in, file-layout PE out.

The writer's contract (docs/analysis-coverage.md §11.3) is that it starts from
the image's own header bytes and patches only what moving the sections to file
offsets changes — the parsed model drops fields a re-serialiser would need
(DllCharacteristics, stack/heap sizes, SizeOfOptionalHeader). Every test below
pins one part of that contract by reading the result back with the normal
reader, which is the independent check: nothing here re-derives the expected
bytes the way the writer lays them out.
"""

import struct
import unittest

from tests.pe_builder import PEBuilder, build_loaded_image_with_one_import

TEXT_RVA = 0x1000
RDATA_RVA = 0x2000
IMAGE_BASE = 0x140000000
FILE_ALIGN = 0x200


def loaded_layout_image():
    """The ready-made loaded-layout fixture with a single import."""
    return build_loaded_image_with_one_import()


def parse_loaded(data, image_base=IMAGE_BASE):
    """Parse 'data' the way a dumped/loaded image must be parsed."""
    from pydbg.pe import BytesSource, LoadedView, PE

    return PE.from_source(BytesSource(data), LoadedView(), va_base=image_base)


class TestWritePEFileLayout(unittest.TestCase):
    """Sections moved to file offsets keep their identity and contents."""

    def test_round_trip_preserves_sections_entry_and_imports(self):
        from pydbg.pe import PE, write_pe

        data, iat_rva = loaded_layout_image()
        loaded = parse_loaded(data)

        written = write_pe(loaded, data)
        rebuilt = PE(written)

        self.assertEqual(
            [(s.name, s.characteristics) for s in rebuilt.sections],
            [(s.name, s.characteristics) for s in loaded.sections])
        self.assertEqual(rebuilt.optional_header.entry_point_rva,
                         loaded.optional_header.entry_point_rva)
        self.assertEqual([imp.rva for imp in rebuilt.imports], [iat_rva])
        self.assertEqual([imp.dll_name for imp in rebuilt.imports],
                         ['user32.dll'])
        self.assertEqual([imp.name for imp in rebuilt.imports],
                         ['MessageBoxA'])


class TestWritePEHeaderPatching(unittest.TestCase):
    """The header is the original bytes with a few fields patched."""

    def _loaded_with(self, mutate):
        """Parse the fixture after 'mutate' edited its header bytes."""
        data, _ = loaded_layout_image()
        image = bytearray(data)
        mutate(image)
        return bytes(image)

    def test_checksum_is_zeroed(self):
        from pydbg.pe import PE, write_pe

        optional_offset = 0x80 + 4 + 20
        image = self._loaded_with(
            lambda data: struct.pack_into(
                "<I", data, optional_offset + 64, 0xDEADBEEF))

        written = write_pe(parse_loaded(image), image)

        self.assertEqual(PE(written).optional_header.checksum, 0)
        self.assertEqual(struct.unpack_from("<I", written,
                                            optional_offset + 64)[0], 0)

    def test_fields_dropped_by_the_model_are_copied_through(self):
        from pydbg.pe import PE, write_pe

        e_lfanew = 0x80
        optional_offset = e_lfanew + 4 + 20

        def mutate(image):
            struct.pack_into("<H", image, optional_offset + 70, 0x8140)
            struct.pack_into("<Q", image, optional_offset + 72, 0x12345000)
            struct.pack_into("<I", image, e_lfanew + 4 + 4, 0x12345678)

        image = self._loaded_with(mutate)
        written = write_pe(parse_loaded(image), image)
        rebuilt = PE(written)

        # None of these three are reachable through the parsed dataclasses.
        self.assertEqual(struct.unpack_from("<H", written,
                                            optional_offset + 70)[0], 0x8140)
        self.assertEqual(struct.unpack_from("<Q", written,
                                            optional_offset + 72)[0],
                         0x12345000)
        self.assertEqual(rebuilt.file_header.time_date_stamp, 0x12345678)
        # The DOS stub and SizeOfOptionalHeader come along verbatim.
        self.assertEqual(written[:0x80], image[:0x80])
        self.assertEqual(
            struct.unpack_from("<H", written,
                               e_lfanew + 4 + 16)[0],
            struct.unpack_from("<H", image, e_lfanew + 4 + 16)[0])

    def test_size_of_headers_is_recomputed_and_aligned(self):
        from pydbg.pe import PE, write_pe

        data, _ = loaded_layout_image()
        self.assertEqual(PE(data).optional_header.size_of_headers, 0x400)

        # Smallest header that still holds the section table, deliberately
        # misaligned: the writer must round it up to FileAlignment.
        image = bytearray(data)
        struct.pack_into("<I", image, 0x80 + 4 + 20 + 60, 0x1C8)
        image = bytes(image)

        rebuilt = PE(write_pe(parse_loaded(image), image))

        self.assertEqual(rebuilt.optional_header.size_of_headers, 0x200)
        self.assertEqual([s.pointer_to_raw_data for s in rebuilt.sections],
                         [0x200, 0x400])

    def test_original_size_of_headers_is_kept(self):
        from pydbg.pe import PE, write_pe

        data, _ = loaded_layout_image()
        written = write_pe(parse_loaded(data), data)

        self.assertEqual(PE(written).optional_header.size_of_headers, 0x400)

    def test_under_declared_size_of_headers_keeps_the_section_table(self):
        from pydbg.pe import PE, write_pe

        data = bytearray(loaded_layout_image()[0])
        # A header can under-declare SizeOfHeaders and still parse, because the
        # section table is read at its own offset. Those bytes must survive.
        struct.pack_into("<I", data, 0x80 + 4 + 20 + 60, 0x98)
        image = bytes(data)

        rebuilt = PE(write_pe(parse_loaded(image), image))

        self.assertEqual([(s.name, s.characteristics)
                          for s in rebuilt.sections],
                         [('.text', 0x60000020), ('.rdata', 0x60000020)])


class TestHostileHeaderFields(unittest.TestCase):
    """Header fields are file input, not facts, when they size an allocation.

    SizeOfHeaders feeds a bytearray/ljust and a section's VirtualSize feeds the
    per-section copy; a forged 0xFFFFFF00 used to become a four-gigabyte
    allocation or a MemoryError. Both are clamped to what the Source can
    supply, and the clamp is reported rather than silent.
    """

    def test_forged_size_of_headers_is_clamped_to_the_source(self):
        from pydbg.pe import PE, file_layout, write_pe

        data = bytearray(loaded_layout_image()[0])
        optional_offset = 0x80 + 4 + 20
        struct.pack_into("<I", data, optional_offset + 60, 0xFFFFFF00)
        image = bytes(data)
        loaded = parse_loaded(image)

        with self.assertWarnsRegex(UserWarning, "SizeOfHeaders"):
            layout = file_layout(loaded)
        # The section table is the smallest header the writer must keep.
        self.assertEqual(layout.size_of_headers, 0x200)

        with self.assertWarnsRegex(UserWarning, "SizeOfHeaders"):
            written = write_pe(loaded, image)
        self.assertLess(len(written), 0x1000)
        # The written header records the clamped value, not the forgery.
        self.assertEqual(PE(written).optional_header.size_of_headers, 0x200)

    def test_forged_virtual_size_is_clamped_before_the_copy(self):
        from pydbg.pe import file_layout, write_pe

        data = bytearray(loaded_layout_image()[0])
        size_of_optional_header = struct.unpack_from(
            "<H", data, 0x80 + 4 + 16)[0]
        sections_offset = 0x80 + 4 + 20 + size_of_optional_header
        struct.pack_into("<I", data, sections_offset + 8, 0xFFFFFF00)
        image = bytes(data)
        loaded = parse_loaded(image)

        with self.assertWarnsRegex(UserWarning, "VirtualSize"):
            layout = file_layout(loaded)

        # .text may claim only the bytes the source has from its RVA, and
        # SizeOfImage is computed from that clamped extent.
        self.assertEqual(layout.sections[0].size, len(image) - TEXT_RVA)
        self.assertEqual(layout.size_of_image, 0x3000)

        with self.assertWarnsRegex(UserWarning, "VirtualSize"):
            written = write_pe(loaded, image)
        self.assertLess(len(written), 0x8000)


class TestFileLayout(unittest.TestCase):
    """The shared layout calculation that write_pe and rebuild_pe both use."""

    def test_the_layout_matches_the_written_header_and_section_table(self):
        from pydbg.pe import PE, file_layout, write_pe

        data, _ = loaded_layout_image()
        loaded = parse_loaded(data)

        layout = file_layout(loaded)
        written = PE(write_pe(loaded, data))

        self.assertEqual(layout.size_of_image,
                         written.optional_header.size_of_image)
        self.assertEqual(layout.size_of_headers,
                         written.optional_header.size_of_headers)
        self.assertEqual(
            [(section.raw_pointer, section.raw_size)
             for section in layout.sections],
            [(section.pointer_to_raw_data, section.size_of_raw_data)
             for section in written.sections])
        # The fixture hard-codes SizeOfImage = 0x8000; the layout has the
        # recomputed truth.
        self.assertEqual(layout.size_of_image, 0x3000)


class TestWritePELayout(unittest.TestCase):
    """Section data lands at aligned, increasing, non-overlapping offsets."""

    def test_section_offsets_are_aligned_and_strictly_increasing(self):
        from pydbg.pe import PE, write_pe

        data, _ = loaded_layout_image()
        written = write_pe(parse_loaded(data), data)
        rebuilt = PE(written)

        pointers = [s.pointer_to_raw_data for s in rebuilt.sections]
        self.assertEqual(pointers, sorted(set(pointers)))
        self.assertTrue(all(pointer % FILE_ALIGN == 0 for pointer in pointers))
        self.assertGreaterEqual(pointers[0],
                                rebuilt.optional_header.size_of_headers)

    def test_size_of_image_is_recomputed_from_the_sections(self):
        from pydbg.pe import PE, write_pe

        data, _ = loaded_layout_image()
        loaded = parse_loaded(data)
        # The fixture hard-codes 0x8000; .rdata ends at 0x2500, so the truth
        # is the next SectionAlignment boundary.
        self.assertEqual(loaded.optional_header.size_of_image, 0x8000)

        rebuilt = PE(write_pe(loaded, data))

        self.assertEqual(rebuilt.optional_header.size_of_image, 0x3000)
        for section in rebuilt.sections:
            self.assertLessEqual(
                section.virtual_address + section.span,
                rebuilt.optional_header.size_of_image)

    def test_output_has_no_overlay_and_section_data_is_copied(self):
        from pydbg.pe import PE, write_pe

        data, _ = loaded_layout_image()
        written = write_pe(parse_loaded(data), data)
        rebuilt = PE(written)

        last = rebuilt.sections[-1]
        self.assertEqual(
            len(written), last.pointer_to_raw_data + last.size_of_raw_data)

        text, rdata = rebuilt.sections
        # .text (0x100 bytes) padded to FileAlignment.
        text_raw = written[text.pointer_to_raw_data:
                           text.pointer_to_raw_data + text.size_of_raw_data]
        self.assertEqual(text_raw[:0x100], data[TEXT_RVA:TEXT_RVA + 0x100])
        self.assertEqual(text_raw[0x100:], b"\x00" * 0x100)
        # .rdata (0x500 bytes) likewise.
        rdata_raw = written[rdata.pointer_to_raw_data:
                            rdata.pointer_to_raw_data +
                            rdata.size_of_raw_data]
        self.assertEqual(rdata_raw[:0x500], data[RDATA_RVA:RDATA_RVA + 0x500])
        self.assertEqual(rdata_raw[0x500:], b"\x00" * 0x100)

    def test_entry_point_can_be_overridden(self):
        from pydbg.pe import PE, write_pe

        data, _ = loaded_layout_image()
        loaded = parse_loaded(data)

        written = write_pe(loaded, data, entry_point=0x2010)
        rebuilt = PE(written)

        self.assertEqual(rebuilt.optional_header.entry_point_rva, 0x2010)
        self.assertEqual(loaded.optional_header.entry_point_rva, 0x1000)

    def test_a_file_view_parsed_pe_is_rejected(self):
        from pydbg.pe import PE, write_pe

        data, _ = loaded_layout_image()
        file_pe = PE(data)

        with self.assertRaises(ValueError):
            write_pe(file_pe, data)

    def test_short_image_bytes_are_zero_filled(self):
        from pydbg.pe import PE, write_pe

        data, _ = loaded_layout_image()
        truncated = data[:0x2400]  # cut inside .rdata

        written = write_pe(parse_loaded(data), truncated)
        rebuilt = PE(written)

        rdata = rebuilt.sections[1]
        raw = written[rdata.pointer_to_raw_data:
                      rdata.pointer_to_raw_data + rdata.size_of_raw_data]
        self.assertEqual(raw[:0x400], truncated[RDATA_RVA:0x2400])
        self.assertEqual(raw[0x400:0x600], b"\x00" * 0x200)

    def test_the_input_pe_is_not_modified(self):
        from pydbg.pe import write_pe

        data, _ = loaded_layout_image()
        loaded = parse_loaded(data)
        before = (loaded.optional_header.size_of_image,
                  loaded.optional_header.size_of_headers,
                  loaded.optional_header.entry_point_rva,
                  loaded.optional_header.checksum,
                  [(s.virtual_size, s.size_of_raw_data,
                    s.pointer_to_raw_data) for s in loaded.sections])

        write_pe(loaded, data, entry_point=0x2010)

        after = (loaded.optional_header.size_of_image,
                 loaded.optional_header.size_of_headers,
                 loaded.optional_header.entry_point_rva,
                 loaded.optional_header.checksum,
                 [(s.virtual_size, s.size_of_raw_data,
                   s.pointer_to_raw_data) for s in loaded.sections])
        self.assertEqual(after, before)

    def test_zero_virtual_size_falls_back_to_the_section_span(self):
        from pydbg.pe import PE, write_pe

        data = bytearray(loaded_layout_image()[0])
        size_of_optional_header = struct.unpack_from("<H", data, 0x80 + 4 + 16)[0]
        sections_offset = 0x80 + 4 + 20 + size_of_optional_header
        struct.pack_into("<I", data, sections_offset + 8, 0)  # .text VirtualSize
        image = bytes(data)

        written = write_pe(parse_loaded(image), image)
        rebuilt = PE(written)

        text = rebuilt.sections[0]
        self.assertEqual(text.virtual_size, 0)
        self.assertEqual(text.size_of_raw_data, 0x200)
        self.assertEqual(
            written[text.pointer_to_raw_data:
                    text.pointer_to_raw_data + 0x100],
            image[TEXT_RVA:TEXT_RVA + 0x100])
        self.assertEqual(rebuilt.optional_header.size_of_image, 0x3000)

    def test_pe32_round_trip(self):
        from pydbg.pe import PE, write_pe

        builder = PEBuilder(magic=0x10B, image_base=0x400000)
        builder.add_section(".text", b"\x90" * 0x100, TEXT_RVA)
        builder.add_section(".data", b"\xcc" * 0x300, RDATA_RVA, 0x40000040)
        data = builder.build()

        written = write_pe(parse_loaded(data, image_base=0x400000), data)
        rebuilt = PE(written)

        self.assertEqual([(s.name, s.characteristics)
                          for s in rebuilt.sections],
                         [('.text', 0x60000020), ('.data', 0x40000040)])
        self.assertEqual(rebuilt.optional_header.entry_point_rva, 0x1000)
        self.assertEqual(rebuilt.optional_header.size_of_image, 0x3000)
        self.assertEqual(written[rebuilt.sections[1].pointer_to_raw_data:]
                         [:0x300], b"\xcc" * 0x300)
