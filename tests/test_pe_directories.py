"""Tests for the lazily-parsed PE data directories.

Data directories 3 (exception), 5 (base relocations), 6 (debug) and 9 (TLS),
plus the Rich header. pydbg previously read only directories 0 and 1, which is
what left every reverse-engineering consumer hand-rolling its own walks.
"""

import os
import struct
import unittest

from tests.pe_builder import PEBuilder

RVA_TEXT = 0x1000
RVA_RDATA = 0x2000
RVA_TLS_HDR = 0x2000
RVA_TLS_CALLBACKS = 0x2040
RVA_RELOC = 0x2080
RVA_DEBUG = 0x2100
RVA_PDATA = 0x2200


def _base_image(magic=0x20B):
    """Builder with the .text/.rdata pair every fixture below starts from."""
    image_base = 0x140000000 if magic == 0x20B else 0x400000
    builder = PEBuilder(magic=magic, image_base=image_base)
    builder.add_section(".text", b"\x90" * 0x100, RVA_TEXT)
    return builder, image_base


def _place(buffer, rva, data):
    offset = rva - RVA_RDATA
    buffer[offset:offset + len(data)] = data


def build_tls_image(magic=0x20B, callback_offsets=(0x1000, 0x1010),
                    terminate=True):
    """Image with a TLS directory whose callbacks point into .text."""
    builder, image_base = _base_image(magic)
    is_pe32plus = magic == 0x20B
    stride_fmt = "<Q" if is_pe32plus else "<I"

    callbacks = [image_base + offset for offset in callback_offsets]
    array = b"".join(struct.pack(stride_fmt, value) for value in callbacks)
    if terminate:
        array += struct.pack(stride_fmt, 0)

    values = (image_base + 0x1000, image_base + 0x2000, image_base + 0x3000,
              image_base + RVA_TLS_CALLBACKS, 0, 0)
    header = (struct.pack("<QQQQII", *values) if is_pe32plus
              else struct.pack("<IIIIII", *values))

    rdata = bytearray(0x400)
    _place(rdata, RVA_TLS_HDR, header)
    _place(rdata, RVA_TLS_CALLBACKS, array)
    builder.add_section(".rdata", bytes(rdata), RVA_RDATA, 0x40000040)
    builder.add_dir(9, RVA_TLS_HDR, len(header))
    return builder.build(), image_base, callbacks


def build_reloc_image(magic=0x20B, kind=10, declared_size=None,
                      pages=(0x1000,), terminator=True,
                      block_after_terminator=False):
    """Relocation directory holding a two-entry block per page in 'pages'.

    'block_after_terminator' plants a further real block past the zero block,
    so a walk that ignored the terminator would find it instead of stopping.
    """
    builder, _ = _base_image(magic)
    body = struct.pack("<HH", (kind << 12) | 0x10, (kind << 12) | 0x20)

    def block(page):
        return struct.pack("<II", page, 8 + len(body)) + body

    payload = b"".join(block(page) for page in pages)
    if terminator:
        payload += struct.pack("<II", 0, 0)
    if block_after_terminator:
        payload += block(0x9000)

    builder.add_section(".reloc", payload, RVA_RELOC, 0x42000040)
    builder.add_dir(5, RVA_RELOC,
                    len(payload) if declared_size is None else declared_size)
    return builder.build()


def build_debug_image():
    builder, _ = _base_image()
    entry = struct.pack("<IIHHIIII", 0, 0x5A000000, 0, 0, 2, 0x20,
                        RVA_TEXT, 0x400)
    builder.add_section(".rdata", entry, RVA_RDATA, 0x40000040)
    builder.add_dir(6, RVA_RDATA, len(entry))
    return builder.build()


def build_pdata_image(terminate=False):
    builder, _ = _base_image()
    payload = (struct.pack("<III", 0x1000, 0x1050, 0x2000)
               + struct.pack("<III", 0x1050, 0x10A0, 0x2008))
    if terminate:
        payload += struct.pack("<III", 0, 0, 0)
    builder.add_section(".pdata", payload, RVA_PDATA, 0x40000040)
    builder.add_dir(3, RVA_PDATA, len(payload))
    return builder.build()


def build_rich_image(key=0x12345678, pairs=((0x0101, 5), (0x0202, 3))):
    builder, _ = _base_image()
    blob = struct.pack("<I", 0x536E6144 ^ key)          # "DanS", encoded
    blob += struct.pack("<I", key) * 3                  # three zero dwords
    for comp_id, count in pairs:
        blob += struct.pack("<I", comp_id ^ key)
        blob += struct.pack("<I", count ^ key)
    blob += b"Rich" + struct.pack("<I", key)
    builder.set_rich(blob)
    return builder.build(), key


class TestTLSDirectory(unittest.TestCase):

    def test_pe32plus_callbacks_are_read(self):
        from pydbg.pe import PE

        data, _, expected = build_tls_image(0x20B)
        tls = PE(data).tls
        self.assertIsNotNone(tls)
        self.assertEqual(tls.callbacks, expected)
        self.assertEqual(tls.size_of_zero_fill, 0)

    def test_pe32_header_uses_the_24_byte_layout(self):
        """PE32 and PE32+ differ in both header size and array stride."""
        from pydbg.pe import PE

        data, _, expected = build_tls_image(0x10B)
        tls = PE(data).tls
        self.assertIsNotNone(tls)
        self.assertEqual(tls.callbacks, expected)

    def test_absent_directory_is_none(self):
        from pydbg.pe import PE

        builder, _ = _base_image()
        self.assertIsNone(PE(builder.build()).tls)

    def test_callbacks_stop_at_the_null_terminator(self):
        from pydbg.pe import PE

        data, _, expected = build_tls_image(0x20B)
        tls = PE(data).tls
        self.assertEqual(len(tls.callbacks), len(expected))

    def test_wrong_va_base_yields_no_callbacks(self):
        """The stored addresses are VAs, so the base has to be right.

        Worth a test because the failure is silent: with a live module under
        ASLR, passing the preferred ImageBase instead of the runtime base
        leaves every callback pointing outside the image, and the honest
        answer — no callbacks — looks the same as a module without TLS.
        """
        from pydbg.pe import PE
        from pydbg.pe.source import BytesSource

        data, image_base, _ = build_tls_image(0x20B)
        pe = PE.from_source(BytesSource(data), None,
                            va_base=image_base + 0x100000)
        self.assertEqual(pe.tls.callbacks, [])


class TestRelocations(unittest.TestCase):

    def test_pe32plus_dir64_entries(self):
        from pydbg.pe import PE

        blocks = PE(build_reloc_image(0x20B, kind=10)).relocations
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].page_rva, 0x1000)
        self.assertEqual([entry.kind for entry in blocks[0].entries], [10, 10])
        self.assertEqual([entry.offset for entry in blocks[0].entries],
                         [0x10, 0x20])

    def test_pe32_higlow_entries(self):
        """kind 3 is the 32-bit form; kind 10 the 64-bit one.

        The prototype this is ported from only handled kind 3, which made the
        largest seed source silently empty on every x64 image.
        """
        from pydbg.pe import PE

        blocks = PE(build_reloc_image(0x10B, kind=3)).relocations
        self.assertEqual([entry.kind for entry in blocks[0].entries], [3, 3])

    def test_walks_every_block(self):
        """Control for the terminator test below: the walk really does follow
        one block to the next, so 'stopped at one block' there is the
        terminator's doing and not a walk that only ever reads the first."""
        from pydbg.pe import PE

        blocks = PE(build_reloc_image(pages=(0x1000, 0x2000))).relocations
        self.assertEqual([block.page_rva for block in blocks],
                         [0x1000, 0x2000])

    def test_terminator_block_ends_the_walk(self):
        """A real block planted past the zero block must not be reached."""
        from pydbg.pe import PE

        blocks = PE(build_reloc_image(
            pages=(0x1000,), block_after_terminator=True)).relocations
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].page_rva, 0x1000)

    def test_truncated_directory_stops_instead_of_raising(self):
        from pydbg.pe import PE

        blocks = PE(build_reloc_image(declared_size=10)).relocations
        self.assertEqual(blocks, [])

    def test_absent_directory_is_empty(self):
        from pydbg.pe import PE

        builder, _ = _base_image()
        self.assertEqual(PE(builder.build()).relocations, [])


class TestDebugDirectory(unittest.TestCase):

    def test_entry_fields(self):
        from pydbg.pe import PE

        entries = PE(build_debug_image()).debug_entries
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry.type, 2)          # IMAGE_DEBUG_TYPE_CODEVIEW
        self.assertEqual(entry.address_of_raw_data, RVA_TEXT)
        self.assertEqual(entry.time_date_stamp, 0x5A000000)

    def test_absent_directory_is_empty(self):
        from pydbg.pe import PE

        builder, _ = _base_image()
        self.assertEqual(PE(builder.build()).debug_entries, [])


class TestExceptionDirectory(unittest.TestCase):

    def test_runtime_function_ranges(self):
        """x64 function boundaries, straight from the loader's own table."""
        from pydbg.pe import PE

        entries = PE(build_pdata_image()).exception_entries
        self.assertEqual(len(entries), 2)
        self.assertEqual((entries[0].begin_rva, entries[0].end_rva),
                         (0x1000, 0x1050))
        self.assertEqual((entries[1].begin_rva, entries[1].end_rva),
                         (0x1050, 0x10A0))

    def test_zero_entry_terminates(self):
        from pydbg.pe import PE

        entries = PE(build_pdata_image(terminate=True)).exception_entries
        self.assertEqual(len(entries), 2)

    def test_absent_directory_is_empty(self):
        """A PE32 image has no .pdata, and that is not an error."""
        from pydbg.pe import PE

        builder, _ = _base_image(magic=0x10B)
        self.assertEqual(PE(builder.build()).exception_entries, [])


class TestRichHeader(unittest.TestCase):

    def test_decodes_with_the_stored_key(self):
        from pydbg.pe import PE

        data, key = build_rich_image()
        rich = PE(data).rich_header
        self.assertIsNotNone(rich)
        self.assertEqual(rich.xor_key, key)
        self.assertEqual([(e.comp_id, e.count) for e in rich.entries],
                         [(0x0101, 5), (0x0202, 3)])

    def test_absent_is_none(self):
        from pydbg.pe import PE

        builder, _ = _base_image()
        self.assertIsNone(PE(builder.build()).rich_header)


class TestLazyDirectories(unittest.TestCase):

    def test_parsed_once_and_remembered(self):
        """Late binding is the point, but it must not re-parse per access."""
        from pydbg.pe import PE

        pe = PE(build_debug_image())
        self.assertIs(pe.debug_entries, pe.debug_entries)

    def test_construction_does_not_parse_them(self):
        from pydbg.pe import PE

        pe = PE(build_debug_image())
        self.assertEqual(pe._cache, {})


class TestRealImageDirectories(unittest.TestCase):
    """End-to-end against a real x64 image.

    The synthetic fixtures prove the parsers read what they are told to; only
    a real image proves they read what a linker actually wrote. The kind-10
    assertion below is the one that matters most — it is the 64-bit relocation
    form, and the prototype this was ported from handled only the 32-bit
    kind 3, which silently emptied its largest seed source on every x64 image.
    """

    KERNEL32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                            "System32", "kernel32.dll")

    def setUp(self):
        if not os.path.exists(self.KERNEL32):
            self.skipTest(f"no system DLL at {self.KERNEL32}")
        from pydbg.pe import PE
        self.pe = PE.from_file(self.KERNEL32)

    def test_relocations_include_the_64_bit_kind(self):
        blocks = self.pe.relocations
        self.assertTrue(blocks, "an x64 system DLL has a .reloc")
        kinds = {entry.kind for block in blocks for entry in block.entries}
        self.assertIn(10, kinds, "IMAGE_REL_BASED_DIR64 missing on an x64 image")

    def test_exception_table_gives_function_ranges(self):
        entries = self.pe.exception_entries
        self.assertTrue(entries, "an x64 system DLL has .pdata")
        for entry in entries[:50]:
            self.assertLess(entry.begin_rva, entry.end_rva)
            self.assertLess(entry.end_rva, self.pe.optional_header.size_of_image)

    def test_debug_directory_has_a_codeview_entry(self):
        types = {entry.type for entry in self.pe.debug_entries}
        self.assertIn(2, types, "IMAGE_DEBUG_TYPE_CODEVIEW (the PDB) missing")


if __name__ == "__main__":
    unittest.main()
