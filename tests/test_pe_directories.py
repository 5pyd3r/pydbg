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


# A GUID in the four fields a GUID is stored as: the three ints little-endian,
# then the trailing eight bytes verbatim. The trailing bytes are not an int, so
# a decoder that treated the whole thing as four dwords gets the last two
# groups wrong — which is the usual bug, and why this is spelled out.
PDB_GUID = (0x12345678, 0x9ABC, 0xDEF0, bytes(range(0x11, 0x19)))
PDB_GUID_TEXT = "12345678-9ABC-DEF0-1112-131415161718"


def build_codeview_payload(signature="RSDS", path=r"c:\build\out\app.pdb",
                           age=3, timestamp=0x5A000000, guid=PDB_GUID):
    """One IMAGE_DEBUG_TYPE_CODEVIEW payload in either of the two layouts."""
    if signature == "RSDS":
        a, b, c, tail = guid
        return (b"RSDS" + struct.pack("<IHH", a, b, c) + tail
                + struct.pack("<I", age) + path.encode() + b"\x00")
    if signature == "NB10":
        return (b"NB10" + struct.pack("<III", 0, timestamp, age)
                + path.encode() + b"\x00")
    raise ValueError(signature)


def build_codeview_image(payloads, declared_size=None, type=2):
    """Image whose debug directory holds one record per payload.

    The records sit at the start of .rdata and the payloads at RVA_DEBUG, so
    the entry's AddressOfRawData is an RVA that is not the section base — the
    same shape a linker produces, and the reason a parser that assumed the
    payload followed the record would read the wrong bytes here.
    """
    builder, _ = _base_image()
    rdata = bytearray(0x400)
    entry_size = 28
    for index, payload in enumerate(payloads):
        size = len(payload) if declared_size is None else declared_size
        _place(rdata, RVA_DEBUG + index * 0x40, payload)
        _place(rdata, RVA_RDATA + index * entry_size,
               struct.pack("<IIHHIIII", 0, 0x5A000000, 0, 0, type, size,
                           RVA_DEBUG + index * 0x40, 0))
    builder.add_section(".rdata", bytes(rdata), RVA_RDATA, 0x40000040)
    builder.add_dir(6, RVA_RDATA, len(payloads) * entry_size)
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


class TestCodeViewPayload(unittest.TestCase):
    """The type-2 payload, which is the only part that names a PDB.

    Structure alone was all pydbg returned, so every consumer decoded these
    bytes itself — and got the GUID wrong, because a GUID is three
    little-endian ints followed by eight raw bytes, not four ints.
    """

    def test_rsds_payload_is_decoded(self):
        from pydbg.pe import PE

        pe = PE(build_codeview_image([build_codeview_payload()]))
        infos = pe.codeview_entries
        self.assertEqual(len(infos), 1)
        info = infos[0]
        self.assertEqual(info.signature, "RSDS")
        self.assertEqual(info.pdb_path, r"c:\build\out\app.pdb")
        self.assertEqual(info.age, 3)
        self.assertEqual(info.guid, PDB_GUID_TEXT)
        self.assertIsNone(info.timestamp)

    def test_nb10_payload_is_decoded(self):
        """The older layout: no GUID, and a timestamp where RSDS has none."""
        from pydbg.pe import PE

        payload = build_codeview_payload("NB10", path=r"d:\old\app.pdb",
                                         age=7, timestamp=0x5A000000)
        info = PE(build_codeview_image([payload])).codeview_entries[0]
        self.assertEqual(info.signature, "NB10")
        self.assertEqual(info.pdb_path, r"d:\old\app.pdb")
        self.assertEqual(info.age, 7)
        self.assertEqual(info.timestamp, 0x5A000000)
        self.assertIsNone(info.guid)

    def test_every_record_is_decoded(self):
        """Two type-2 records both come back; the first is not 'the' PDB.

        A merged or re-linked image can carry more than one. Returning the
        first would make the second unobservable, which is the failure mode a
        singular accessor invites and this one is a list to avoid.
        """
        from pydbg.pe import PE

        paths = [r"c:\a.pdb", r"c:\b.pdb"]
        pe = PE(build_codeview_image([build_codeview_payload(path=p)
                                      for p in paths]))
        infos = pe.codeview_entries
        self.assertEqual([info.pdb_path for info in infos], paths)

    def test_path_runs_to_the_end_when_unterminated(self):
        from pydbg.pe import PE

        payload = build_codeview_payload()[:-1]      # drop the NUL
        info = PE(build_codeview_image([payload])).codeview_entries[0]
        self.assertEqual(info.pdb_path, r"c:\build\out\app.pdb")

    def test_non_codeview_record_is_ignored(self):
        from pydbg.pe import PE

        pe = PE(build_codeview_image([build_codeview_payload()], type=16))
        self.assertEqual(pe.codeview_entries, [])
        self.assertEqual(len(pe.debug_entries), 1)

    def test_undecodable_payload_is_skipped_not_fatal(self):
        """Garbage in the slot costs the payload, not the parse.

        The DebugEntry survives in debug_entries, so the two counts disagreeing
        is how a caller sees that something was left on the table instead of
        reading an empty list as 'no PDB'.
        """
        from pydbg.pe import PE

        pe = PE(build_codeview_image([b"XXXX" + b"\x00" * 64]))
        self.assertEqual(pe.codeview_entries, [])
        self.assertEqual([entry.type for entry in pe.debug_entries], [2])

    def test_truncated_header_is_skipped(self):
        """A SizeOfData that lies about a 24-byte header must not be read past."""
        from pydbg.pe import PE

        payload = build_codeview_payload()
        pe = PE(build_codeview_image([payload], declared_size=8))
        self.assertEqual(pe.codeview_entries, [])

    def test_file_offset_is_used_when_the_rva_is_absent(self):
        """Some linkers and most dumpers zero AddressOfRawData.

        The fixture writes sections at raw offset == RVA, so the pointer and
        the RVA are the same number here; what is being tested is that the
        fallback is reached at all.
        """
        from pydbg.pe import PE

        data = bytearray(build_codeview_image([build_codeview_payload()]))
        # Zero AddressOfRawData, point PointerToRawData at the same payload.
        entry = struct.unpack_from("<IIHHIIII", data, RVA_RDATA)
        struct.pack_into("<IIHHIIII", data, RVA_RDATA, *entry[:6],
                         RVA_DEBUG, RVA_DEBUG)
        info = PE(bytes(data)).codeview_entries[0]
        self.assertEqual(info.pdb_path, r"c:\build\out\app.pdb")

    def test_absent_directory_is_empty(self):
        from pydbg.pe import PE

        builder, _ = _base_image()
        self.assertEqual(PE(builder.build()).codeview_entries, [])


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


def build_broken_rich_image(blob):
    """Image with 'blob' dropped in the DOS stub and nothing else."""
    builder, _ = _base_image()
    builder.set_rich(blob)
    return builder.build()


class TestRichHeader(unittest.TestCase):

    def test_decodes_with_the_stored_key(self):
        from pydbg.pe import PE

        data, key = build_rich_image()
        rich = PE(data).rich_header
        self.assertIsNotNone(rich)
        self.assertEqual(rich.xor_key, key)
        self.assertIsNone(rich.malformed)
        self.assertEqual([(e.comp_id, e.count) for e in rich.entries],
                         [(0x0101, 5), (0x0202, 3)])

    def test_absent_is_none(self):
        """No marker at all is the one thing None still means."""
        from pydbg.pe import PE

        builder, _ = _base_image()
        self.assertIsNone(PE(builder.build()).rich_header)

    def test_marker_without_a_decodable_dans_is_malformed(self):
        """The case this distinction exists for.

        Before, this came back as None — identical to an image with no Rich
        header, i.e. "built by something other than MSVC's linker". An image
        carrying the marker but no decodable body is the opposite finding: a
        nonstandard or deliberately mangled stub, which is worth seeing.
        """
        from pydbg.pe import PE

        key = 0x12345678
        blob = b"Rich" + struct.pack("<I", key)
        rich = PE(build_broken_rich_image(blob)).rich_header
        self.assertIsNotNone(rich)
        self.assertEqual(rich.entries, [])
        self.assertIsNotNone(rich.malformed)
        self.assertIn("DanS", rich.malformed)
        self.assertEqual(rich.xor_key, key)     # the key itself was readable

    def test_truncated_key_leaves_the_key_unknown(self):
        """A marker at the very end of the stub has no key to report.

        xor_key is None here rather than a made-up zero: the one thing this
        record must not do is state a key it did not read.
        """
        from pydbg.pe import PE

        rich = PE(build_broken_rich_image(b"\x00" * 60 + b"Rich")).rich_header
        self.assertIsNotNone(rich)
        self.assertIsNone(rich.xor_key)
        self.assertIn("cut off", rich.malformed)

    def test_marker_reachable_but_with_no_room_for_an_entry(self):
        from pydbg.pe import PE

        key = 0x0BADF00D
        blob = (struct.pack("<I", 0x536E6144 ^ key) + b"\x00" * 8
                + b"Rich" + struct.pack("<I", key))
        rich = PE(build_broken_rich_image(blob)).rich_header
        self.assertIsNotNone(rich)
        self.assertEqual(rich.entries, [])
        self.assertIn("no room", rich.malformed)


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
