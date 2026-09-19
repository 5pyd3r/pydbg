"""Tests for base-relative access tracing.

This is the half of structure recovery that can be stated honestly: "inside
this function, this register is used as a base at these offsets". Which
register holds an object cannot be decided statically, so the tests care as
much about what the trace *refuses* to claim — stack frames, indexed
addressing, `lea`, absolute addresses formed through a register — as about
what it reports.
"""

import struct
import unittest

from tests.pe_builder import PEBuilder

TEXT_RVA = 0x1000
IMAGE_BASE = 0x400000
TEXT_SIZE = 0x80


def build(code):
    text = bytearray(b"\x90" * TEXT_SIZE)
    text[0:len(code)] = code
    builder = PEBuilder(magic=0x10B, image_base=IMAGE_BASE,
                        entry_rva=TEXT_RVA)
    builder.add_section(".text", bytes(text), TEXT_RVA)
    return builder.build()


def analyze(code):
    from pydbg.analysis import analyze_bytes
    return analyze_bytes(build(code))


def mov_eax_from(offset, base=3):
    """mov eax, [reg + offset] — base 3 is ebx in capstone's x86 ids."""
    return b"\x8b\x43" + bytes([offset & 0xFF]) if base == 3 else None


class TestWhatIsRecorded(unittest.TestCase):

    def accesses(self, code):
        return analyze(code).accesses()

    def test_a_base_relative_read_is_recorded_with_its_offset_and_width(self):
        # mov eax, [ebx+0x18]  (8b 43 18)
        found = self.accesses(b"\x8b\x43\x18" + b"\xc3")
        self.assertEqual(len(found), 1)
        access = found[0]
        self.assertEqual(access.base_reg, "ebx")
        self.assertEqual(access.offset, 0x18)
        self.assertEqual(access.size, 4)
        self.assertFalse(access.is_write)

    def test_a_write_is_marked_as_one(self):
        # mov [ebx+0x18], eax  (89 43 18)
        found = self.accesses(b"\x89\x43\x18" + b"\xc3")
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].is_write)

    def test_the_width_follows_the_operand_size(self):
        # mov al, [ebx+0x10]  (8a 43 10) — a byte field
        found = self.accesses(b"\x8a\x43\x10" + b"\xc3")
        self.assertEqual(found[0].size, 1)

    def test_a_negative_displacement_is_kept_signed(self):
        # mov eax, [ebx-0x8]  (8b 43 f8)
        found = self.accesses(b"\x8b\x43\xf8" + b"\xc3")
        self.assertEqual(found[0].offset, -8)


class TestWhatIsRefused(unittest.TestCase):
    """The exclusions matter as much as the inclusions."""

    def accesses(self, code):
        return analyze(code).accesses()

    def test_stack_relative_accesses_are_not_structure_fields(self):
        """Every function has a frame; none of them is a structure.

        `[ebp-0x8]` is a local. Counting it would give every function a
        structure at frame pointer minus something.
        """
        # mov eax, [ebp-0x8]  (8b 45 f8)
        self.assertEqual(self.accesses(b"\x8b\x45\xf8" + b"\xc3"), ())

    def test_indexed_addressing_is_not_a_field_offset(self):
        """`[ebx + ecx*4 + disp]`'s displacement is a table base.

        Treating it as a field would invent a field at every switch statement.
        """
        # mov eax, [ebx + ecx*4 + 0x10]  (8b 44 8b 10)
        self.assertEqual(self.accesses(b"\x8b\x44\x8b\x10" + b"\xc3"), ())

    def test_lea_is_not_an_access(self):
        """Taking an address is not reading the thing at it.

        capstone marks lea's memory operand read, but no memory is touched;
        recording it would say a field is read where the code only took its
        address — a different fact, and often the more interesting one.
        """
        # lea eax, [ebx+0x18]  (8d 43 18)
        self.assertEqual(self.accesses(b"\x8d\x43\x18" + b"\xc3"), ())

    def test_an_absolute_address_formed_through_a_register_is_not_a_field(self):
        """`[eax + 0x400000]` is the image base, not a 4MB-wide structure."""
        # mov eax, [ebx+0x400000]  (8b 83 00 00 40 00)
        code = b"\x8b\x83" + struct.pack("<I", IMAGE_BASE) + b"\xc3"
        self.assertEqual(self.accesses(code), ())

    def test_a_rip_relative_access_has_no_base_register(self):
        """RIP is a base, but the displacement is relative, not a field."""
        # mov eax, [rip+disp] in a 32-bit image decodes as absolute, so use
        # the displacement form that has no base at all.
        # mov eax, dword ptr [0x402000] — an absolute operand, no base
        code = b"\xa1" + struct.pack("<I", IMAGE_BASE + 0x2000) + b"\xc3"
        self.assertEqual(self.accesses(code), ())


class TestProfiles(unittest.TestCase):

    def test_a_register_used_at_several_offsets_becomes_a_structure(self):
        code = (b"\x8b\x43\x18" + b"\x8b\x4b\x1c" + b"\x8b\x53\x20"
                + b"\xc3")
        result = analyze(code)
        found = result.structures()
        self.assertTrue(found)
        ((function, base), profile), = list(found.items())[:1]
        self.assertEqual(base, "ebx")
        self.assertEqual(function, TEXT_RVA)
        self.assertEqual(profile.offsets, [0x18, 0x1C, 0x20])

    def test_one_offset_is_not_a_structure(self):
        """A lone offset through a register is a global, not a layout."""
        result = analyze(b"\x8b\x43\x18" + b"\xc3")
        self.assertEqual(result.structures(), {})

    def test_a_field_that_is_called_through_is_a_function_pointer(self):
        """The one field kind this can identify outright.

        `call [ebx+0x18]` says the value at that offset is branched to, which
        is a function pointer and the thing a reader most wants marked.
        """
        code = (b"\x8b\x43\x18" + b"\x8b\x4b\x1c" + b"\x8b\x53\x20"
                + b"\xff\x53\x18" + b"\xc3")
        result = analyze(code)
        found = result.structures()
        self.assertTrue(found)
        profile = list(found.values())[0]
        self.assertTrue(profile.fields[0x18].called)
        self.assertEqual(profile.fields[0x18].kind, "function pointer")

    def test_reads_and_writes_are_counted_separately(self):
        # Two reads and a write of +0x18, plus two further offsets so the
        # register clears the structural threshold at all.
        code = (b"\x8b\x43\x18" + b"\x8b\x43\x18" + b"\x89\x43\x18"
                + b"\x8b\x4b\x1c" + b"\x8b\x53\x20" + b"\xc3")
        profile = list(analyze(code).structures().values())[0]
        use = profile.fields[0x18]
        self.assertEqual(use.reads, 2)
        self.assertEqual(use.writes, 1)

    def test_the_report_names_the_function_and_the_register(self):
        code = (b"\x8b\x43\x18" + b"\x8b\x4b\x1c" + b"\x8b\x53\x20"
                + b"\xc3")
        text = analyze(code).render_structures()
        self.assertIn("base ebx", text)
        self.assertIn("+0x0018", text)

    def test_a_result_without_records_can_still_be_traced(self):
        """Collection can be switched off; the replay path must still work."""
        from pydbg.analysis import SeedConfig, analyze_bytes
        code = b"\x8b\x43\x18" + b"\x8b\x4b\x1c" + b"\x8b\x53\x20" + b"\xc3"
        result = analyze_bytes(build(code),
                               config=SeedConfig(collect_accesses=False))
        self.assertIsNone(result.access_records)
        self.assertEqual(len(result.accesses()), 3)


class TestRealImageTraces(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        import os
        path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                            "System32", "kernel32.dll")
        if not os.path.exists(path):
            raise unittest.SkipTest(f"no system DLL at {path}")
        from pydbg.analysis import analyze_file
        cls.result = analyze_file(path)

    def setUp(self):
        if not hasattr(self.__class__, "result"):
            self.skipTest("no system DLL to analyse")

    def test_the_trace_comes_from_the_sweep_not_a_second_decode(self):
        """Asserted structurally, not by timing.

        The first version of this decoded the whole image again afterwards and
        took 84s against 30s for the analysis alone. That regression is
        invisible in the output, so it needs a guard — but a guard does not
        have to be a stopwatch. `access_records` being populated *is* the fast
        path: if collection were dropped, it would be None and every read
        would fall back to replaying the decode.
        """
        self.assertIsNotNone(
            self.result.access_records,
            "no records: collect_accesses defaulted off, or was removed")

    def test_traces_are_found_and_bounded(self):
        found = self.result.accesses()
        self.assertGreater(len(found), 100)
        # No access may claim a displacement beyond the image base.
        for access in found:
            self.assertLess(abs(access.offset), self.result.image.image_base)

    def test_stack_registers_do_not_appear_as_bases(self):
        bases = {access.base_reg for access in self.result.accesses()}
        self.assertFalse(bases & {"rsp", "rbp", "esp", "ebp"})

    def test_structural_profiles_are_produced(self):
        profiles = self.result.structures()
        self.assertGreater(len(profiles), 10)
        for (function, base), profile in profiles.items():
            self.assertNotIn(base, ("rsp", "rbp"))
            self.assertGreaterEqual(len(profile.fields), 3)
            self.assertTrue(function > 0)


if __name__ == "__main__":
    unittest.main()
