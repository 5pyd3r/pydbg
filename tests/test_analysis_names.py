"""Tests for naming and workspace persistence.

A name is only useful if it can be trusted and kept. So the tests care about
two things beyond "a name comes out": provenance is preserved rather than
flattened, and a workspace refuses to apply to the wrong binary — because
names attached to the wrong offsets read exactly like correct ones.
"""

import json
import os
import struct
import tempfile
import unittest

from tests.pe_builder import PEBuilder

TEXT_RVA = 0x1000
DATA_RVA = 0x2000
IMAGE_BASE = 0x400000
TEXT_SIZE = 0x40
FUNCTION_RVA = 0x1020


def build(code, data=b"\x00" * 0x10):
    text = bytearray(b"\x90" * TEXT_SIZE)
    text[0:len(code)] = code
    text[FUNCTION_RVA - TEXT_RVA] = 0xC3
    builder = PEBuilder(magic=0x10B, image_base=IMAGE_BASE,
                        entry_rva=TEXT_RVA)
    builder.add_section(".text", bytes(text), TEXT_RVA)
    builder.add_section(".data", data, DATA_RVA, 0xC0000040)
    return builder.build()


def analyze(code=None, data=b"\x00" * 0x10):
    from pydbg.analysis import analyze_bytes
    return analyze_bytes(build(code if code is not None else b"\xc3", data))


class TestNameTable(unittest.TestCase):

    def table(self):
        from pydbg.analysis.names import NameTable
        return NameTable()

    def test_a_made_up_label_does_not_overwrite_a_real_name(self):
        """The fallback pass runs over everything, so it must not win.

        `sub_401000` is this analysis saying it does not know; letting it
        replace an export would erase the only real evidence there was.
        """
        from pydbg.analysis.names import SOURCE_AUTO, SOURCE_EXPORT
        table = self.table()
        self.assertTrue(table.add(0x1000, "CreateFileW", SOURCE_EXPORT))
        self.assertFalse(table.add(0x1000, "sub_001000", SOURCE_AUTO))
        self.assertEqual(table.name_of(0x1000), "CreateFileW")

    def test_a_person_overrides_an_export(self):
        from pydbg.analysis.names import SOURCE_EXPORT, SOURCE_USER
        table = self.table()
        table.add(0x1000, "ExportedName", SOURCE_EXPORT)
        self.assertTrue(table.add(0x1000, "ActuallyTheParser", SOURCE_USER))
        self.assertEqual(table.name_of(0x1000), "ActuallyTheParser")

    def test_every_address_gets_a_stable_label(self):
        """Nothing may be left as a bare hex number.

        An analysis full of hex cannot be written about: "the function at
        0x401234" does not survive being quoted in a comment or compared
        between two runs.
        """
        table = self.table()
        self.assertEqual(table.label(0x401234), "loc_401234")
        table.add(0x401234, "WinMain")
        self.assertEqual(table.label(0x401234), "WinMain")

    def test_provenance_survives_a_round_trip(self):
        from pydbg.analysis.names import SOURCE_EXPORT, NameTable
        table = self.table()
        table.add(0x1000, "Thing", SOURCE_EXPORT)
        again = NameTable.from_dict(table.to_dict())
        self.assertEqual(again.get(0x1000).source, SOURCE_EXPORT)
        self.assertEqual(again.get(0x1000).text, "Thing")


class TestAutomaticNames(unittest.TestCase):

    def test_exported_names_are_recovered(self):
        """An export is the linker's own statement about an address."""
        from pydbg.analysis import analyze_bytes
        from tests.test_pe import build_pe_with_exports

        result = analyze_bytes(build_pe_with_exports())
        table = result.names()
        self.assertEqual(table.name_of(0x1000), "MyExport")
        self.assertEqual(table.get(0x1000).source, "export")

    def test_unnamed_function_starts_get_a_made_up_label(self):
        result = analyze()
        table = result.names()
        self.assertEqual(table.name_of(TEXT_RVA), f"sub_{TEXT_RVA:06x}")
        self.assertEqual(table.get(TEXT_RVA).source, "auto")

    def test_a_thunk_records_the_iat_slot_it_jumps_through(self):
        """The slot is the piece a name comes from, so it is kept.

        Finding the thunk is only half of naming it `CreateFileW`; without the
        slot there is nothing to look the import up by.

        The slot set is seeded directly rather than built from a fixture's
        import table, because the fixture format here has no way to declare
        imports — and what is under test is which thunks get recorded, not how
        the import table is parsed (test_pe covers that).
        """
        from pydbg.analysis import AnalyzedImage
        from pydbg.analysis.engine import StaticAnalyzer

        iat_rva = 0x1040
        text = bytearray(b"\x90" * TEXT_SIZE)
        # `ff 25` in 32-bit mode is `jmp dword ptr [abs32]` — an absolute
        # address, not RIP-relative (that encoding only exists in 64-bit).
        text[0:6] = b"\xff\x25" + struct.pack("<I", IMAGE_BASE + iat_rva)
        text[FUNCTION_RVA - TEXT_RVA] = 0xC3
        builder = PEBuilder(magic=0x10B, image_base=IMAGE_BASE,
                            entry_rva=TEXT_RVA)
        builder.add_section(".text", bytes(text), TEXT_RVA)
        builder.add_section(".idata", b"\x00" * 0x40, iat_rva, 0xC0000040)

        analyzer = StaticAnalyzer(AnalyzedImage.from_bytes(builder.build()))
        analyzer._iat_slots = {iat_rva}
        analyzer._enqueue(TEXT_RVA, confident=True)
        analyzer._sweep_from(TEXT_RVA)
        self.assertEqual(analyzer.import_thunks.get(TEXT_RVA), iat_rva)

    def test_import_slots_map_to_dll_bang_function(self):
        """The other half of naming a thunk: what the slot is for."""
        from pydbg.analysis import AnalyzedImage, import_names
        from tests.test_pe import build_pe_with_imports

        image = AnalyzedImage.from_bytes(build_pe_with_imports())
        slots = import_names(image)
        self.assertTrue(slots, "the fixture has an import table")
        for text in slots.values():
            self.assertIn("!", text)
            self.assertIn(".dll", text.split("!")[0])


class TestWorkspace(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.image_path = os.path.join(self.tmp, "target.exe")
        with open(self.image_path, "wb") as handle:
            handle.write(build(b"\xc3"))
        self.other_path = os.path.join(self.tmp, "other.exe")
        with open(self.other_path, "wb") as handle:
            handle.write(build(b"\xc3") + b"\x00" * 64)
        self.ws_path = os.path.join(self.tmp, "target.ws.json")

    def test_names_and_comments_survive_a_save_and_load(self):
        from pydbg.analysis import Workspace
        workspace = Workspace.for_image(self.image_path)
        workspace.name(0x1000, "WinMain")
        workspace.comment(0x1000, "entry, dispatches to the scanner")
        workspace.save(self.ws_path)

        again = Workspace.load(self.ws_path, self.image_path)
        self.assertEqual(again.label(0x1000), "WinMain")
        self.assertEqual(again.comment_of(0x1000),
                         "entry, dispatches to the scanner")

    def test_saving_twice_produces_the_same_file(self):
        """Sorted output, so two saves of the same work diff clean."""
        from pydbg.analysis import Workspace
        workspace = Workspace.for_image(self.image_path)
        for rva in (0x3000, 0x1000, 0x2000):
            workspace.name(rva, f"name_{rva:x}")
        workspace.save(self.ws_path)
        first = open(self.ws_path, encoding="utf-8").read()
        workspace.save(self.ws_path)
        self.assertEqual(first, open(self.ws_path, encoding="utf-8").read())

    def test_a_workspace_for_another_binary_is_refused(self):
        """The whole reason the check exists.

        Names attached to the wrong offsets are indistinguishable from correct
        ones, so applying them silently is worse than refusing.
        """
        from pydbg.analysis import Workspace, WorkspaceError
        workspace = Workspace.for_image(self.image_path)
        workspace.name(0x1000, "WinMain")
        workspace.save(self.ws_path)

        with self.assertRaises(WorkspaceError) as caught:
            Workspace.load(self.ws_path, self.other_path)
        self.assertIn("different image", str(caught.exception))

    def test_a_mismatch_can_be_accepted_deliberately(self):
        from pydbg.analysis import Workspace
        workspace = Workspace.for_image(self.image_path)
        workspace.name(0x1000, "WinMain")
        workspace.save(self.ws_path)

        loaded = Workspace.load(self.ws_path, self.other_path, strict=False)
        self.assertEqual(loaded.label(0x1000), "WinMain")

    def test_an_unversioned_or_future_file_is_refused(self):
        from pydbg.analysis import Workspace, WorkspaceError
        with open(self.ws_path, "w", encoding="utf-8") as handle:
            json.dump({"version": 99, "names": {}}, handle)
        with self.assertRaises(WorkspaceError):
            Workspace.load(self.ws_path)

    def test_a_workspace_without_an_image_is_refused_when_checked(self):
        from pydbg.analysis import Workspace, WorkspaceError
        with open(self.ws_path, "w", encoding="utf-8") as handle:
            json.dump({"version": 1, "names": {}}, handle)
        with self.assertRaises(WorkspaceError):
            Workspace.load(self.ws_path, self.image_path)

    def test_workspace_names_reach_the_result(self):
        """A supplied name wins over the one the analysis invented."""
        from pydbg.analysis import Workspace, analyze_file
        workspace = Workspace.for_image(self.image_path)
        workspace.name(TEXT_RVA, "WinMain")

        result = analyze_file(self.image_path)
        self.assertEqual(result.names().label(TEXT_RVA), f"sub_{TEXT_RVA:06x}")

        table = result.names(workspace)
        self.assertEqual(table.label(TEXT_RVA), "WinMain")
        self.assertEqual(table.get(TEXT_RVA).source, "user")


class TestRendering(unittest.TestCase):

    def test_the_names_report_shows_provenance(self):
        result = analyze()
        text = result.render_names(limit=5)
        self.assertIn("source", text)
        self.assertIn("auto", text)

    def test_the_function_listing_shows_names(self):
        result = analyze()
        text = result.render_functions(limit=3)
        self.assertIn("name", text)
        self.assertIn("sub_001000", text)

    def test_the_listing_annotates_comments_and_names(self):
        from pydbg.analysis import Workspace
        result = analyze()
        workspace = Workspace()
        workspace.name(TEXT_RVA, "WinMain")
        workspace.comment(TEXT_RVA, "starts here")
        text = result.render_listing(TEXT_RVA, 8, workspace=workspace)
        self.assertIn("WinMain", text)
        self.assertIn("starts here", text)


if __name__ == "__main__":
    unittest.main()
