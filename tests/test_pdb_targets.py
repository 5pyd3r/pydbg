"""The C and C++ targets meson builds with a PDB (spec §10.6(8)).

Every Phase 5 claim about names and types rests on a real MSVC PDB, so these
tests do not synthesise one: they read the paths meson puts into the test
environment and inspect the artefacts on disk. What is being checked is the
pairing, not either file alone — an image built with `/DEBUG` must carry a
CodeView RSDS record naming the `.pdb` that sits next to it, because a reader
handed a PDB the image does not point at would be testing a file no symbol
lookup could ever use.

When the targets were not built the tests skip with `target not built:` and
name the meson command, so a source-only checkout stays green without letting
the coverage go quiet.
"""

import os
import unittest

from pydbg.pe import PE

# A PDB 7.0 file begins with this MSF superblock magic. A truncated or bogus
# file passes an isfile() check but not this one.
_MSF_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"

_BUILD_COMMAND = "meson compile -C build pdb_target pdb_target_cpp"


class _PdbTargetChecks:
    """The checks every PDB target makes; subclasses only name its paths.

    Deliberately not a TestCase: the two subclasses are the collected tests,
    and keeping the base out of collection stops it running without paths.
    """

    LABEL = ""          # "C" or "C++", only used in skip/assert messages
    IMAGE_ENV = ""      # env var holding the executable meson built
    PDB_ENV = ""        # env var holding the .pdb the linker wrote

    def _paths(self):
        """Return (image, pdb), or skip naming what has to be built."""
        image = os.environ.get(self.IMAGE_ENV)
        pdb = os.environ.get(self.PDB_ENV)
        for name, value in ((self.IMAGE_ENV, image), (self.PDB_ENV, pdb)):
            if not value:
                self.skipTest(
                    f"target not built: {name} unset ({self.LABEL} target); "
                    f"run: {_BUILD_COMMAND}")
        for name, value in ((self.IMAGE_ENV, image), (self.PDB_ENV, pdb)):
            if not os.path.isfile(value):
                self.skipTest(
                    f"target not built: {value} missing (from {name}); "
                    f"run: {_BUILD_COMMAND}")
        return image, pdb

    def test_pdb_sits_next_to_the_image(self):
        """`/DEBUG` writes the PDB beside the binary; that is where it is found.

        dbghelp can be pointed elsewhere, but the default pairing is what the
        rest of the suite relies on, and a PDB in another directory is a
        different (harder to explain) situation.
        """
        image, pdb = self._paths()
        self.assertEqual(
            os.path.dirname(os.path.abspath(image)),
            os.path.dirname(os.path.abspath(pdb)),
            f"{self.LABEL} PDB is not in the image's directory")

    def test_pdb_is_an_msf_file(self):
        """The artefact is really a PDB, not an empty or placeholder file."""
        _, pdb = self._paths()
        with open(pdb, "rb") as handle:
            magic = handle.read(len(_MSF_MAGIC))
        self.assertEqual(magic, _MSF_MAGIC, f"{pdb} is not a PDB 7.0 file")
        self.assertGreater(os.path.getsize(pdb), len(_MSF_MAGIC),
                           f"{pdb} holds no MSF data after its header")

    def test_image_codeview_names_that_pdb(self):
        """The RSDS record is the link between image and PDB; it must agree."""
        image, pdb = self._paths()
        entries = PE.from_file(image).codeview_entries
        self.assertTrue(entries,
                        f"{image} has no decodable CodeView record")
        rsds = [entry for entry in entries if entry.signature == "RSDS"]
        self.assertTrue(
            rsds,
            f"{image} has no RSDS record "
            f"(found {[entry.signature for entry in entries]})")
        named = [os.path.basename(entry.pdb_path) for entry in rsds]
        self.assertIn(
            os.path.basename(pdb), named,
            f"{image} points at {named}, not {os.path.basename(pdb)}")


class TestPdbTargetC(_PdbTargetChecks, unittest.TestCase):
    """The plain-C target: exports, a static function, structs with bitfields."""

    LABEL = "C"
    IMAGE_ENV = "TEST_PDB_TARGET_PATH"
    PDB_ENV = "TEST_PDB_PATH"


class TestPdbTargetCpp(_PdbTargetChecks, unittest.TestCase):
    """The C++ target: a vftable and decorated names, i.e. a different PDB."""

    LABEL = "C++"
    IMAGE_ENV = "TEST_PDB_CPP_TARGET_PATH"
    PDB_ENV = "TEST_PDB_CPP_PDB_PATH"
