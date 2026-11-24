"""ProcessSource: an unreadable page is "no data there", not a failed analysis.

A live module is not one contiguous readable blob. Pages go uncommitted or
guarded — a packed image's stub, a dump in progress, a module being patched —
and everything around them still parses. `pe.Source` defines that case as a
ValueError: `try_read` turns it into None and every directory walk reads None as
"nothing more here". ProcessSource.read let MemoryManager's MemError out
instead, so the promise in its own docstring was false and the first hole
aborted the whole parse.

The tests pin the promise at the seam that was broken (read / try_read) and at
the two calls a user makes: PE.from_source over a holey module, and
analyze_process.
"""

import unittest
from types import SimpleNamespace
from unittest import mock

from pydbg.analysis.process_source import ProcessSource
from pydbg.exceptions import MemError
from pydbg.pe import PE
from pydbg.pe.view import LoadedView
from tests.pe_builder import PEBuilder, build_loaded_image_with_one_import

# Where the module happens to be loaded: deliberately not the image's preferred
# ImageBase, the way ASLR makes it differ.
BASE = 0x180000000
IMAGE_BASE = 0x140000000

HOLE_RVA = 0x1008
HOLE_SIZE = 8


def build_code_module():
    """A PE32+ image with 0x20 bytes of nops at .text rva 0x1000.

    Loaded layout (PEBuilder writes raw offset == RVA), so LoadedView reads it
    exactly as a live module is read.
    """
    builder = PEBuilder(magic=0x20B, image_base=IMAGE_BASE, entry_rva=0x1000)
    builder.add_section(".text", b"\x90" * 0x20, 0x1000)
    return builder.build()


class FakeMemory:
    """Serve a module's bytes the way MemoryManager.read serves them.

    `holes` are absolute VA ranges the target refuses; a read that touches one
    raises MemError, which is what ReadProcessMemory produces for a page that is
    not committed. Reads outside the module fail the same way, because the
    target has nothing mapped there either.
    """

    def __init__(self, data, base, holes=()):
        self.data = bytes(data)
        self.base = base
        self.holes = tuple(holes)

    def read(self, addr, size):
        end = addr + size
        for low, high in self.holes:
            if addr < high and low < end:
                raise MemError(
                    f"ReadProcessMemory at 0x{addr:X}: page is not committed")
        offset = addr - self.base
        if offset < 0 or offset + size > len(self.data):
            raise MemError(
                f"ReadProcessMemory at 0x{addr:X}: outside the module")
        return self.data[offset:offset + size]

    def source(self, size, session=None):
        return ProcessSource(session or SimpleNamespace(pid=4242), self.base,
                             size=size, reader=self.read)


def extension_available():
    """True when the Windows extension is built, for the live-memory path."""
    try:
        from pydbg import _pydbg  # noqa: F401
    except ImportError:
        return False
    return True


class TestUnreadablePageIsNotAFailure(unittest.TestCase):
    """The Source contract, observed through the methods callers use."""

    def setUp(self):
        self.image = build_code_module()
        self.memory = FakeMemory(
            self.image, BASE,
            holes=[(BASE + HOLE_RVA, BASE + HOLE_RVA + HOLE_SIZE)])

    def test_try_read_returns_none_for_an_unreadable_page(self):
        source = self.memory.source(len(self.image))

        # Readable bytes still come back...
        self.assertEqual(source.try_read(0, 2), b"MZ")
        # ...and the hole is "nothing more here", not an exception.
        self.assertIsNone(source.try_read(HOLE_RVA, 4))

    def test_read_translates_the_memory_error_into_the_source_contract(self):
        source = self.memory.source(len(self.image))

        with self.assertRaises(ValueError) as caught:
            source.read(HOLE_RVA, 4)

        self.assertNotIsInstance(caught.exception, MemError)
        # The reason survives, so a caller that catches our error can still
        # report why the range was unavailable.
        self.assertIn("ReadProcessMemory", str(caught.exception))

    def test_oserror_is_left_alone(self):
        """The translation is for PydbgError only; try_read already owns OSError."""
        def unreadable(addr, size):
            raise OSError("ReadProcessMemory failed")

        source = ProcessSource(SimpleNamespace(pid=4242), BASE,
                               size=len(self.image), reader=unreadable)

        with self.assertRaises(OSError):
            source.read(0, 2)
        self.assertIsNone(source.try_read(0, 2))


class TestParsingAHoleyModule(unittest.TestCase):
    """A directory behind a hole is absent; everything else still parses."""

    def test_pe_from_source_returns_the_parseable_parts(self):
        image, _iat_rva = build_loaded_image_with_one_import(
            image_base=IMAGE_BASE)
        # The import descriptor is the whole of 0x2000..0x2014; the .rdata
        # around it, and the whole .text, stay readable.
        memory = FakeMemory(image, BASE,
                            holes=[(BASE + 0x2000, BASE + 0x2014)])

        pe = PE.from_source(memory.source(len(image)), LoadedView(), va_base=BASE)

        self.assertEqual([section.name for section in pe.sections],
                         [".text", ".rdata"])
        self.assertEqual(pe.imports, [])
        self.assertEqual(pe.va_base, BASE)


class TestAnalyzeProcessWithHoles(unittest.TestCase):
    """The end-to-end claim: a hole degrades the result instead of aborting it."""

    def test_a_hole_in_the_code_section_yields_a_partial_result(self):
        if not extension_available():
            self.skipTest(
                "optional dependency: the _pydbg extension is not built")
        from pydbg.analysis import analyze_process
        from pydbg.memory.manager import MemoryManager

        image = build_code_module()
        memory = FakeMemory(
            image, BASE,
            holes=[(BASE + HOLE_RVA, BASE + HOLE_RVA + HOLE_SIZE)])
        session = SimpleNamespace(pid=4242, process_handle=0)

        def read(manager, addr, size):
            return memory.read(addr, size)

        # analyze_process builds its own ProcessSource, so the fake memory goes
        # in where MemoryManager.read would be; everything above it is real.
        with mock.patch.object(MemoryManager, "read", new=read):
            result = analyze_process(session, BASE, module_size=len(image))

        self.assertGreater(result.stats.insns, 0, "readable code was dropped")
        self.assertIn(HOLE_RVA, result.undecodable)
        self.assertEqual(result.image.image_base, BASE)


if __name__ == "__main__":
    unittest.main()
