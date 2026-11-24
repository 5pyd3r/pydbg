"""dump_module / dump_region: a memory range plus a gap side table.

The fake debugger below stands in for a live target: it answers the two
memory queries the dump policy is built on (read_memory_safe and
enum_regions), so the tests observe the public DumpedImage without needing the
Cython extension. The live smoke test at the bottom is the only one that does.
"""

import unittest
from types import SimpleNamespace

from pydbg.dump import DumpError, Gap, dump_module, dump_region

try:
    from pydbg import _pydbg  # noqa: F401

    _has_cython = True
except ImportError:
    _has_cython = False


MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000


def _region(base, size, *, state=MEM_COMMIT, protect=0x04):
    """One VirtualQueryEx-shaped region dict."""
    return {
        'base_address': base,
        'allocation_base': base,
        'allocation_protect': protect,
        'region_size': size,
        'state': state,
        'protect': protect,
        'type': 0x20000,
    }


class FakeDebugger:
    """Answers the two reads dump_module/dump_region are allowed to make.

    read_memory_safe mirrors the real contract: it always returns 'size'
    bytes, zero-filling anything in 'unreadable' and reporting it as a gap
    with win32_error 0 — the same shape an uncommitted page produces, which is
    why the gap *reason* cannot come from here.
    """

    def __init__(self, image=b'', base=0x140000000, regions=None,
                 modules=None, unreadable=()):
        self.image = bytes(image)
        self.base = base
        self.regions = list(regions) if regions is not None else [
            _region(base, max(len(self.image), 0x1000))]
        self.modules = modules
        self.unreadable = list(unreadable)
        self.reads = []

    def read_memory_safe(self, addr, size, pid=None, max_bytes=None):
        self.reads.append((addr, size))
        data = bytearray(size)
        lo = max(addr, self.base)
        hi = min(addr + size, self.base + len(self.image))
        if lo < hi:
            data[lo - addr:hi - addr] = self.image[lo - self.base:hi - self.base]
        gaps = []
        for failed_addr, failed_size in self.unreadable:
            lo = max(addr, failed_addr)
            hi = min(addr + size, failed_addr + failed_size)
            if lo < hi:
                data[lo - addr:hi - addr] = b'\x00' * (hi - lo)
                gaps.append((lo, hi - lo, 0))
        gaps.sort()
        return SimpleNamespace(
            address=addr, size=size, data=bytes(data), gaps=gaps)

    def enum_regions(self, pid=None, start=0, max_addr=0):
        return [dict(region) for region in self.regions]

    def enum_modules(self, pid=None):
        if self.modules is not None:
            return [dict(module) for module in self.modules]
        return [{'base_address': self.base, 'size': len(self.image),
                 'name': 'main.exe'}]


def _pattern(size):
    return bytes((i * 7 + 3) & 0xFF for i in range(size))


class TestDumpRegion(unittest.TestCase):

    def test_a_fully_readable_region_comes_back_whole(self):
        base, size = 0x20000, 0x3000
        image = _pattern(size)
        dbg = FakeDebugger(image=image, base=base,
                           regions=[_region(base, size)])

        dumped = dump_region(dbg, base, size, name='scratch')

        self.assertEqual(dumped.data, image)
        self.assertEqual(dumped.gaps, ())
        self.assertTrue(dumped.complete)
        self.assertEqual(dumped.rva_base, base)
        self.assertEqual(dumped.image_base, base)
        self.assertEqual(dumped.size_of_image, size)
        self.assertEqual(dumped.entry_point_rva, 0)
        self.assertEqual(dumped.load_delta, 0)
        self.assertEqual(dumped.module_name, 'scratch')

    def test_a_free_region_in_the_middle_is_zero_filled_and_named(self):
        base, size = 0x10000, 0x3000
        image = _pattern(size)
        dbg = FakeDebugger(image=image, base=base, regions=[
            _region(base, 0x1000),
            _region(base + 0x1000, 0x1000, state=MEM_FREE, protect=0x01),
            _region(base + 0x2000, 0x1000),
        ])

        dumped = dump_region(dbg, base, size)

        self.assertEqual(dumped.data[:0x1000], image[:0x1000])
        self.assertEqual(dumped.data[0x1000:0x2000], b'\x00' * 0x1000)
        self.assertEqual(dumped.data[0x2000:], image[0x2000:])
        self.assertEqual(dumped.gaps, (Gap(0x1000, 0x1000, 'free'),))
        self.assertFalse(dumped.complete)
        self.assertNotIn((base + 0x1000, 0x1000), dbg.reads)

    def test_a_committed_page_that_cannot_be_read_names_its_protect(self):
        """The win32_error is 0 here, so the protect has to supply the reason."""
        base, size = 0x30000, 0x2000
        image = _pattern(size)
        dbg = FakeDebugger(
            image=image, base=base,
            regions=[_region(base, size, protect=0x0)],
            unreadable=[(base + 0x1000, 0x1000)])

        dumped = dump_region(dbg, base, size)

        self.assertEqual(dumped.data[:0x1000], image[:0x1000])
        self.assertEqual(dumped.data[0x1000:], b'\x00' * 0x1000)
        self.assertEqual(
            dumped.gaps,
            (Gap(0x1000, 0x1000, 'unreadable:protect=0x0'),))
        self.assertEqual(dbg.reads, [(base, size)])


class TestDumpModule(unittest.TestCase):

    def _builder(self, entry_rva=0x1234):
        from tests.pe_builder import PEBuilder

        builder = PEBuilder(image_base=0x140000000, entry_rva=entry_rva)
        builder.add_section('.text', b'\x90' * 0x100, 0x1000)
        return builder

    def test_the_header_decides_the_extent_and_the_entry_point(self):
        image = self._builder(entry_rva=0x1234).build().ljust(0x8000, b'\x00')
        base = 0x7FF6_0000_0000
        dbg = FakeDebugger(image=image, base=base, modules=[{
            'base_address': base,
            'size': 0x1000,          # stale hint; the header says 0x8000
            'name': r'C:\target\simple_target.exe',
        }])

        dumped = dump_module(dbg)

        self.assertEqual(len(dumped.data), 0x8000)   # header SizeOfImage
        self.assertEqual(dumped.data, image)
        self.assertEqual(dumped.data[:2], b'MZ')
        self.assertEqual(dumped.gaps, ())
        self.assertTrue(dumped.complete)
        self.assertEqual(dumped.rva_base, base)
        self.assertEqual(dumped.image_base, base)
        self.assertEqual(dumped.entry_point_rva, 0x1234)
        self.assertEqual(dumped.load_delta, base - 0x140000000)
        self.assertEqual(dumped.module_name, r'C:\target\simple_target.exe')

    def test_a_base_size_tuple_is_an_accepted_module(self):
        image = self._builder().build().ljust(0x8000, b'\x00')
        base = 0x400000
        dbg = FakeDebugger(image=image, base=base)

        dumped = dump_module(dbg, (base, 0x8000))

        self.assertIsNone(dumped.module_name)
        self.assertEqual(len(dumped.data), 0x8000)
        self.assertEqual(dumped.data, image)

    def test_bytes_that_are_not_a_pe_are_refused_with_a_reason(self):
        base = 0x50000000
        dbg = FakeDebugger(image=b'\x00' * 0x1000, base=base)

        with self.assertRaisesRegex(DumpError, 'not a PE image'):
            dump_module(dbg, (base, 0x1000))

    def test_no_module_to_dump_is_a_dump_error(self):
        dbg = FakeDebugger(image=b'', modules=[])

        with self.assertRaisesRegex(DumpError, 'no loaded module'):
            dump_module(dbg)


class TestDumpModuleLive(unittest.TestCase):
    """Against the real target: zero-filled pages are the only difference."""

    @unittest.skipUnless(_has_cython, 'optional dependency: Cython extension')
    def test_dump_the_main_module_of_the_simple_target(self):
        from pydbg.pe import PE
        from tests import TEST_TARGET_PATH
        from tests.helpers import create_debugger, entry_point, module_base, teardown

        dbg, pid, tid = create_debugger()
        try:
            base = module_base(dbg)
            dumped = dump_module(dbg)

            self.assertEqual(len(dumped.data), dumped.size_of_image)
            self.assertEqual(dumped.data[:2], b'MZ')
            self.assertEqual(dumped.rva_base, base)
            # The live entry point must agree with both the dump header and a
            # fresh parse of the target file.
            live_rva = entry_point(dbg) - base
            file_rva = PE.from_file(TEST_TARGET_PATH).optional_header.entry_point_rva
            self.assertEqual(dumped.entry_point_rva, live_rva)
            self.assertEqual(dumped.entry_point_rva, file_rva)
            self.assertEqual(dumped.size_of_image,
                             PE.from_file(TEST_TARGET_PATH).optional_header.size_of_image)
        finally:
            teardown(dbg)
