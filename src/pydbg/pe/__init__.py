"""PE format parser package - three-layer architecture (Source/View/Parse)."""

from .types import (
    DosHeader, FileHeader, OptionalHeader, DataDirectory,
    SectionHeader, ExportEntry, ImportEntry,
    RelocationEntry, RelocationBlock, TLSDirectory, DebugEntry,
    ExceptionEntry, RichHeader, RichHeaderEntry,
)
from .source import Source, FileSource, BytesSource
from .view import View, FileView, LoadedView
from .parser import PEParser


class PE:
    """PE format parser facade. Delegates to PEParser with Source+View."""

    def __init__(self, data: bytes):
        """Parse PE from raw bytes (backward-compatible)."""
        self._adopt(BytesSource(data), None)

    @classmethod
    def from_source(cls, source, view=None, va_base=None):
        """Build from an arbitrary Source, and optionally an explicit View.

        The seam that lets a live process be parsed with the same code as a
        file: pass a Source positioned at the module base together with
        LoadedView, and every RVA resolves as a direct offset into it.

        'view' defaults to FileView over the parsed sections. 'va_base' is
        where the addresses stored in the image (TLS callbacks) are anchored;
        it defaults to the optional header's ImageBase, which is right for a
        file, but a live module under ASLR sits elsewhere — pass that module's
        runtime base or every TLS callback lands outside the image.
        """
        pe = cls.__new__(cls)
        pe._adopt(source, view)
        if va_base is not None:
            pe._va_base = va_base
        return pe

    @classmethod
    def from_file(cls, path, lazy=False):
        """Parse PE from a file on disk.

        Reads the file into memory by default, so the handle is closed before
        returning while directory parsing stays possible afterwards — the two
        things the previous implementation could not have at once.

        lazy=True keeps the file open instead, for images too large to be worth
        slurping. The caller then owns that open handle and must close it.
        """
        if lazy:
            source = FileSource(path)
            try:
                return cls.from_source(source, None)
            except Exception:
                source.close()
                raise
        with open(path, 'rb') as handle:
            return cls(handle.read())

    def _adopt(self, source, view):
        """Parse the headers, sections and the two eager directories.

        The single construction path. PE.__init__ and PE.from_file used to
        each carry their own copy of this sequence, which meant every new
        directory had to be wired into both (and would eventually be wired into
        only one).
        """
        self._source = source
        self._cache = {}

        parser = PEParser(source, None)
        self.dos_header = parser.parse_dos_header()
        self.file_header, self.optional_header, sections_offset = (
            parser.parse_nt_headers(self.dos_header.e_lfanew))

        self.sections = parser.parse_sections(
            sections_offset, self.file_header.number_of_sections)

        self._view = view if view is not None else FileView(self.sections)
        self._parser = PEParser(source, self._view)

        dirs = self.optional_header.data_directories
        self.exports = self._parser.parse_exports(dirs)
        self.imports = self._parser.parse_imports(dirs, self.optional_header.magic)

        # What the image's stored addresses are relative to. Overridable via
        # from_source() for a live module loaded away from its preferred base.
        self._va_base = self.optional_header.image_base

    def _cached(self, key, factory):
        """Compute a lazy directory once and keep it.

        These are parsed on first use rather than at construction: most
        consumers want none of them, and a 30k-function .pdata is 360KB
        nobody asked for. A PE object is also expected to outlive the call
        that made it, so re-parsing on every access would be wasteful.
        """
        if key not in self._cache:
            self._cache[key] = factory()
        return self._cache[key]

    @property
    def relocations(self):
        """Base relocation blocks (data directory 5)."""
        return self._cached('relocations', lambda: self._parser.parse_relocations(
            self.optional_header.data_directories))

    @property
    def tls(self):
        """TLS directory (data directory 9), or None."""
        return self._cached('tls', lambda: self._parser.parse_tls(
            self.optional_header.data_directories,
            self.optional_header.magic, self._va_base))

    @property
    def debug_entries(self):
        """Debug directory records (data directory 6); type 2 carries the PDB."""
        return self._cached(
            'debug_entries',
            lambda: self._parser.parse_debug(self.optional_header.data_directories))

    @property
    def exception_entries(self):
        """RUNTIME_FUNCTION table (data directory 3) — x64 function boundaries."""
        return self._cached(
            'exception_entries',
            lambda: self._parser.parse_exception(
                self.optional_header.data_directories))

    @property
    def rich_header(self):
        """Decoded Rich header, or None when the image has none."""
        return self._cached(
            'rich_header',
            lambda: self._parser.parse_rich_header(self.dos_header.e_lfanew))

    @property
    def va_base(self):
        """What the image's stored addresses are relative to."""
        return self._va_base

    @property
    def source(self):
        return self._source

    @property
    def view(self):
        return self._view

    @property
    def image_base(self):
        """Preferred load address from the optional header.

        Not necessarily where a module actually sits: an ASLR'd image in a live
        process is at a different base, and callers comparing VAs against this
        would find every one of them out of range. Use the runtime base there.
        """
        return self.optional_header.image_base

    def rva_to_offset(self, rva):
        """Convert RVA to file offset (delegated to FileView)."""
        return self._view.rva_to_source_offset(rva)

    def read_rva(self, rva, size):
        """Bytes at 'rva', or None if that range is not fully available.

        None rather than a short slice or an exception: callers walking a data
        directory stop on it, and a truncated directory is an ordinary thing to
        meet rather than an error worth aborting the parse for.
        """
        offset = self._view.rva_to_source_offset(rva)
        if offset is None:
            return None
        return self._source.try_read(offset, size)


__all__ = [
    'PE',
    'DosHeader', 'FileHeader', 'OptionalHeader', 'DataDirectory',
    'SectionHeader', 'ExportEntry', 'ImportEntry',
    'RelocationEntry', 'RelocationBlock', 'TLSDirectory', 'DebugEntry',
    'ExceptionEntry', 'RichHeader', 'RichHeaderEntry',
    'Source', 'FileSource', 'BytesSource',
    'View', 'FileView', 'LoadedView',
    'PEParser',
]
