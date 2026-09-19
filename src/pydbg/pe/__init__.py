"""PE format parser package - three-layer architecture (Source/View/Parse)."""

from .types import (
    DosHeader, FileHeader, OptionalHeader, DataDirectory,
    SectionHeader, ExportEntry, ImportEntry,
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
    def from_source(cls, source, view=None):
        """Build from an arbitrary Source, and optionally an explicit View.

        The seam that lets a live process be parsed with the same code as a
        file: pass a Source positioned at the module base together with
        LoadedView, and every RVA resolves as a direct offset into it.

        'view' defaults to FileView over the parsed sections.
        """
        pe = cls.__new__(cls)
        pe._adopt(source, view)
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
    'Source', 'FileSource', 'BytesSource',
    'View', 'FileView', 'LoadedView',
    'PEParser',
]
