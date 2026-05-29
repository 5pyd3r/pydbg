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
        from .source import BytesSource
        from .view import FileView
        from .parser import PEParser

        self._source = BytesSource(data)
        self._parser = PEParser(self._source, None)

        self.dos_header = self._parser.parse_dos_header()
        e_lfanew = self.dos_header.e_lfanew
        self.file_header, self.optional_header, sections_offset = (
            self._parser.parse_nt_headers(e_lfanew))

        data_dirs = self.optional_header.data_directories
        magic = self.optional_header.magic

        self.sections = self._parser.parse_sections(sections_offset, self.file_header.number_of_sections)
        self._view = FileView(self.sections)
        self._parser = PEParser(self._source, self._view)

        self.exports = self._parser.parse_exports(data_dirs)
        self.imports = self._parser.parse_imports(data_dirs, magic)

    def rva_to_offset(self, rva):
        """Convert RVA to file offset (delegated to FileView)."""
        return self._view.rva_to_source_offset(rva)

    @staticmethod
    def from_file(path):
        """Parse PE from a file on disk."""
        from .source import FileSource
        from .view import FileView
        from .parser import PEParser

        source = FileSource(path)
        parser = PEParser(source, None)

        dos = parser.parse_dos_header()
        file_hdr, opt_hdr, sections_offset = parser.parse_nt_headers(dos.e_lfanew)

        data_dirs = opt_hdr.data_directories
        magic = opt_hdr.magic

        sections = parser.parse_sections(sections_offset, file_hdr.number_of_sections)
        view = FileView(sections)
        parser = PEParser(source, view)

        pe = PE.__new__(PE)
        pe._source = source
        pe._parser = parser
        pe._view = view
        pe.dos_header = dos
        pe.file_header = file_hdr
        pe.optional_header = opt_hdr
        pe.sections = sections
        pe.exports = parser.parse_exports(data_dirs)
        pe.imports = parser.parse_imports(data_dirs, magic)
        return pe


__all__ = [
    'PE',
    'DosHeader', 'FileHeader', 'OptionalHeader', 'DataDirectory',
    'SectionHeader', 'ExportEntry', 'ImportEntry',
    'Source', 'FileSource', 'BytesSource',
    'View', 'FileView', 'LoadedView',
    'PEParser',
]
