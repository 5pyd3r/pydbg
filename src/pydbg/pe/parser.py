"""Parse layer — PE binary structure parser."""

import struct

from .types import (
    DosHeader, FileHeader, OptionalHeader, DataDirectory,
    SectionHeader, ExportEntry, ImportEntry,
)
from .view import View


class PEParser:
    """Parse PE binary structures from a byte source."""

    def __init__(self, source, view: View):
        self._src = source
        self._view = view

    def parse_dos_header(self) -> DosHeader:
        data = self._src.read(0, 64)
        magic = struct.unpack_from('<2s', data, 0)[0]
        if magic != b'MZ':
            raise ValueError(f"Invalid DOS signature: {magic!r}")
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        return DosHeader(e_magic=0x5A4D, e_lfanew=e_lfanew)

    def parse_nt_headers(self, e_lfanew: int) -> tuple[FileHeader, OptionalHeader, int]:
        sig = struct.unpack_from('<I', self._src.read(e_lfanew, 4), 0)[0]
        if sig != 0x00004550:
            raise ValueError(f"Invalid PE signature: 0x{sig:08X}")

        offset = e_lfanew + 4
        fh_data = self._src.read(offset, 20)
        machine, num_sections, ts, _, _, opt_hdr_size, chars = struct.unpack_from(
            '<HHIIIHH', fh_data, 0)
        file_hdr = FileHeader(
            machine=machine, time_date_stamp=ts,
            number_of_sections=num_sections, characteristics=chars)

        offset += 20
        magic = struct.unpack_from('<H', self._src.read(offset, 2), 0)[0]

        if magic == 0x20B:
            opt_hdr, sections_offset = self._parse_optional_64(offset, num_sections)
        elif magic == 0x10B:
            opt_hdr, sections_offset = self._parse_optional_32(offset, num_sections)
        else:
            raise ValueError(f"Unknown optional header magic: 0x{magic:04X}")

        return file_hdr, opt_hdr, sections_offset

    def _parse_optional_64(self, offset, num_sections):
        fields_data = self._src.read(offset, 112)
        fields = struct.unpack_from('<HBBIIIIIQIIIIHHHHHHIIII', fields_data, 0)
        num_rva = struct.unpack_from('<I', fields_data, 108)[0]

        data_dirs = self._parse_data_directories(offset + 112, num_rva)
        sections_offset = offset + 112 + num_rva * 8

        opt_hdr = OptionalHeader(
            magic=fields[0], major_linker_version=fields[1],
            minor_linker_version=fields[2], size_of_code=fields[3],
            entry_point_rva=fields[6], base_of_code=fields[7],
            image_base=fields[8], section_alignment=fields[9],
            file_alignment=fields[10],
            size_of_image=struct.unpack_from('<I', fields_data, 56)[0],
            size_of_headers=struct.unpack_from('<I', fields_data, 60)[0],
            checksum=struct.unpack_from('<I', fields_data, 64)[0],
            subsystem=struct.unpack_from('<H', fields_data, 68)[0],
            number_of_rva_and_sizes=num_rva, data_directories=data_dirs)
        return opt_hdr, sections_offset

    def _parse_optional_32(self, offset, num_sections):
        fields_data = self._src.read(offset, 96)
        fields = struct.unpack_from(
            '<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII', fields_data, 0)
        num_rva = struct.unpack_from('<I', fields_data, 92)[0]

        data_dirs = self._parse_data_directories(offset + 96, num_rva)
        sections_offset = offset + 96 + num_rva * 8

        opt_hdr = OptionalHeader(
            magic=fields[0], major_linker_version=fields[1],
            minor_linker_version=fields[2], size_of_code=fields[3],
            entry_point_rva=fields[6], base_of_code=fields[7],
            image_base=fields[9], section_alignment=fields[10],
            file_alignment=fields[11],
            size_of_image=struct.unpack_from('<I', fields_data, 56)[0],
            size_of_headers=struct.unpack_from('<I', fields_data, 60)[0],
            checksum=struct.unpack_from('<I', fields_data, 64)[0],
            subsystem=struct.unpack_from('<H', fields_data, 68)[0],
            number_of_rva_and_sizes=num_rva, data_directories=data_dirs)
        return opt_hdr, sections_offset

    def _parse_data_directories(self, offset: int, count: int) -> dict:
        data_dirs = {}
        for i in range(min(count, 16)):
            dd_offset = offset + i * 8
            dd_data = self._src.read(dd_offset, 8)
            rva, size = struct.unpack_from('<II', dd_data, 0)
            data_dirs[i] = DataDirectory(virtual_address=rva, size=size)
        return data_dirs

    def parse_sections(self, offset: int, count: int) -> list[SectionHeader]:
        sections = []
        for i in range(count):
            sec_offset = offset + i * 40
            sec_data = self._src.read(sec_offset, 40)
            raw_name = struct.unpack_from('<8s', sec_data, 0)[0]
            name = raw_name.split(b'\x00', 1)[0].decode('ascii', errors='replace')
            vs, va, rs, rp, _, _, _, _, chars = struct.unpack_from(
                '<IIIIIIIHH', sec_data, 8)
            sections.append(SectionHeader(
                name=name, virtual_size=vs, virtual_address=va,
                size_of_raw_data=rs, pointer_to_raw_data=rp,
                characteristics=chars))
        return sections

    def parse_exports(self, data_dirs: dict) -> list[ExportEntry]:
        exports = []
        if 0 not in data_dirs:
            return exports
        dd = data_dirs[0]
        if dd.virtual_address == 0 or dd.size == 0:
            return exports

        offset = self._view.rva_to_source_offset(dd.virtual_address)
        if offset is None:
            return exports

        export_data = self._src.read(offset, 40)
        fields = struct.unpack_from('<IIHHIIIIIII', export_data, 0)
        base = fields[5]
        num_funcs = fields[6]
        num_names = fields[7]
        func_table_rva = fields[8]
        name_table_rva = fields[9]
        ordinal_table_rva = fields[10]

        func_offsets = self._read_rva_table(func_table_rva, num_funcs, 4, '<I')
        name_to_ordinal = self._read_name_ordinal_map(
            name_table_rva, ordinal_table_rva, num_names)

        export_dir_end = dd.virtual_address + dd.size
        for i in range(len(func_offsets)):
            func_rva = func_offsets[i]
            name = name_to_ordinal.get(i)
            forwarder = None
            if dd.virtual_address <= func_rva < export_dir_end:
                fwd_offset = self._view.rva_to_source_offset(func_rva)
                if fwd_offset is not None:
                    forwarder = self._read_string_at_offset(fwd_offset)
            exports.append(ExportEntry(
                name=name, ordinal=i + base,
                rva=func_rva, forwarder=forwarder))
        return exports

    def parse_imports(self, data_dirs: dict, magic: int) -> list[ImportEntry]:
        imports = []
        if 1 not in data_dirs:
            return imports
        dd = data_dirs[1]
        if dd.virtual_address == 0 or dd.size == 0:
            return imports

        offset = self._view.rva_to_source_offset(dd.virtual_address)
        if offset is None:
            return imports

        is_pe32plus = magic == 0x20B
        thunk_size = 8 if is_pe32plus else 4
        ordinal_flag = 0x8000000000000000 if is_pe32plus else 0x80000000
        thunk_fmt = '<Q' if is_pe32plus else '<I'

        cursor = offset
        while True:
            desc_data = self._src.read(cursor, 20)
            ilt_rva, _, _, name_rva, iat_rva = struct.unpack_from(
                '<IIIII', desc_data, 0)
            if ilt_rva == 0 and name_rva == 0 and iat_rva == 0:
                break

            dll_name = ''
            name_offset = self._view.rva_to_source_offset(name_rva)
            if name_offset is not None:
                dll_name = self._read_string_at_offset(name_offset)

            thunk_rva = ilt_rva if ilt_rva != 0 else iat_rva
            thunk_offset = self._view.rva_to_source_offset(thunk_rva)
            if thunk_offset is not None:
                t_index = 0
                while True:
                    t_data = self._src.read(thunk_offset, thunk_size)
                    thunk = struct.unpack_from(thunk_fmt, t_data, 0)[0]
                    if thunk == 0:
                        break
                    if thunk & ordinal_flag:
                        imports.append(ImportEntry(
                            dll_name=dll_name, name=None,
                            ordinal=thunk & 0xFFFF,
                            rva=iat_rva + t_index * thunk_size))
                    else:
                        ibn_offset = self._view.rva_to_source_offset(thunk)
                        func_name = None
                        if ibn_offset is not None:
                            func_name = self._read_string_at_offset(ibn_offset + 2)
                        imports.append(ImportEntry(
                            dll_name=dll_name, name=func_name,
                            ordinal=None,
                            rva=iat_rva + t_index * thunk_size))
                    thunk_offset += thunk_size
                    t_index += 1
            cursor += 20
        return imports

    def _read_rva_table(self, table_rva: int, count: int,
                        entry_size: int, fmt: str) -> list[int]:
        result = []
        table_offset = self._view.rva_to_source_offset(table_rva)
        if table_offset is None:
            return result
        for i in range(count):
            data = self._src.read(table_offset + i * entry_size, entry_size)
            result.append(struct.unpack_from(fmt, data, 0)[0])
        return result

    def _read_name_ordinal_map(self, name_table_rva: int,
                               ordinal_table_rva: int,
                               num_names: int) -> dict:
        mapping = {}
        name_off = self._view.rva_to_source_offset(name_table_rva)
        ord_off = self._view.rva_to_source_offset(ordinal_table_rva)
        if name_off is None or ord_off is None:
            return mapping
        for i in range(num_names):
            n_data = self._src.read(name_off + i * 4, 4)
            name_rva = struct.unpack_from('<I', n_data, 0)[0]
            o_data = self._src.read(ord_off + i * 2, 2)
            ordinal = struct.unpack_from('<H', o_data, 0)[0]
            str_off = self._view.rva_to_source_offset(name_rva)
            if str_off is not None:
                name = self._read_string_at_offset(str_off)
                mapping[ordinal] = name
        return mapping

    def _read_string_at_offset(self, offset: int) -> str:
        max_read = 256
        data = self._src.read(offset, max_read)
        end = data.find(b'\x00')
        if end == -1:
            end = len(data)
        return data[:end].decode('ascii', errors='replace')
