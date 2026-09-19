"""Parse layer — PE binary structure parser."""

import struct

from .types import (
    DosHeader, FileHeader, OptionalHeader, DataDirectory,
    SectionHeader, ExportEntry, ImportEntry,
    RelocationEntry, RelocationBlock, TLSDirectory, DebugEntry,
    ExceptionEntry, RichHeader, RichHeaderEntry,
)
from .view import View

# Data directory indices this module understands. Only dirs 0 and 1 are parsed
# eagerly at construction; the rest are lazy (see PE).
DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_RESOURCE = 2          # parsed on a separate branch (feat/pe-resource-parser)
DIR_EXCEPTION = 3
DIR_SECURITY = 4
DIR_BASERELOC = 5
DIR_DEBUG = 6
DIR_TLS = 9

# All 16 slots fit; the cap is what keeps a lying NumberOfRvaAndSizes bounded.
MAX_DATA_DIRECTORIES = 16


class PEParser:
    """Parse PE binary structures from a byte source."""

    def __init__(self, source, view: View):
        self._src = source
        self._view = view

    def _read_rva(self, rva, size):
        """Bytes at 'rva', or None when that range is not fully available.

        Every table walk below goes through this, so a truncated or unmapped
        directory ends its own parse instead of raising out of the caller.
        """
        offset = self._view.rva_to_source_offset(rva)
        if offset is None:
            return None
        return self._src.try_read(offset, size)

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
        for i in range(min(count, MAX_DATA_DIRECTORIES)):
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

    # ── data directories 3, 5, 6, 9 and the Rich header ────────
    #
    # Parsed lazily (see PE), because most consumers want none of them and
    # several are large: a 30k-function .pdata is 360KB nobody asked for.

    def parse_relocations(self, data_dirs: dict, max_blocks: int = 4096) -> list:
        """Base relocation blocks (data directory 5).

        Returns structure only — see RelocationBlock for why the slots are not
        dereferenced here.
        """
        blocks = []
        dd = data_dirs.get(DIR_BASERELOC)
        if dd is None or dd.virtual_address == 0 or dd.size == 0:
            return blocks

        cursor = dd.virtual_address
        end = dd.virtual_address + dd.size
        for _ in range(max_blocks):
            if cursor + 8 > end:
                break
            header = self._read_rva(cursor, 8)
            if header is None:
                break
            page_rva, block_size = struct.unpack_from('<II', header, 0)
            if page_rva == 0 and block_size == 0:
                break                       # terminator
            if block_size < 8 or cursor + block_size > end:
                break                       # malformed, or a size that lies
            body = self._read_rva(cursor + 8, block_size - 8)
            if body is None:
                break

            entries = []
            for i in range((block_size - 8) // 2):
                value = struct.unpack_from('<H', body, i * 2)[0]
                entries.append(RelocationEntry(kind=value >> 12,
                                               offset=value & 0x0FFF))
            blocks.append(RelocationBlock(page_rva=page_rva,
                                          block_size=block_size,
                                          entries=entries))
            cursor += block_size
        return blocks

    def parse_tls(self, data_dirs: dict, magic: int, va_base: int = 0,
                  max_callbacks: int = 64):
        """TLS directory (data directory 9), or None when absent.

        'va_base' is what the directory's stored addresses are relative to.
        For a file that is the optional header's ImageBase; for a live module
        it is the module's runtime base, which ASLR makes a different number —
        pass the wrong one and every callback lands outside the image.
        """
        dd = data_dirs.get(DIR_TLS)
        if dd is None or dd.virtual_address == 0 or dd.size == 0:
            return None

        is_pe32plus = magic == 0x20B
        header_size = 40 if is_pe32plus else 24
        raw = self._read_rva(dd.virtual_address, header_size)
        if raw is None:
            return None

        if is_pe32plus:
            start, end, index, callbacks, zero_fill, chars = struct.unpack_from(
                '<QQQQII', raw, 0)
            stride, fmt = 8, '<Q'
        else:
            start, end, index, callbacks, zero_fill, chars = struct.unpack_from(
                '<IIIIII', raw, 0)
            stride, fmt = 4, '<I'

        return TLSDirectory(
            start_address_of_raw_data=start,
            end_address_of_raw_data=end,
            address_of_index=index,
            address_of_callbacks=callbacks,
            size_of_zero_fill=zero_fill,
            characteristics=chars,
            callbacks=self._read_va_array(callbacks, va_base, stride, fmt,
                                          max_callbacks))

    def _read_va_array(self, va, va_base, stride, fmt, limit):
        """Read a NULL-terminated array of VAs, as RVAs relative to 'va_base'."""
        if not va:
            return []
        values = []
        for i in range(limit):
            rva = va + i * stride - va_base
            raw = self._read_rva(rva, stride)
            if raw is None:
                break
            value = struct.unpack_from(fmt, raw, 0)[0]
            if value == 0:
                break                       # NULL terminator
            values.append(value)
        return values

    def parse_debug(self, data_dirs: dict, max_entries: int = 64) -> list:
        """Debug directory records (data directory 6).

        Entry type 2 (IMAGE_DEBUG_TYPE_CODEVIEW) is the one that carries the
        PDB path and GUID for a build.
        """
        entries = []
        dd = data_dirs.get(DIR_DEBUG)
        if dd is None or dd.virtual_address == 0 or dd.size == 0:
            return entries

        count = min(dd.size // 28, max_entries)
        for i in range(count):
            raw = self._read_rva(dd.virtual_address + i * 28, 28)
            if raw is None:
                break
            chars, stamp, major, minor, kind, size, addr, ptr = struct.unpack_from(
                '<IIHHIIII', raw, 0)
            entries.append(DebugEntry(
                characteristics=chars, time_date_stamp=stamp,
                major_version=major, minor_version=minor, type=kind,
                size_of_data=size, address_of_raw_data=addr,
                pointer_to_raw_data=ptr))
        return entries

    def parse_exception(self, data_dirs: dict, max_entries: int = 65536) -> list:
        """RUNTIME_FUNCTION table (data directory 3).

        x64 only in practice — a PE32 image has no .pdata, so this returns []
        there. Where it exists it is the authoritative function table, which is
        why it is worth reading before any prologue heuristic.
        """
        entries = []
        dd = data_dirs.get(DIR_EXCEPTION)
        if dd is None or dd.virtual_address == 0 or dd.size == 0:
            return entries

        count = min(dd.size // 12, max_entries)
        for i in range(count):
            raw = self._read_rva(dd.virtual_address + i * 12, 12)
            if raw is None:
                break
            begin, end, unwind = struct.unpack_from('<III', raw, 0)
            if begin == 0 and end == 0:
                break                       # terminator
            entries.append(ExceptionEntry(begin_rva=begin, end_rva=end,
                                          unwind_info_rva=unwind))
        return entries

    def parse_rich_header(self, e_lfanew: int):
        """Decode the Rich header from the DOS stub, or None.

        The header is XOR-obfuscated with a key stored after the "Rich" marker
        and is located by XOR-searching for the "DanS" marker, so the scan is
        bounded by the PE header rather than the whole file.
        """
        if e_lfanew <= 0x40:
            return None
        region = self._src.try_read(0x40, e_lfanew - 0x40)
        if not region or len(region) < 8:
            return None

        rich = region.rfind(b"Rich")
        if rich == -1 or rich + 8 > len(region):
            return None
        key = struct.unpack_from('<I', region, rich + 4)[0]

        encoded_dans = struct.pack('<I', 0x536E6144 ^ key)
        dans = region.rfind(encoded_dans, 0, rich)
        if dans == -1:
            return None

        # Entries follow the marker and three encoded zero dwords.
        entries = []
        for off in range(dans + 16, rich - 7, 8):
            comp_id = struct.unpack_from('<I', region, off)[0] ^ key
            count = struct.unpack_from('<I', region, off + 4)[0] ^ key
            entries.append(RichHeaderEntry(comp_id=comp_id, count=count))
        return RichHeader(xor_key=key, entries=entries)

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
