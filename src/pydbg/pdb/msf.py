"""Read the MSF 7.0 container that holds a PDB.

A PDB is a page-addressed container, not a serialized structure. A 56-byte
superblock gives the page size and the page holding the *block map*; the block
map lists the pages of the stream directory; the directory gives every stream's
size and page numbers. This module reads that shell, and stream 1 (the PDB info
record) through it. Stream bytes are fetched on demand: opening a file reads the
superblock, the block map and the directory, never the streams themselves.

dbghelp accepts a PDB built from a different binary without complaint, so these
checks are the only thing standing between a caller and quietly wrong symbols.
Structure errors are rejected with the rule and the offset; they are never
rounded down to "unknown". See research/pdb-format.md §A1-A5 for the measured
layout and the failure modes this follows.
"""

import os
import struct
import uuid
from dataclasses import dataclass

from .errors import PdbFormatError

# 29 bytes is what MSVC's own reader compares: the magic field is 32 bytes, but
# bytes 30-31 are alignment padding and a legal file may fill them differently.
MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS"
SUPERBLOCK_SIZE = 56

# MSVC only ever writes 4096; the smaller sizes are accepted because the reader
# is page-size agnostic and synthetic fixtures cover them. Bigger sizes have no
# real product to check against, so they are refused rather than guessed at.
BLOCK_SIZES = (512, 1024, 2048, 4096)

# A stream whose size field is this value does not exist. It is not the same as
# a zero-size stream, which exists and is empty; the directory stores no pages
# for either, and both read as b"" here.
NIL_STREAM_SIZE = 0xFFFFFFFF

# Stream 1, the PDB info record: the only stream this layer interprets.
INFO_STREAM_INDEX = 1
INFO_STREAM_SIZE = 28     # Version(4) + Signature(4) + Age(4) + Guid(16)


def _blocks_for(size, block_size):
    """Number of whole blocks needed to hold 'size' bytes."""
    return (size + block_size - 1) // block_size


def _format_guid(raw):
    """16 raw GUID bytes -> the 8-4-4-4-12 uppercase form pydbg.pe uses.

    The bytes are in Windows GUID memory order (Data1/Data2/Data3 little
    endian), so bytes_le is the rendering that matches what a symbol server and
    pydbg.pe.CodeViewInfo.guid print. bytes= would instead treat Data1 as
    big-endian and produce a different, equally well-formed GUID. This must
    stay identical to pe.parser._format_guid: the two are compared as strings
    when only one side has its raw bytes.
    """
    return str(uuid.UUID(bytes_le=raw)).upper()


@dataclass(frozen=True)
class PdbInfo:
    """The fixed 28-byte header of stream 1 (RawTypes.h InfoStreamHeader).

    version is kept exactly as read. 20000404 is PdbImplVC70, which VS2022
    still writes, and an unfamiliar value is explicit unknown rather than a bad
    file: these four fields sit at fixed offsets in every version. signature is
    the build timestamp for VC70 and later. guid_bytes is the raw identity
    bytes, the same bytes an image's RSDS record carries; guid is that same
    identity rendered for display and for string comparison when a caller has
    no raw image bytes.
    """

    version: int
    signature: int
    age: int
    guid_bytes: bytes
    guid: str


class MSFFile:
    """An MSF 7.0 container opened for lazy random access.

    Construction reads and validates the superblock, the block map and the
    stream directory. read_stream() fetches stream bytes on demand, and
    stream 1 is decoded into PdbInfo by the info property.

    A structurally invalid container raises PdbFormatError naming the failed
    rule and its offset; no struct.error or IndexError escapes. A nil stream
    (declared size 0xFFFFFFFF) and an empty stream (size 0) both report a size
    of 0 and read as b"": the format distinguishes them, but nothing above this
    layer acts on the difference.
    """

    def __init__(self, path):
        self._path = os.fspath(path)
        with open(self._path, "rb") as handle:
            self._file_size = os.fstat(handle.fileno()).st_size
            header = handle.read(SUPERBLOCK_SIZE)
            if len(header) < SUPERBLOCK_SIZE:
                raise PdbFormatError(
                    f"pdb corrupt: truncated superblock: {len(header)} of "
                    f"{SUPERBLOCK_SIZE} bytes at offset 0")
            self._read_superblock(header)
            directory = self._read_directory(handle)
        self._read_stream_table(directory)
        self._info = None

    def _read_superblock(self, header):
        """Validate the 56-byte header and keep the fields the walk needs."""
        if not header.startswith(MAGIC):
            raise PdbFormatError(
                "pdb not a PDB 7.0 file: bad magic at offset 0")
        (block_size, free_block_map, num_blocks, directory_bytes,
         unknown1, block_map_addr) = struct.unpack_from("<6I", header, 32)

        if block_size not in BLOCK_SIZES:
            raise PdbFormatError(
                f"pdb corrupt: unsupported block size {block_size} at offset 32")
        if free_block_map not in (1, 2):
            raise PdbFormatError(
                f"pdb corrupt: invalid free block map index {free_block_map} "
                f"at offset 36")
        # The field is really an index into a second page list. MSVC always
        # writes 0, and reading it as LLVM does would read the block table from
        # the wrong place; the indirection is explicitly unsupported.
        if unknown1 != 0:
            raise PdbFormatError(
                f"pdb unsupported: directory page-list indirection "
                f"(Unknown1={unknown1}) at offset 48")
        if directory_bytes % 4:
            raise PdbFormatError(
                f"pdb corrupt: directory size {directory_bytes} not 4-byte "
                f"aligned at offset 44")
        if directory_bytes < 4:
            raise PdbFormatError(
                f"pdb corrupt: truncated stream count: directory is "
                f"{directory_bytes} bytes at offset 44")
        directory_blocks = _blocks_for(directory_bytes, block_size)
        if directory_blocks > block_size // 4:
            raise PdbFormatError(
                f"pdb corrupt: too many directory blocks: {directory_blocks} "
                f"needed, one block map names {block_size // 4} (offset 44)")
        if self._file_size % block_size:
            raise PdbFormatError(
                f"pdb corrupt: file size {self._file_size} not block aligned "
                f"(block size {block_size})")
        if num_blocks * block_size != self._file_size:
            raise PdbFormatError(
                f"pdb truncated: block count does not match file size: "
                f"{num_blocks} blocks of {block_size} is "
                f"{num_blocks * block_size}, file is {self._file_size}")
        if block_map_addr == 0:
            raise PdbFormatError(
                "pdb corrupt: block map at reserved block 0 (offset 52)")
        if block_map_addr >= num_blocks:
            raise PdbFormatError(
                f"pdb corrupt: block map out of range: block {block_map_addr} "
                f"of {num_blocks} (offset 52)")

        self.block_size = block_size
        self.num_blocks = num_blocks
        self._directory_bytes = directory_bytes
        self._directory_blocks = directory_blocks
        self._block_map_addr = block_map_addr

    def _read_at(self, handle, offset, size, what):
        """Exactly 'size' bytes at 'offset', or PdbFormatError naming it."""
        if offset < 0 or size < 0 or offset + size > self._file_size:
            raise PdbFormatError(
                f"pdb truncated: {what}: {size} bytes at offset {offset} "
                f"past the {self._file_size}-byte file")
        handle.seek(offset)
        data = handle.read(size)
        if len(data) != size:
            raise PdbFormatError(
                f"pdb truncated: {what}: {len(data)} of {size} bytes at "
                f"offset {offset}")
        return data

    def _read_directory(self, handle):
        """Read the block map and through it the stream directory bytes."""
        map_size = self._directory_blocks * 4
        map_bytes = self._read_at(handle, self._block_map_addr * self.block_size,
                                  map_size, "block map")
        pages = struct.unpack_from(f"<{self._directory_blocks}I", map_bytes, 0)
        for page in pages:
            if page >= self.num_blocks:
                raise PdbFormatError(
                    f"pdb corrupt: directory page out of range: block {page} "
                    f"of {self.num_blocks}")

        chunks = []
        for page in pages:
            chunks.append(self._read_at(handle, page * self.block_size,
                                        self.block_size, "directory block"))
        return b"".join(chunks)[:self._directory_bytes]

    def _read_stream_table(self, directory):
        """Decode NumStreams, the size array, and every stream's page list."""
        self._sizes = []
        self._pages = []
        stream_count = struct.unpack_from("<I", directory, 0)[0]
        table_end = 4 + 4 * stream_count
        if table_end > self._directory_bytes:
            raise PdbFormatError(
                f"pdb corrupt: truncated stream table: {stream_count} stream "
                f"size(s) need {table_end} bytes, directory has "
                f"{self._directory_bytes}")
        offset = 4
        for _ in range(stream_count):
            self._sizes.append(struct.unpack_from("<I", directory, offset)[0])
            offset += 4

        for index, size in enumerate(self._sizes):
            blocks = 0 if size == NIL_STREAM_SIZE else _blocks_for(
                size, self.block_size)
            end = offset + 4 * blocks
            if end > self._directory_bytes:
                raise PdbFormatError(
                    f"pdb corrupt: truncated stream directory: stream {index} "
                    f"needs {blocks} page number(s) at offset {offset}, "
                    f"directory has {self._directory_bytes} bytes")
            pages = (struct.unpack_from(f"<{blocks}I", directory, offset)
                     if blocks else ())
            offset = end
            for page in pages:
                if page >= self.num_blocks:
                    raise PdbFormatError(
                        f"pdb corrupt: stream {index} page out of range: "
                        f"block {page} of {self.num_blocks}")
            self._pages.append(pages)

    @property
    def stream_count(self):
        """Number of streams the directory declares."""
        return len(self._sizes)

    def stream_size(self, index):
        """Declared byte size of stream 'index'.

        A nil stream (size 0xFFFFFFFF) reports 0, like an empty one; read_stream
        returns b"" for both.

        Raises:
            PdbFormatError: 'index' is outside [0, stream_count).
        """
        self._check_index(index)
        size = self._sizes[index]
        return 0 if size == NIL_STREAM_SIZE else size

    def read_stream(self, index):
        """Bytes of stream 'index', read from the file on each call.

        Raises:
            PdbFormatError: 'index' is out of range, or the file no longer
                supplies a page the directory names.
        """
        size = self.stream_size(index)
        if size == 0:
            return b""
        chunks = []
        remaining = size
        with open(self._path, "rb") as handle:
            for page in self._pages[index]:
                amount = min(self.block_size, remaining)
                chunks.append(self._read_at(handle, page * self.block_size,
                                            amount, f"stream {index}"))
                remaining -= amount
        return b"".join(chunks)

    def _check_index(self, index):
        if not isinstance(index, int) or isinstance(index, bool):
            raise PdbFormatError(
                f"pdb stream index {index!r} is not an integer")
        if index < 0 or index >= self.stream_count:
            raise PdbFormatError(
                f"pdb stream index {index} out of range (0.."
                f"{self.stream_count - 1})")

    @property
    def info(self):
        """The PDB info record (stream 1), parsed once on first access.

        Raises:
            PdbFormatError: the file has no stream 1, or it is shorter than the
                28-byte fixed header, so there is no GUID/age to check an image
                against. A nil or empty stream 1 lands here too.
        """
        if self._info is None:
            self._info = self._parse_info()
        return self._info

    def _parse_info(self):
        if self.stream_count <= INFO_STREAM_INDEX:
            raise PdbFormatError(
                f"pdb corrupt: missing PDB info stream: file has "
                f"{self.stream_count} stream(s)")
        raw = self.read_stream(INFO_STREAM_INDEX)
        if len(raw) < INFO_STREAM_SIZE:
            raise PdbFormatError(
                f"pdb corrupt: missing PDB info stream: stream 1 is "
                f"{len(raw)} bytes, need {INFO_STREAM_SIZE}")
        version, signature, age = struct.unpack_from("<III", raw, 0)
        guid_bytes = raw[12:INFO_STREAM_SIZE]
        return PdbInfo(version=version, signature=signature, age=age,
                       guid_bytes=guid_bytes, guid=_format_guid(guid_bytes))
