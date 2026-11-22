"""Build minimal MSF 7.0 containers for the pdb reader tests.

MSF 7.0 is a page-addressed file, not a serialized structure. A 56-byte
superblock names the page size and the page holding the *block map*; the block
map lists the pages of the stream directory; the directory then holds every
stream's size followed by the page numbers its bytes live on. The free-block-map
pages are never interpreted by the reader, so they are written as zeros here.

Every synthetic file uses this block layout ('bs' is the block size):

    0                 superblock
    1, 2              free block maps (content ignored)
    3                 block map: the directory's page numbers
    4 .. 4+d-1        stream directory
    4+d ..            stream data, in stream-index order

A stream index missing from the mapping is written as the nil stream (size
0xFFFFFFFF, no pages); an index mapped to b"" is a present but empty stream
(size 0). Real PDBs contain both, and they mean different things — one is "no
such stream", the other is a stream of no bytes — so the builder keeps them
apart. The reader treats both as b"", per the ticket's API.

These builders deliberately accept any block size, not just the four the reader
supports, so tests can hand the reader a header it must reject.
"""

import struct

MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS"
SUPERBLOCK_SIZE = 56             # 32-byte magic field + six u32 fields
BLOCK_SIZES = (512, 1024, 2048, 4096)
NIL_STREAM_SIZE = 0xFFFFFFFF

_BLOCK_MAP_BLOCK = 3
_DIRECTORY_BLOCK = 4

# The MSVC sample from research/pdb-format.md §A3. The expected rendering is
# the bytes_le one (the Windows GUID display form), which is what symbol
# servers and pydbg.pe.CodeViewInfo.guid print.
SAMPLE_GUID_BYTES = bytes.fromhex("7c700da34a05fe438f7db696349e3f16")
SAMPLE_GUID_TEXT = "A30D707C-054A-43FE-8F7D-B696349E3F16"

INFO_STREAM_VERSION = 20000404   # PdbImplVC70, what current MSVC still writes
INFO_STREAM_SIGNATURE = 0x6B030339
INFO_STREAM_AGE = 2


def blocks_for(size, block_size):
    """Number of whole blocks needed to hold 'size' bytes."""
    return (size + block_size - 1) // block_size


def pdb_info_stream(version=INFO_STREAM_VERSION, signature=INFO_STREAM_SIGNATURE,
                    age=INFO_STREAM_AGE, guid=SAMPLE_GUID_BYTES, trailing=b""):
    """Stream 1's fixed 28-byte header, plus whatever the caller appends.

    Offsets are the ones measured in research/pdb-format.md §A3: Version +0,
    Signature +4, Age +8, Guid(16) +12. 'trailing' stands in for the named
    stream table that follows the header in a real file.
    """
    return struct.pack("<III", version, signature, age) + bytes(guid) + trailing


def build_msf(streams, block_size=4096, *, magic=MAGIC, unknown1=0,
              free_block_map=1):
    """Assemble a structurally consistent MSF 7.0 container.

    Args:
        streams: {stream index: bytes}. The container has max(index)+1 streams;
            a missing index below that maximum is the nil stream, and an index
            mapped to b"" is an empty one.
        block_size: page size to write.
        magic: the 32 header bytes' meaningful prefix (29 bytes in real files).
        unknown1: superblock +48. MSVC always writes 0.
        free_block_map: superblock +36; a real file writes 1 or 2.

    Raises:
        ValueError: the requested streams need more directory pages than one
            block map can name, or an index is negative / magic too long. The
            builder refuses rather than emit a file the format cannot hold.
    """
    if len(magic) > 32:
        raise ValueError(f"magic is {len(magic)} bytes; the field is 32")
    streams = {index: bytes(data) for index, data in streams.items()}
    if any(index < 0 for index in streams):
        raise ValueError("stream indices cannot be negative")

    stream_count = max(streams) + 1 if streams else 0
    sizes = []
    data_blocks = []
    for index in range(stream_count):
        data = streams.get(index)
        if data is None:
            sizes.append(NIL_STREAM_SIZE)
            data_blocks.append(0)
        else:
            sizes.append(len(data))
            data_blocks.append(blocks_for(len(data), block_size))

    directory_bytes = 4 + 4 * stream_count + 4 * sum(data_blocks)
    directory_blocks = blocks_for(directory_bytes, block_size)
    if directory_blocks > block_size // 4:
        raise ValueError(
            f"stream directory needs {directory_blocks} blocks; one block map "
            f"can name only {block_size // 4}")

    first_data_block = _DIRECTORY_BLOCK + directory_blocks
    page_lists = []
    next_block = first_data_block
    for count in data_blocks:
        page_lists.append(list(range(next_block, next_block + count)))
        next_block += count

    directory = bytearray(struct.pack("<I", stream_count))
    for size in sizes:
        directory += struct.pack("<I", size)
    for pages in page_lists:
        for page in pages:
            directory += struct.pack("<I", page)
    assert len(directory) == directory_bytes, (len(directory), directory_bytes)

    num_blocks = next_block
    header = bytearray(32)
    header[:len(magic)] = magic
    header += struct.pack("<6I", block_size, free_block_map, num_blocks,
                          directory_bytes, unknown1, _BLOCK_MAP_BLOCK)
    assert len(header) == SUPERBLOCK_SIZE, len(header)

    image = bytearray(num_blocks * block_size)
    image[0:SUPERBLOCK_SIZE] = header
    map_offset = _BLOCK_MAP_BLOCK * block_size
    for slot, page in enumerate(
            range(_DIRECTORY_BLOCK, _DIRECTORY_BLOCK + directory_blocks)):
        struct.pack_into("<I", image, map_offset + 4 * slot, page)
    directory_offset = _DIRECTORY_BLOCK * block_size
    image[directory_offset:directory_offset + len(directory)] = directory

    data_offset = first_data_block * block_size
    for index in range(stream_count):
        data = streams.get(index)
        if data:
            image[data_offset:data_offset + len(data)] = data
        data_offset += data_blocks[index] * block_size
    return bytes(image)


def patch_field(data, offset, fmt, value):
    """Return 'data' with one little-endian field overwritten.

    Corruption tests read as one line: patch the superblock, the block map or
    the directory where the field lives, then hand the bytes to the reader.
    """
    out = bytearray(data)
    struct.pack_into(fmt, out, offset, value)
    return bytes(out)


def info_guid_offset(data):
    """File offset of stream 1's first GUID byte in an existing container.

    A real PDB cannot be mutated by patching a fixed file offset the way the
    synthetic ones can: stream 1's bytes live on pages named by the block map
    and the directory. This walks that documented layout (research §A1-A3) for
    the tests, so a compiler-written file can be changed without the reader
    code exposing its page table. The GUID sits at stream 1 + 12 (after
    Version/Signature/Age), so that byte is returned.

    Raises:
        ValueError: the file has no stream 1, so there is no identity to edit.
    """
    (block_size, _free_block_map, _num_blocks, directory_bytes,
     _unknown1, block_map_addr) = struct.unpack_from("<6I", data, 32)
    directory_blocks = blocks_for(directory_bytes, block_size)
    directory_pages = struct.unpack_from(
        f"<{directory_blocks}I", data, block_map_addr * block_size)
    directory = b"".join(
        data[page * block_size:(page + 1) * block_size]
        for page in directory_pages)[:directory_bytes]

    stream_count = struct.unpack_from("<I", directory, 0)[0]
    pages_offset = 4 + 4 * stream_count
    for index in range(stream_count):
        size = struct.unpack_from("<I", directory, 4 + 4 * index)[0]
        block_count = (0 if size == NIL_STREAM_SIZE
                       else blocks_for(size, block_size))
        pages = struct.unpack_from(f"<{block_count}I", directory, pages_offset)
        pages_offset += 4 * block_count
        if index == 1:
            within = 12
            return (pages[within // block_size] * block_size
                    + within % block_size)
    raise ValueError("pdb has no info stream (stream 1)")
