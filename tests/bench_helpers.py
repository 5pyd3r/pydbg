"""Synthetic fixtures for the phase-6 scale budgets (spec §13.5).

`build_function_image` returns the *bytes* of a PE32+ holding a given number of
leaf functions, so the static budget feeds `analyze_bytes` the same image a
file would contain without a temp file becoming part of the measurement (and
without a cleanup step that can fail).

Why the image carries a `.pdata`: the exception directory is the loader's own
function ranges, and `SeedProvider` treats it as the strongest seed class there
is. A 10,000-function image whose only evidence is a heuristic would measure
the heuristic's recall as much as the analyzer's throughput; with the ranges
present, the recovered start count is a fact about the image, so the test can
say "10k functions were analysed" rather than "10k functions were offered".
The analysis still decodes every body — a range table says where a function is,
not what runs there.
"""

import struct

from tests.pe_builder import PEBuilder, SECTION_ALIGN

# IMAGE_DIRECTORY_ENTRY_EXCEPTION: the RUNTIME_FUNCTION table.
EXCEPTION_DIRECTORY = 3

TEXT_RVA = 0x1000
FUNCTION_SIZE = 32

# Instructions every body starts with, so the sized run of whole instructions
# the BBL planner would need also exists in this fixture: push rbp; mov rbp,rsp.
_PROLOGUE = b"\x55\x48\x89\xE5"
_EPILOGUE = b"\x5d\xc3"                       # pop rbp; ret
# int3 fills the tail of each body. It is real padding between functions and
# decodes as one byte, so an extent that runs past `ret` would be visible.
_PADDING = 0xCC


def _function_body(index):
    """One 32-byte leaf function with an index-dependent immediate.

    The immediates differ per function so the bytes are not one repeated blob:
    a decoder with a broken cache would still see distinct instructions, and a
    future analysis that folds constants sees 10,000 different values. The
    shape stays exactly FUNCTION_SIZE bytes for every function, which is what
    keeps the `.pdata` table's begin/end pairs uniform.
    """
    body = bytearray(_PROLOGUE)
    body += b"\xb8" + struct.pack("<I", index & 0xFFFFFFFF)               # mov eax, i
    body += b"\x05" + struct.pack("<I", (index * 3 + 1) & 0xFFFFFFFF)     # add eax, 3i+1
    body += _EPILOGUE
    if len(body) > FUNCTION_SIZE:
        raise AssertionError(
            f"function body is {len(body)} bytes, over the {FUNCTION_SIZE}-byte "
            "slot: the .pdata entries would overlap")
    return bytes(body).ljust(FUNCTION_SIZE, bytes([_PADDING]))


def _align_up(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def build_function_image(count):
    """A PE32+ image containing `count` functions, as bytes.

    Layout: `.text` at TEXT_RVA with one FUNCTION_SIZE-byte body per function,
    then a `.pdata` section naming each body's exact [begin, end) range. Every
    function is a leaf (no calls, no data operands), so each sweep is bounded by
    the function's own `ret` and the measurement is the per-function cost of
    the analysis, not the shape of one giant function.
    """
    if count < 1:
        raise ValueError(f"need at least one function, got {count!r}")

    text = b"".join(_function_body(index) for index in range(count))
    pdata_rva = _align_up(TEXT_RVA + len(text), SECTION_ALIGN)
    pdata = b"".join(
        struct.pack(
            "<III",
            TEXT_RVA + index * FUNCTION_SIZE,
            TEXT_RVA + (index + 1) * FUNCTION_SIZE,
            0)                                     # no unwind info needed
        for index in range(count))

    builder = PEBuilder(entry_rva=TEXT_RVA)
    builder.add_section(".text", text, TEXT_RVA)
    builder.add_section(".pdata", pdata, pdata_rva, 0x40000040)
    builder.add_dir(EXCEPTION_DIRECTORY, pdata_rva, len(pdata))
    return builder.build()
