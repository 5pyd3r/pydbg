"""Integer alignment — the one rounding rule the PE package shares.

FileAlignment and SectionAlignment size every file-layout value, and the
version resource rounds node offsets up to 4. Those call sites used to spell
the rounding out themselves with different arithmetic (a divide-and-round and
a 4-byte mask); this module states it once.
"""


def align_up(value, alignment):
    """Round 'value' up to the next multiple of 'alignment'."""
    return (value + alignment - 1) // alignment * alignment
