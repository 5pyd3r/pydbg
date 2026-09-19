"""InstructionDecoder — decoding plus honest coverage accounting."""

from collections import OrderedDict

from ..disasm.engine import DisasmEngine


class InstructionDecoder:
    """Decodes one instruction at a time and records what was decoded.

    Deliberately does NOT retain Instruction objects. A CsInsn is roughly a
    kilobyte — capstone's operand array, byte buffer and strings — so a
    670k-instruction image would sit on close to a gigabyte if the decoded
    instructions were kept for the whole run. What is kept is three bytearrays
    indexed by RVA, which is a few megabytes for the same image, plus a small
    LRU for callers that want to look at an instruction again.
    """

    def __init__(self, image, mode=None, cache_size=4096, min_read=1):
        self.image = image
        self.engine = DisasmEngine(mode=mode or image.mode)
        self._size_at = bytearray(image.span)
        self._flags_at = bytearray(image.span)
        self._covered = bytearray(image.span)
        self._bad = set()
        self._cache = OrderedDict()
        self._cache_size = cache_size
        self._min_read = min_read
        self.overlap_bytes = 0
        self.overlap_conflicts = 0
        self.instructions = 0
        # Which seed class decoded each instruction. Only the start is
        # recorded; the owner of an arbitrary byte is found by walking back at
        # most one instruction, which happens only for the rare overlap.
        self._origin_at = {}
        # (existing origin, new origin) -> bytes they both claimed. This is the
        # answer to "if the overlap were to be fixed by changing the seed set,
        # which class would have to change".
        self.overlap_by_origin = {}

    # flag bits
    _CALL = 1
    _JMP = 2
    _RET = 4
    _COND = 8

    def is_decoded(self, rva):
        return 0 <= rva < len(self._size_at) and self._size_at[rva] != 0

    def is_known_bad(self, rva):
        return rva in self._bad

    def size_of(self, rva):
        if 0 <= rva < len(self._size_at):
            return self._size_at[rva]
        return 0

    def flags_of(self, rva):
        if 0 <= rva < len(self._flags_at):
            return self._flags_at[rva]
        return 0

    def is_call(self, rva):
        return bool(self.flags_of(rva) & self._CALL)

    def decode_one(self, rva):
        """The instruction at 'rva', or None if it will not decode.

        Decodes at the instruction's VIRTUAL address, not its RVA, so the
        returned Instruction's `address` is a VA. That is not cosmetic:
        capstone derives a branch target from the base it is handed, while a
        memory displacement is an absolute address straight from the encoding.
        Feeding it an RVA therefore mixes the two address spaces in one
        listing, and every relative branch lands somewhere meaningless. It is
        also what makes RIP-relative resolution work — `address + size + disp`
        is only an address if `address` is a VA.

        Failures are remembered: a branch that targets a byte which does not
        decode is real information (the seed that led there was wrong), and
        retrying the same address on every sweep would be wasted work.
        """
        if rva in self._bad or not self.image.is_mapped(rva):
            return None

        if rva in self._cache:
            self._cache.move_to_end(rva)
            return self._cache[rva]

        data = self.image.read_code_bytes(rva, min_len=self._min_read)
        if not data:
            self._bad.add(rva)
            return None

        va = self.image.rva_to_va(rva)
        instructions = self.engine.disasm(va, data)
        if not instructions or instructions[0].address != va:
            self._bad.add(rva)
            return None

        insn = instructions[0]
        self._remember(rva, insn)
        return insn

    def _remember(self, rva, insn):
        size = insn.size
        if rva + size > len(self._size_at):
            return
        self._size_at[rva] = size

        flags = 0
        if insn.is_call:
            flags |= self._CALL
        if insn.is_jmp:
            flags |= self._JMP
        if insn.is_ret:
            flags |= self._RET
        if insn.is_cond:
            flags |= self._COND
        self._flags_at[rva] = flags

        self._cache[rva] = insn
        if len(self._cache) > self._cache_size:
            self._cache.popitem(last=False)

        self.instructions += 1

    def mark_covered(self, rva, size, origin=None):
        """Claim [rva, rva+size).

        A byte claimed more than once counts once toward coverage and the extra
        claims are counted as overlap. Reporting the sum of instruction sizes
        instead is what makes a 94% decode look like 99.5%: misaligned decoding
        inflates the total while looking like success.

        'origin' names the seed class that led here, so an overlap can be
        charged to a cause rather than only counted.
        """
        end = min(rva + size, len(self._covered))
        if end <= rva:
            return
        self._origin_at[rva] = origin

        for offset in range(rva, end):
            if self._covered[offset]:
                self.overlap_bytes += 1
                self.overlap_conflicts += 1
                other = self.origin_of_byte(offset)
                key = (other or "?", origin or "?")
                self.overlap_by_origin[key] = (
                    self.overlap_by_origin.get(key, 0) + 1)
            else:
                self._covered[offset] = 1

    def enclosing_instruction(self, rva):
        """The RVA of the decoded instruction covering 'rva', or None.

        Returns 'rva' itself when an instruction starts there. The distinction
        is what makes this useful as a filter: an address strictly inside
        another instruction cannot begin a function, and no property of the
        bytes around it reveals that — only the decode does.
        """
        if self.is_decoded(rva):
            return rva
        for back in range(1, 16):        # the longest x86 instruction
            start = rva - back
            if start < 0:
                break
            size = self._size_at[start]
            if size and start + size > rva:
                return start
        return None

    def origin_of_byte(self, offset):
        """Which seed class decoded the instruction covering 'offset'."""
        for back in range(1, 16):        # the longest x86 instruction
            start = offset - back
            if start < 0:
                break
            size = self._size_at[start]
            if size and start + size > offset:
                return self._origin_at.get(start)
        return None

    def origin_of(self, rva):
        """The seed class recorded for the instruction at 'rva'."""
        return self._origin_at.get(rva)

    def overlap_by_class(self):
        """Overlap bytes grouped by the class pair that produced them."""
        merged = {}
        for (existing, new), count in self.overlap_by_origin.items():
            merged[(existing, new)] = merged.get((existing, new), 0) + count
        return dict(sorted(merged.items(), key=lambda item: -item[1]))

    def covered_in(self, start, end):
        """Bytes claimed at least once within [start, end)."""
        start = max(start, 0)
        end = min(end, len(self._covered))
        return sum(self._covered[start:end]) if end > start else 0

    def decoded_rvas(self):
        """Every RVA an instruction starts at, ascending.

        The decoded set is the size bytearray itself, so this is a scan rather
        than a set to maintain. Callers that want to walk the whole decode
        again (access tracing, say) get it without the run having kept one.
        """
        return [rva for rva, size in enumerate(self._size_at) if size]

    def is_covered(self, rva):
        """Whether any instruction claimed this byte.

        Separate from covered_in because scanning a section for uncovered runs
        asks this per byte, and slicing a bytearray per byte is a great deal of
        allocation to answer one question.
        """
        return 0 <= rva < len(self._covered) and self._covered[rva] != 0
