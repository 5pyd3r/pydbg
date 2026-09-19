"""StaticAnalyzer — recursive descent to a fixpoint, without a live process."""

from .decoder import InstructionDecoder
from .functions import FunctionTable
from .image import AnalyzedImage
from .model import AnalysisResult, AnalysisStats, CoverageReport, RefKind, SeedConfig, Xref
from .refs import branch_target, classify_refs, memory_address
from .seeds import SeedProvider, looks_like_entry


class StaticAnalyzer:
    """Recover function boundaries and cross-references from an image alone.

    The traversal is recursive descent with a worklist, run to a fixpoint: a
    function reached only by a direct call from another discovered function is
    still found, because discovering a call queues its target. One pass over a
    fixed seed list drops coverage from 99% to 7% on a real binary — the
    difference is entirely the functions that only a call reveals.
    """

    def __init__(self, image, mode=None, config=None):
        if not isinstance(image, AnalyzedImage):
            image = AnalyzedImage.from_pe(image, mode=mode)
        self.image = image
        self.config = config or SeedConfig()
        self.decoder = InstructionDecoder(
            image, mode=mode, cache_size=self.config.decode_cache_size)
        self.functions = FunctionTable(image)
        self.xrefs = {}
        self.undecodable = set()
        self.stats = AnalysisStats()
        self._pending = []
        self._queued = set()
        self._xref_targets = set()
        # RVAs of the import address table slots, so a branch through one can be
        # recognised as a thunk rather than an ordinary indirect call.
        self._iat_slots = {entry.rva for entry in self.image.pe.imports
                           if entry.rva}

    # ── public entry point ─────────────────────────────────────

    def run(self):
        """Seed, sweep to a fixpoint, and return the result."""
        seeds = SeedProvider(self.image).collect()
        self.stats.seed_functions = len(seeds.confident)
        for rva in sorted(seeds.confident):
            # Something calls, exports, or registers these — evidence, so a
            # branch into them is a function entry.
            self._enqueue(rva, confident=True)
        for rva in sorted(seeds.tentative):
            # Pointer-shaped evidence only. Decoded, but not claimed as an
            # entry: that is the whole reason the two sets are separate.
            self._enqueue_code_seed(rva)

        self.stats.sweep_rounds = 0
        while self._pending:
            self.stats.sweep_rounds += 1
            batch, self._pending = self._pending, []
            for rva in batch:
                self._sweep_from(rva)

        self.functions.invalidate()
        self._finish_stats()
        return AnalysisResult(
            image=self.image,
            functions=self.functions,
            xrefs=self._freeze_xrefs(),
            stats=self.stats,
            coverage=self._coverage(),
            undecodable=tuple(sorted(self.undecodable)),
            decoder=self.decoder,
        )

    # ── seeding ────────────────────────────────────────────────

    def _enqueue(self, rva, confident=False):
        if rva is None or not self.image.is_mapped(rva):
            return False
        if not self.image.is_exec(rva):
            return False
        self.functions.add_start(rva, confident=confident)
        if rva not in self._queued:
            self._queued.add(rva)
            self._pending.append(rva)
            return True
        return False

    def _seed_branch_target(self, insn, target):
        """Decide what a branch target is, and register it as that.

        A call target is a function entry, full stop. A jump target is not:
        most of them are blocks *inside* the current function — the target of
        an `if`, a loop head — and registering those as entries cuts the
        function into pieces at every branch, which is what makes an extent
        stop in the middle of a function and a CFG run off its own end.

        A jump target that does look like an entry is kept as a tentative one:
        a tail call (`jmp other_function`) lands on a function start, and the
        byte before it is typically padding. Everything else is decoded as a
        code seed, which finds the code without claiming to have found a
        function.
        """
        if insn.is_call:
            self._enqueue(target, confident=True)
        elif looks_like_entry(self.image, target):
            self._enqueue(target, confident=False)
        else:
            self._enqueue_code_seed(target)

    def _enqueue_code_seed(self, rva):
        """Queue an address for decoding without claiming it starts a function.

        This is where pointer-derived seeds go. A switch-table case body and a
        misread data value are both things worth decoding and neither is a
        function entry; recording them as one corrupts every extent that spans
        them.
        """
        if rva is None or not self.image.is_mapped(rva):
            return False
        if not self.image.is_exec(rva):
            return False
        self.functions.add_code_seed(rva)
        if rva not in self._queued:
            self._queued.add(rva)
            self._pending.append(rva)
            return True
        return False

    # ── traversal ──────────────────────────────────────────────

    def _sweep_from(self, start, budget=None):
        """Follow control flow forward from 'start' until it stops.

        A conditional jump continues to its fallthrough as well as queueing its
        target: treating it as terminal silently drops every false branch. A
        call queues its target but does not follow it inline — the callee is a
        function, not part of this one's straight-line flow. 'ret' and an
        unconditional jump end the path.

        Stops at an already-decoded instruction. Two sweeps reaching the same
        address is normal (a shared tail, a jump target that is also a
        fallthrough), and without this the second sweep would re-claim those
        bytes and inflate the overlap count — the very number that is supposed
        to measure how much of the decode is untrustworthy.
        """
        budget = budget or self.config.max_instructions
        addr = start

        while budget > 0:
            if self.decoder.is_decoded(addr):
                break

            insn = self.decoder.decode_one(addr)
            if insn is None:
                self.undecodable.add(addr)
                break

            budget -= 1
            self.decoder.mark_covered(addr, insn.size)
            self.functions.note_instruction(addr, insn.size)
            self._record_refs(insn, addr)

            target = branch_target(insn, self.image)
            if target is not None and self.image.is_exec(target):
                self.functions.add_call_target(target)
                self._seed_branch_target(insn, target)

            if insn.is_ret:
                break
            if insn.is_jmp and not insn.is_cond:
                break                     # unconditional: this path is done

            addr += insn.size

        return budget

    def _record_refs(self, insn, rva):
        """Record 'insn' references. 'rva' is passed explicitly because the
        Instruction's own address is a VA (see InstructionDecoder.decode_one)."""
        if not self.config.collect_xrefs:
            return
        for target, kind in classify_refs(insn, self.image):
            self.xrefs.setdefault(target, []).append(Xref(rva, int(kind)))
            self._xref_targets.add(target)
            if kind == RefKind.IMM and self.image.is_exec(target):
                # An immediate landing in code is a candidate entry the call
                # graph did not reveal; queued so the fixpoint can decide.
                self._enqueue(target)
            elif kind == RefKind.TABLE:
                self._absorb_jump_table(target)

        self._absorb_indirect_jump(insn)
        self._note_if_thunk(insn, rva)

    def _absorb_indirect_jump(self, insn):
        """Read a switch table that is reached through one memory operand.

        On x86 a jump table appears as `jmp [reg*4 + table]`, whose
        displacement is the table base — that arrives as a TABLE reference and
        is handled above. On x64 the usual form is `jmp qword ptr [rip+disp]`,
        where no index register is visible at all: the displacement names the
        slot directly, so it is classified as an ordinary memory reference and
        the table is invisible unless it is read here.

        Reading it is safe for the other case it matches: an indirect jump
        through a single function pointer yields that one target, which is a
        code seed either way.
        """
        if not insn.is_jmp or insn.is_call:
            return
        for op in insn.operands:
            address = memory_address(insn, op, self.image)
            if address is not None:
                self._absorb_jump_table(address)

    def _note_if_thunk(self, insn, rva):
        """Register `jmp [IAT slot]` stubs as the function entries they are.

        An import thunk is a one-instruction function, and the compiler emits
        one per imported API. Nothing calls it directly — callers go through
        the thunk — so a call graph built without this knows the call sites but
        not the functions they reach.

        Only a jump counts: `call [IAT]` is an ordinary call through the import
        table from inside a real function, and treating those as entries would
        invent a function at every import call site.
        """
        if not insn.is_jmp or insn.is_call or not self._iat_slots:
            return
        for op in insn.operands:
            if memory_address(insn, op, self.image) in self._iat_slots:
                self.functions.add_start(rva, confident=True)
                return

    def _absorb_jump_table(self, table_rva, max_entries=512):
        """Read a switch table's entries as code seeds.

        They are case bodies, not function entries — so they are decoded and
        named as code seeds only. Recording them as starts would cut every
        function that contains a switch into pieces at each case.
        """
        stride = self.image.slot_size
        for index in range(max_entries):
            value = self.image.read_pointer(table_rva + index * stride)
            if value is None:
                break
            rva = self.image.va_to_rva(value)
            if rva is None or not self.image.is_exec(rva):
                break                  # tables are packed; the run has ended
            self._enqueue_code_seed(rva)

    # ── results ────────────────────────────────────────────────

    def _freeze_xrefs(self):
        return {target: tuple(sorted(set(refs), key=lambda r: (r.source, r.kind)))
                for target, refs in self.xrefs.items()}

    def _coverage(self):
        report = {}
        for section in self.image.sections:
            if not section.is_exec:
                continue
            start = section.virtual_address
            end = start + section.virtual_size
            report[section.name] = CoverageReport(
                covered=self.decoder.covered_in(start, end),
                total=max(section.virtual_size, 0),
                overlap_bytes=self.decoder.overlap_bytes,
            )
        return report

    def _finish_stats(self):
        stats = self.stats
        stats.insns = self.decoder.instructions
        stats.func_starts = len(self.functions.starts)
        stats.func_starts_confident = len(self.functions.confident)
        stats.xref_targets = len(self._xref_targets)
        stats.xrefs = sum(len(v) for v in self.xrefs.values())
        stats.overlap_bytes = self.decoder.overlap_bytes
        stats.overlap_conflicts = self.decoder.overlap_conflicts


def analyze_file(path, **kwargs):
    """Analyze a PE on disk. No process is created."""
    return StaticAnalyzer(AnalyzedImage.from_file(path), **kwargs).run()


def analyze_bytes(data, **kwargs):
    """Analyze PE bytes."""
    return StaticAnalyzer(AnalyzedImage.from_bytes(data), **kwargs).run()


def analyze_pe(pe, **kwargs):
    """Analyze an already-parsed PE."""
    return StaticAnalyzer(AnalyzedImage.from_pe(pe), **kwargs).run()


def analyze_process(session, base_address, mode=None, module_size=None, **kwargs):
    """Analyze a module inside a live process.

    The bytes come from the target rather than a file, so the image base is the
    module's RUNTIME base — which is the whole point of passing it here. An
    ASLR'd module sits away from its preferred ImageBase, and testing its
    addresses against the preferred one puts every operand outside the window,
    giving an empty result that reports success.

    'module_size' bounds the reads; without it a read past the end of the
    module walks into whatever is mapped next.
    """
    image = AnalyzedImage.from_process(session, base_address, mode=mode,
                                       module_size=module_size)
    return StaticAnalyzer(image, **kwargs).run()
