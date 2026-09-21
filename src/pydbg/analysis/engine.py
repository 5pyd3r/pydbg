"""StaticAnalyzer — recursive descent to a fixpoint, without a live process."""

from .access import STACK_REGISTERS, base_relative_access, stack_register_ids
from .consts import ConstantTracker
from .decoder import InstructionDecoder
from .functions import FunctionTable
from .image import AnalyzedImage
from .model import (
    AnalysisResult, AnalysisStats, CoverageReport, IndirectSite, RefKind,
    SeedConfig, SlotTable, Xref,
)
from .refs import (
    branch_target, classify_refs, is_indirect_branch, memory_address,
)
from .seeds import SeedProvider, looks_like_entry

# Names for the causes a decode can be charged to. Seed classes come from
# SeedProvider; these are the roots discovered *during* a sweep, which are
# charged to themselves so that a conflict between two admitted callers reads
# differently from one between two seed sources.
CALL_TARGET = "call_target"
JUMP_TARGET = "jump_target"
JUMP_TABLE = "jump_table"
IMMEDIATE = "immediate"
DISCOVERED = "discovered"


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
        self.indirect_sites = {}
        # thunk rva -> the IAT slot it jumps through
        self.import_thunks = {}
        # table base rva -> SlotTable. Keyed by base because the same table can
        # be named by more than one indexing instruction.
        self._slot_tables = {}
        self._accesses = []
        self._stack_ids = frozenset()

        self.stats = AnalysisStats()
        # Set here as well as in run(), so a caller driving sweeps directly
        # (tests do) is not depending on run() having gone first.
        self._budget_left = self.config.max_total_instructions
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
        seeds = SeedProvider(self.image).collect(self.config.seed_classes)
        self.stats.seed_functions = len(seeds.confident)
        self._record_pointer_refs(seeds)

        # Which class produced each seed, so a sweep can be attributed to its
        # cause. Seeded addresses win over follow-ons: the same address reached
        # both ways is the seed class's doing.
        origin_of = {}
        for kind, rvas in seeds.found.items():
            for rva in rvas:
                origin_of.setdefault(rva, kind)

        for rva in sorted(seeds.confident):
            # Something calls, exports, or registers these — evidence, so a
            # branch into them is a function entry.
            self._enqueue(rva, confident=True, origin=origin_of.get(rva))
        for rva in sorted(seeds.tentative):
            # Pointer-shaped evidence only. Decoded, but not claimed as an
            # entry: that is the whole reason the two sets are separate.
            self._enqueue_code_seed(rva, origin=origin_of.get(rva))

        self.stats.sweep_rounds = 0
        while self._pending:
            self.stats.sweep_rounds += 1
            batch, self._pending = self._pending, []
            for rva, origin in batch:
                if self._budget_left <= 0:
                    self.stats.budget_exhausted = True
                    self._pending = []
                    break
                self._sweep_from(rva, origin)

        # Only once every trusted start is known: the check is about one
        # start falling inside another, which cannot be answered while the
        # traversal is still discovering them.
        self.stats.pruned_starts = self.functions.prune_starts_inside_functions()
        self.functions.invalidate()
        xrefs = self._freeze_xrefs()
        self._finish_stats(xrefs)
        return AnalysisResult(
            image=self.image,
            functions=self.functions,
            xrefs=xrefs,
            stats=self.stats,
            xref_gaps=self._xref_gaps(seeds),
            coverage=self._coverage(),
            undecodable=tuple(sorted(self.undecodable)),
            indirect_sites=tuple(self.indirect_sites[rva]
                                 for rva in sorted(self.indirect_sites)),
            import_thunks=dict(self.import_thunks),
            slot_tables=tuple(self._slot_tables[rva]
                              for rva in sorted(self._slot_tables)),
            access_records=(tuple(self._accesses)
                            if self.config.collect_accesses else None),
            decoder=self.decoder,
        )

    # ── seeding ────────────────────────────────────────────────

    def _record_pointer_refs(self, seeds):
        """Turn pointer-class seeds into DATA cross-references.

        The index used to be built from decoded instructions only, which is a
        definition rather than a bug and is why the empty answer looked right:
        a vtable entry is not an instruction, so no amount of decoding finds
        it. The readers that do find it were already there and threw the
        positions away after using them as decode seeds.

        Only the index gains an entry. Confidence is untouched on purpose — a
        pointer is evidence that something *names* an address, never that
        anything calls it, and the two sets are kept apart for exactly this
        reason. A tentative start stays tentative.
        """
        for target, slot in seeds.pointers:
            self._add_data_ref(target, slot)

    def _add_data_ref(self, target, slot):
        """Record that the image holds a pointer to 'target' at 'slot'."""
        if not self.config.collect_xrefs:
            return
        self.xrefs.setdefault(target, []).append(Xref(slot, int(RefKind.DATA)))
        self._xref_targets.add(target)

    def _xref_gaps(self, seeds):
        """Why this run's reference index may be missing whole classes.

        Both halves of an honest 'nothing references this' belong together:
        the index itself, and the statement of what went into it. Every entry
        here is a case where the index is short by construction rather than by
        what is in the image, so a caller can assert the absence of them
        before treating an empty `callers_of` as a fact.

        Unresolved indirect branches are deliberately not listed — they are
        per-site holes rather than missing classes, and `indirect_call_sites`
        already reports them.
        """
        if not self.config.collect_xrefs:
            return ("xref collection is off (SeedConfig.collect_xrefs=False): "
                    "the index is empty",)
        gaps = []
        enabled = self.config.seed_classes
        for name in ("data_pointers", "relocation_pointers"):
            if enabled is not None and name not in enabled:
                gaps.append(f"seed class '{name}' was not run: no DATA "
                            f"references from it")
        for name in sorted(seeds.truncated):
            gaps.append(f"seed class '{name}' stopped at its ceiling: its "
                        f"references are truncated")
        if self.stats.budget_exhausted:
            gaps.append("the instruction ceiling stopped the sweep: the index "
                        "is truncated")
        return tuple(gaps)

    def _enqueue(self, rva, confident=False, origin=None):
        if rva is None or not self.image.is_mapped(rva):
            return False
        if not self.image.is_exec(rva):
            return False
        self.functions.add_start(rva, confident=confident)
        if rva not in self._queued:
            self._queued.add(rva)
            self._pending.append((rva, origin or DISCOVERED))
            return True
        return False

    def _resolve_indirect(self, insn, rva, tracker):
        """Try to turn an indirect branch into a real edge.

        Either outcome is recorded. Resolved branches become ordinary BRANCH
        cross-references — the call graph gains the edge it was missing. The
        rest are kept as sites, because a function with no recorded callers and
        a function whose callers are all indirect look identical otherwise, and
        one target's entry point really was reachable only through
        `call [esi+0x18]`.
        """
        target = tracker.resolve_branch(insn)
        if target is None:
            self.indirect_sites[rva] = IndirectSite(
                rva=rva, is_call=bool(insn.is_call), text=insn.op_str)
            return None

        self.xrefs.setdefault(target, []).append(Xref(rva, int(RefKind.BRANCH)))
        self._xref_targets.add(target)
        self.stats.indirect_resolved += 1
        return target

    def _seed_branch_target(self, insn, target, origin=None):
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
            self._enqueue(target, confident=True, origin=origin)
        elif looks_like_entry(self.image, target, decoder=self.decoder):
            self._enqueue(target, confident=False, origin=origin)
        else:
            self._enqueue_code_seed(target, origin=origin)

    def _enqueue_code_seed(self, rva, origin=None):
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
            self._pending.append((rva, origin or DISCOVERED))
            return True
        return False

    # ── traversal ──────────────────────────────────────────────

    def _sweep_from(self, start, origin=None, budget=None):
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
        # Bounded by both the per-sweep limit and what is left of the
        # whole-run ceiling.
        budget = min(budget or self.config.max_instructions,
                     self._budget_left)
        granted = budget
        tracker = ConstantTracker(self.image)
        addr = start

        while budget > 0:
            if self.decoder.is_decoded(addr):
                break

            insn = self.decoder.decode_one(addr)
            if insn is None:
                self.undecodable.add(addr)
                break

            budget -= 1
            if self.config.collect_accesses:
                self._note_access(addr, insn)
            self.decoder.mark_covered(addr, insn.size, origin)
            self.functions.note_instruction(addr, insn.size)
            self._record_refs(insn, addr)

            target = branch_target(insn, self.image)
            indirect = target is None and is_indirect_branch(insn)
            if indirect:
                target = self._resolve_indirect(insn, addr, tracker)

            if target is not None and self.image.is_exec(target):
                self.functions.add_call_target(target)
                # Follow-on roots carry their own cause, not the sweep they
                # were found in: a conflict between two admitted callers is a
                # different problem from one between two seed sources.
                cause = CALL_TARGET if insn.is_call else JUMP_TARGET
                if indirect and not insn.is_call:
                    # A resolved indirect jump goes wherever the data says, and
                    # the data cannot say whether that is a switch case body or
                    # a tail-called function. Decode it; do not name it — the
                    # same treatment a jump-table entry gets, and for the same
                    # reason: claiming one cuts the function containing the
                    # switch apart at every case.
                    self._enqueue_code_seed(target, origin=cause)
                else:
                    self._seed_branch_target(insn, target, origin=cause)

            # After the branch has been resolved: observe() forgets everything
            # on an instruction it does not recognise, and every branch is one.
            tracker.observe(insn)

            if insn.is_ret:
                break
            if insn.is_jmp and not insn.is_cond:
                break                     # unconditional: this path is done

            addr += insn.size

        self._budget_left -= granted - max(budget, 0)
        if budget <= 0:
            # The sweep ran out rather than finishing: whatever it was
            # following is now half-traversed, and saying so is the whole point
            # of the ceiling. A run that stopped early and reported nothing
            # would read as a complete analysis of a small binary.
            self.stats.budget_exhausted = True
        return budget

    def _note_access(self, rva, insn):
        """Record a base-relative access, if this instruction makes one.

        Done here rather than in a second pass afterwards: the sweep is
        already holding the instruction, and re-deriving it later means
        decoding the whole image again — half a minute on a system DLL for
        data that was in hand.
        """
        if not self._stack_ids:
            self._stack_ids = stack_register_ids(self.image.mode,
                                                 STACK_REGISTERS)
        resolved = base_relative_access(insn, stack_ids=self._stack_ids)
        if resolved is None:
            return
        # A displacement at or beyond the image base is not a field offset —
        # it is an absolute address formed through a register, which
        # position-independent code does constantly. `[eax + 0x400000]` is the
        # image's own base; no structure is four megabytes wide.
        if abs(resolved[1]) >= self.image.image_base:
            return
        self._accesses.append((rva,) + resolved)

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
                self._enqueue(target, origin=IMMEDIATE)
            elif kind == RefKind.TABLE:
                self._absorb_jump_table(target, origin=JUMP_TABLE,
                                        referrer=rva)

        self._absorb_indirect_jump(insn, rva)
        self._note_if_thunk(insn, rva)

    def _absorb_indirect_jump(self, insn, rva):
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
                self._absorb_jump_table(address, origin=JUMP_TABLE,
                                        referrer=rva)

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
            slot = memory_address(insn, op, self.image)
            if slot in self._iat_slots:
                self.functions.add_start(rva, confident=True)
                # Which import it reaches is what turns `sub_401234` into
                # `CreateFileW`, so the slot is kept, not just the fact.
                self.import_thunks[rva] = slot
                return

    def _absorb_jump_table(self, table_rva, max_entries=512, origin=None,
                           referrer=None):
        """Read a switch table's entries as code seeds, and as references.

        They are case bodies, not function entries — so they are decoded and
        named as code seeds only. Recording them as starts would cut every
        function that contains a switch into pieces at each case.

        Each entry is also a data slot holding a code address, so it is
        recorded as a DATA reference like any other pointer. It is the same
        statement the reading of the table makes, and a case body reached only
        through the table otherwise has no reference to show.

        The table's own identity is kept as well. Reading it already computes
        {base, count, stride} and used to throw all three away, leaving the
        slots reachable only by asking "what points at this address" — which
        answers a different question and does not say where the run of slots
        begins or ends. A byte sitting inside a table embedded in .text is
        otherwise indistinguishable from one sitting inside a function, and
        that is the shape this exists to name.
        """
        stride = self.image.slot_size
        count = 0
        truncated = False
        for index in range(max_entries):
            slot_rva = table_rva + index * stride
            value = self.image.read_pointer(slot_rva)
            if value is None:
                break
            rva = self.image.va_to_rva(value)
            if rva is None or not self.image.is_exec(rva):
                break                  # tables are packed; the run has ended
            self._add_data_ref(rva, slot_rva)
            self._enqueue_code_seed(rva, origin=origin)
            count += 1
        else:
            # The loop ran out of budget rather than out of table. Saying so is
            # the difference between "this table has 512 entries" and "this
            # table has at least 512", and the second is not a table size.
            truncated = count > 0

        if count == 0:
            return None
        # Two jump instructions may index the same table. The longer reading
        # wins: a short one means the reader stopped early, and reporting the
        # shorter count would understate a table both readings agree exists.
        known = self._slot_tables.get(table_rva)
        if known is not None and known.count >= count:
            return known
        table = SlotTable(base=table_rva, count=count, stride=stride,
                          kind="jump_table", referrer=referrer,
                          truncated=truncated)
        self._slot_tables[table_rva] = table
        return table

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

    def _finish_stats(self, xrefs):
        stats = self.stats
        stats.insns = self.decoder.instructions
        stats.func_starts = len(self.functions.starts)
        stats.func_starts_confident = len(self.functions.confident)
        stats.xref_targets = len(self._xref_targets)
        stats.xrefs = sum(len(v) for v in self.xrefs.values())
        # Counted from the frozen index, not from what was recorded: the
        # relocation and data-pointer readers overlap, and the number worth
        # reporting is how many DATA entries the index actually carries.
        stats.data_refs = sum(1 for refs in xrefs.values() for ref in refs
                              if ref.kind == int(RefKind.DATA))
        stats.overlap_bytes = self.decoder.overlap_bytes
        stats.overlap_conflicts = self.decoder.overlap_conflicts
        stats.indirect_unknown = len(self.indirect_sites)


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
