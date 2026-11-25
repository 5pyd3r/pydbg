"""BBL detours: plan blocks, install stubs, drain events, undo.

One detour per planned block: an `E9 rel32` over the block's displaced prefix,
and a target-side stub that appends one v1 BLOCK record per hit before running
the relocated prefix (spec §12.2, §12.5).

The three halves live in their own modules and are re-exported here, so callers
(and the existing tests) keep importing them from `pydbg.instrument.bbl`:

- `relocate.py` — `UnsupportedInstruction`, `take_prefix`,
  `prefix_is_relocatable`, `relocate_prefix`: the displaced instructions;
- `stub.py` — `build_stub`, `STUB_PROLOGUE_SIZE`, the record layout: the
  target-side writer;
- `patch.py` — `TargetBusy`, `InstalledPatch`, `install_patch`,
  `uninstall_patch`: the thread-checked writes.

What is left here is the orchestration: `BlockPlan`, `InstallReport`,
`BblInstrumenter`, and the near-allocation policy for the stub region. A plan
is a record in RVAs; `install()` converts once, at the boundary where the RIP
window, the E9 and the stub addresses are absolute.

This module never imports `_pydbg`: the near allocation goes through
`MemoryManager.alloc_near`, and the extension is only reached by a caller with
a live target. Importing `pydbg.instrument.bbl` therefore stays extension-free
(ADR-0001).
"""

import struct
from dataclasses import dataclass

from ..exceptions import PydbgError
from ..patch.encoding import build_abs_jmp

from .patch import (
    BYTES_CHANGED,
    InstalledPatch,
    TargetBusy,
    install_patch,
    uninstall_patch,
)
from .relocate import (
    DETOUR_SIZE,
    UnsupportedInstruction,
    decoder_address_base,
    prefix_is_relocatable,
    relocate_prefix,
    take_prefix,
)
from .stub import (
    RECORD_SIZE,
    STUB_JUMP_SIZE,
    STUB_PROLOGUE_SIZE,
    build_stub,
    keystone,
)

# Re-exported so the module split does not change an import that already works;
# `__all__` is what tells a linter these are re-exports, not dead imports.
__all__ = [
    'BblInstrumenter', 'BlockPlan', 'DETOUR_SIZE', 'InstallReport',
    'InstalledPatch', 'RECORD_SIZE', 'STUB_PROLOGUE_SIZE', 'TargetBusy',
    'UnsupportedInstruction', 'alloc_near', 'build_stub', 'install_patch',
    'keystone', 'prefix_is_relocatable', 'relocate_prefix', 'take_prefix',
    'uninstall_patch',
]

# ── orchestration ───────────────────────────────────────────────
#
# The plan is a record, not a live object: it says where a block is, how far it
# runs, which instructions it holds and whether the bytes a detour would
# displace can be executed from the stub. `install()` re-reads the same facts
# from the decoder rather than trusting a plan someone may have edited, which
# is why a block that was planned as unrelocatable still gets its exact reason
# from `relocate_prefix` instead of a generic "not planned".

# A ceiling on the instructions one explicit block start may decode. A block
# ends at a branch or a return, so this only trips on a decoder that never
# terminates; refusing to loop forever is worth more than the exact number.
_MAX_BLOCK_INSTRUCTIONS = 4096

# How far from the module a stub may land. A 5-byte E9 is a rel32 jump, so the
# stub has to be within ±2GB; the window stays below the hard 2^31 limit
# because the E9 itself takes five of those bytes.
_RELOC_WINDOW = 0x7F000000


def alloc_near(dbg, near, size):
    """Allocate `size` RWX bytes within the E9's reach of `near`; return it.

    The scan and the VirtualAllocEx call belong to `MemoryManager.alloc_near`
    (the manager owns remote allocation as of P35); this keeps the BBL policy
    on top: the conservative `_RELOC_WINDOW` so even the far edge of a module
    is inside a rel32, and the target handle the manager already holds. Kept
    as the module-level seam the install path and its tests pick, instead of
    reaching into `dbg.memory` in two places.

    `_pydbg` is not imported here: the manager already owns the extension
    (ADR-0001), so importing this module stays extension-free.

    Raises:
        PydbgError: the manager's near allocation failed; its message names
            every candidate it could not use.
    """
    return dbg.memory.alloc_near(size, near, limit=_RELOC_WINDOW)


def _ring_capacity(max_events):
    """The smallest power of two that can hold `max_events` records.

    EventBuffer indexes slots with `count & (capacity - 1)`, so the capacity
    must be a power of two. Sizing it from `max_events` means a single
    `events()` call can return the whole budget without the ring wrapping
    first; `events()` still truncates to exactly `max_events`.
    """
    if max_events is None or max_events < 1:
        return 1
    return 1 << (max_events - 1).bit_length()


@dataclass(frozen=True)
class BlockPlan:
    """One block a detour would be placed on, and how much it would displace.

    Attributes:
        rva: the block entry, module-relative.
        span: bytes from `rva` to the end of the last instruction the decoder
            gave for the block. 0 when nothing decoded there.
        instruction_rvas: the block's instruction addresses, module-relative,
            ascending. The record's `a` field carries the length of this tuple.
        prefix_size: bytes the detour displaces -- the shortest run of whole
            instructions covering `DETOUR_SIZE` bytes. 0 means the block is
            shorter than a detour (or nothing decoded), so there is no prefix
            to take; such a block is still planned and refused at install time.
        relocatable: whether `prefix_size` bytes can run from the stub
            unchanged. False when there is no prefix, or when a branch/return
            sits in it (rewriting rel8/rel32 is out of scope, spec §12.6).
    """

    rva: int
    span: int
    instruction_rvas: tuple
    prefix_size: int
    relocatable: bool


@dataclass(frozen=True)
class InstallReport:
    """What one `BblInstrumenter.install()` managed to place.

    `installed` holds the RVAs of the blocks whose detour is in the target;
    `refused` holds `(rva, reason)` for every other planned block, so
    `len(installed) + len(refused)` is the plan size and no block is silently
    skipped. `warnings` collects cleanup that did not raise -- a thread that
    could not be resumed, a page protection that stayed writable, an event
    buffer released while some detours remain.
    """

    installed: tuple = ()
    refused: tuple = ()
    warnings: tuple = ()


class BblInstrumenter:
    """Plan, install, read and remove BBL detours in one module.

    The sequence (the target should be paused while `plan()` reads its image)::

        instrumenter = BblInstrumenter(dbg)
        instrumenter.plan()               # () means "not analysable"
        report = instrumenter.install()   # per-block success and refusals
        dbg.continue_event(...)           # let the target run
        ...                               # stop it again at any debug event
        events = instrumenter.events()    # drain the target-side ring
        warnings = instrumenter.uninstall()

    Nothing is automatic. The stub appends to a target-side ring, so events can
    only be drained at a stop point; `events()` does not stop the target and
    `uninstall()` does not disarm it. The caller decides when the target is
    quiet, reads, and then restores. `uninstall()` leaves the detours in place
    when a thread is parked inside one, because freeing the stub region under a
    live detour would turn a refused cleanup into a crash.

    Only x64 is supported (spec §12.1): the thread window check needs RIP.
    """

    def __init__(self, dbg, module=None, *, result=None, blocks=None,
                 max_blocks=4096, max_events=100_000):
        """Bind the instrumenter to a debugger and one module.

        Args:
            dbg: A `Debugger` with a target created or attached.
            module: A module dict from `dbg.enum_modules()`, a
                `(base_address, size)` tuple, or None for the main module.
            result: A precomputed `AnalysisResult`. None analyzes the module
                with `analyze_process` on first `plan()`; a caller that
                already has the result avoids a second sweep.
            blocks: An explicit iterable of block-start RVAs. When given it
                replaces the CFG-derived block list; the analysis (or
                `result`) is still used to decode each block and to discard
                starts outside an executable section.
            max_blocks: Never plan more block starts than this.
            max_events: The most events `events()` returns per call. The ring
                is sized to the next power of two at or above it, so a burst
                between two reads is retained up to that size.
        """
        self.dbg = dbg
        self.module = module
        self.max_blocks = max_blocks
        self.max_events = max_events
        self._result = result
        self._block_starts = None if blocks is None else tuple(blocks)
        self._analysis = None
        self._base = None
        self._plans = None
        self._buffer = None
        self._stub_region = None
        self._report = None
        # absolute address -> the InstalledPatch record, in install order. This
        # mapping *is* the "still installed" set: a record leaves it only when
        # its restore landed (or the bytes were already original), so a block
        # whose restore was refused or whose bytes changed under us keeps both
        # its record and the stub memory the record may still point into.
        self._originals = {}

    # ── planning ───────────────────────────────────────────────

    def plan(self):
        """The blocks this instrumenter would detour, sorted by RVA.

        The block starts come from the same CFG walk as `BblTracer.plan()`:
        every recovered function's `cfg_of`, blocks with instructions, filtered
        to executable sections and capped by `max_blocks`. What the tracer threw
        away -- the block's span, its instruction list, the detour prefix and
        whether that prefix can move -- is kept here, because install needs it.

        `blocks=` replaces the block starts with an explicit list; the analysis
        is still consulted for decoding and the exec filter. Duplicates are
        collapsed and the result is sorted.

        A module whose analysis fails is not an exception: the answer is `()`,
        "nothing can be planned here", the same contract `BblTracer.plan()`
        offers. The plan is computed once; later calls return the same tuple.
        """
        if self._plans is not None:
            return self._plans
        result = self._analysis_of()
        if result is None:
            self._plans = ()
            return self._plans

        plans = {}
        if self._block_starts is not None:
            for start in self._block_starts:
                if len(plans) >= self.max_blocks:
                    break
                if start in plans or not result.image.is_exec(start):
                    continue
                instruction_rvas, instructions = self._decode_block(result, start)
                plans[start] = self._make_plan(
                    start, instruction_rvas, instructions)
        else:
            from ..analysis.cfg import cfg_of

            for function in result.functions.functions():
                if len(plans) >= self.max_blocks:
                    break
                cfg = cfg_of(result, function.rva)
                if cfg is None:
                    continue
                for block in cfg.blocks.values():
                    if len(plans) >= self.max_blocks:
                        break
                    if block.rva in plans or not block.instructions:
                        continue        # undecodable: nothing to displace
                    if not result.image.is_exec(block.rva):
                        continue        # data, not code
                    instructions = self._decode_rvas(result, block.instructions)
                    plans[block.rva] = self._make_plan(
                        block.rva, block.instructions, instructions)

        self._plans = tuple(plans[rva] for rva in sorted(plans))
        return self._plans

    def _analysis_of(self):
        """The analysis result, running one if the caller did not supply it."""
        if self._analysis is not None:
            return self._analysis
        if self._result is not None:
            self._analysis = self._result
            return self._analysis

        from ..analysis import analyze_process
        from ..trace import _shared

        module = _shared.find_module(self.dbg, self.module)
        if module is None:
            return None
        base, _ = _shared.module_region(module)
        if not base:
            return None
        self._base = base
        module_size = _shared.module_size(self.dbg, module)
        try:
            self._analysis = analyze_process(
                self.dbg._session, base, module_size=module_size)
        except (PydbgError, OSError, ValueError, struct.error):
            self._analysis = None
        return self._analysis

    @staticmethod
    def _decode_rvas(result, instruction_rvas):
        """Decode known instruction addresses, stopping at the first gap."""
        decoded = []
        for rva in instruction_rvas:
            instruction = result.decoder.decode_one(rva)
            if instruction is None:
                break
            decoded.append(instruction)
        return tuple(decoded)

    @staticmethod
    def _decode_block(result, start):
        """(instruction_rvas, instructions) for a block starting at `start`.

        Used for an explicit `blocks=` list, where the CFG does not already
        name the block's instructions. A call falls through (it returns); a
        branch or a return ends the block, which is the same rule
        `build_function_cfg` applies.
        """
        instruction_rvas = []
        instructions = []
        address = start
        while len(instructions) < _MAX_BLOCK_INSTRUCTIONS:
            instruction = result.decoder.decode_one(address)
            if instruction is None or instruction.size <= 0:
                break
            instruction_rvas.append(address)
            instructions.append(instruction)
            if instruction.is_ret or instruction.is_jmp:
                break
            address += instruction.size
        return tuple(instruction_rvas), tuple(instructions)

    @staticmethod
    def _make_plan(rva, instruction_rvas, instructions):
        """One BlockPlan from the decoded run at `rva`."""
        span = 0
        prefix_size = 0
        relocatable = False
        if instructions and instruction_rvas:
            # The decoder addresses instructions by VA while the plan is in
            # RVAs. `address_base` bridges the two: relocation still uses the
            # decoder's addresses, every refusal names an RVA.
            address_base = decoder_address_base(instruction_rvas, instructions)
            last = instructions[-1]
            span = last.address + last.size - (rva + address_base)
            try:
                prefix = take_prefix(
                    instructions, rva, address_base=address_base)
            except UnsupportedInstruction:
                pass                      # no prefix: planned, refused at install
            else:
                prefix_size = sum(instruction.size for instruction in prefix)
                relocatable = prefix_is_relocatable(prefix)
        return BlockPlan(rva=rva, span=span,
                         instruction_rvas=tuple(instruction_rvas),
                         prefix_size=prefix_size, relocatable=relocatable)

    # ── installing ─────────────────────────────────────────────

    def install(self):
        """Write one detour and one stub per relocatable block.

        The event ring and the stub region are allocated once for the whole
        instrumenter, not per block: every stub embeds the same ring addresses,
        and every detour has to reach its stub through a 5-byte E9.

        Each block is installed independently. A refused block -- a thread
        parked inside its window, a branch in its prefix, a block shorter than
        the detour, a pre-image that is no longer what the plan read, a thread
        enumeration that fails -- goes into `InstallReport.refused` with the
        exception's message, and the remaining blocks are still attempted.
        `len(installed) + len(refused)` is exactly the plan size. Failures of a
        shared resource (the ring, the stub region, a missing keystone) become
        one reason per block for the same reason: no planned block may be
        silently skipped.

        The plan speaks RVAs; the install is in VAs (`base + plan.rva`), because
        the RIP window, the E9 destination and the stub it points at are all
        absolute.

        For each block, the displaced prefix is first copied out of the target
        (`read_memory`) and then overwritten with `E9 rel32` plus NOP padding
        up to the prefix length. `install_patch` re-reads those bytes under the
        suspended window and refuses to write when they are no longer the
        pre-image, so another owner's detour is never overwritten. The NOP
        padding matters: the stub resumes at `block + 5` (the record's shape),
        so the pad bytes are what carry execution across whatever remains of a
        multi-byte displaced instruction to `block + prefix_size`.

        Calling it twice returns the first report and writes nothing; call
        `uninstall()` between installs.

        Raises:
            PydbgError: only if a shared step fails in a way this method
                cannot describe per block; normally every failure is reported.
        """
        if self._report is not None:
            return self._report
        plans = self.plan()
        if not plans:
            self._report = InstallReport()
            return self._report

        refusals = {}
        base = self._module_base()
        if not base:
            for plan in plans:
                refusals[plan.rva] = (
                    f"no module base address for rva 0x{plan.rva:X}")
            return self._finish_report(plans, (), (), refusals)

        candidates = [plan for plan in plans if plan.relocatable]
        sink = None
        region = None
        warnings = []
        if candidates:
            if keystone is None:
                for plan in candidates:
                    refusals[plan.rva] = (
                        "keystone-engine is not installed: a BBL stub cannot "
                        "be assembled")
            else:
                from .event_buffer import EventBuffer

                try:
                    sink = EventBuffer(
                        self.dbg, capacity=_ring_capacity(self.max_events))
                except (PydbgError, OSError, ValueError) as exc:
                    for plan in plans:
                        refusals[plan.rva] = (
                            f"cannot allocate the event buffer: {exc}")
                    return self._finish_report(plans, (), (), refusals)

                stub_size = sum(STUB_PROLOGUE_SIZE + plan.prefix_size
                                + STUB_JUMP_SIZE
                                for plan in candidates)
                try:
                    region = alloc_near(self.dbg, base, stub_size)
                except (PydbgError, OSError) as exc:
                    self._release_setup(sink, None, warnings)
                    for plan in plans:
                        refusals[plan.rva] = (
                            f"cannot allocate stub memory near the module: "
                            f"{exc}")
                    return self._finish_report(plans, (), warnings, refusals)

        installed = []
        originals = {}
        cursor = region
        for plan in plans:
            if plan.rva in refusals:
                continue
            try:
                instructions = self._decode_rvas(
                    self._analysis, plan.instruction_rvas)
                address_base = decoder_address_base(
                    plan.instruction_rvas, instructions)
                prefix = take_prefix(
                    instructions, plan.rva, address_base=address_base)
                if not plan.relocatable:
                    # Let relocate_prefix name the branch and its RVA; its
                    # first check is the branch/return refusal. A plan that
                    # says "not relocatable" for another reason still refuses.
                    relocate_prefix(prefix, base, address_base=address_base)
                    raise UnsupportedInstruction(
                        plan.rva, '', 'the planned prefix cannot be relocated')
                if sink is None or cursor is None:
                    raise PydbgError(
                        'the event buffer or stub region was not allocated')
                stub_address = cursor
                relocated = relocate_prefix(
                    prefix, stub_address, address_base=address_base)
                stub = build_stub(
                    sink, plan.rva, len(plan.instruction_rvas), relocated,
                    base + plan.rva + DETOUR_SIZE)
                self.dbg.write_memory(stub_address, stub)
                # The plan is in RVAs, the install in VAs: the window, the
                # E9 and the record all speak absolute addresses.
                absolute = base + plan.rva
                original = bytes(self.dbg.read_memory(
                    absolute, len(relocated)))
                patch = build_abs_jmp(absolute, stub_address) + (
                    b"\x90" * (len(relocated) - DETOUR_SIZE))
                record = install_patch(
                    self.dbg, absolute, patch, original=original)
                warnings.extend(record.warnings)
                installed.append(plan.rva)
                originals[absolute] = record
                cursor += len(stub)
            except (PydbgError, OSError) as exc:
                refusals[plan.rva] = str(exc) or exc.__class__.__name__
                warnings.extend(getattr(exc, 'warnings', ()))

        if not installed and (sink is not None or region is not None):
            # Nothing points at the shared allocations, so releasing them now
            # is safer than leaving a failed install holding target memory.
            self._release_setup(sink, region, warnings)
            self._originals = {}
            return self._finish_report(plans, (), warnings, refusals)

        self._buffer = sink
        self._stub_region = region
        self._originals = originals
        return self._finish_report(plans, installed, warnings, refusals)

    def _release_setup(self, sink, region, warnings):
        """Release the ring then the stub region, keeping what could not go.

        A failed release is not forgotten: the live object (or address) is
        stored back on `self` so `uninstall()` retries it, and the warning
        names it. On success the attribute is cleared, which is also how
        `uninstall()` decides whether the lifecycle is over.
        """
        if sink is not None:
            freed = sink.free()
            warnings.extend(f"{what}: {why}" for what, why in freed)
            self._buffer = None if not freed else sink
        if region is not None:
            try:
                self.dbg.memory.free_remote(region)
            except (PydbgError, OSError) as exc:
                warnings.append(f"stub region at 0x{region:X}: {exc}")
                self._stub_region = region
            else:
                self._stub_region = None

    def _finish_report(self, plans, installed, warnings, refusals):
        """Build the report in plan order and remember it."""
        refused = tuple((plan.rva, refusals[plan.rva])
                        for plan in plans if plan.rva in refusals)
        self._report = InstallReport(
            installed=tuple(installed),
            refused=refused,
            warnings=tuple(warnings))
        return self._report

    def _module_base(self):
        """The module's runtime base, or None when it cannot be resolved."""
        if self._base:
            return self._base
        from ..trace import _shared

        module = _shared.find_module(self.dbg, self.module)
        if module is None:
            return None
        base, _ = _shared.module_region(module)
        self._base = base or None
        return self._base

    # ── events and teardown ────────────────────────────────────

    def events(self):
        """The BLOCK records written since the previous call, oldest first.

        Drains `EventBuffer.read()` and truncates it to `max_events`. The
        records are returned as the v1 `TraceEvent`s the stub wrote: `kind` is
        BLOCK, `rva` the block start, `a` its instruction count, and `tid`/`ts`
        are 0 because the target-side stub cannot know either (spec §12.1).
        Callers must not read 0 as a real thread id.

        The target has to be stopped for this to be trustworthy: a running
        target can advance the ring's head between the header read and the slot
        read. Nothing here stops it.

        A budget of 0 returns nothing and leaves the ring untouched; after
        `uninstall()` the buffer is gone and the answer is `()`.
        """
        if self._buffer is None or self.max_events <= 0:
            return ()
        return tuple(self._buffer.read()[:self.max_events])

    def uninstall(self):
        """Restore the displaced bytes and release the shared allocations.

        Blocks are restored in install order. A block whose restore is refused
        (a thread inside its window, an unreadable thread context) keeps its
        record, so a later call retries it. A block whose bytes changed under
        us is treated the same way: the bytes may still be our E9 (a changed
        NOP tail, say), so the stub it points at must not be freed and the
        record must not be forgotten -- an overwritten detour is the caller's
        to see, not ours to guess about. In both cases the stub region and the
        event ring are NOT released, and the last warning says the memory was
        kept.

        When every record is gone the ring is freed and then the stub region.
        A failed release is reported as a warning and retried by a later call,
        never silently forgotten: the instrumenter still holds the address.

        Returns:
            tuple[str, ...]: cleanup warnings, in a stable order -- block
            warnings first (in install order), then the ring, then the stub
            region, then the "kept" notice. Empty when everything was clean.
        """
        if (not self._originals and self._buffer is None
                and self._stub_region is None):
            return ()

        warnings = []
        for absolute in list(self._originals):
            try:
                block_warnings = uninstall_patch(
                    self.dbg, self._originals[absolute])
            except (PydbgError, OSError) as exc:
                warnings.append(f"0x{absolute:X}: {exc}")
                warnings.extend(getattr(exc, 'warnings', ()))
                continue
            warnings.extend(block_warnings)
            if any(warning.startswith(BYTES_CHANGED)
                   for warning in block_warnings):
                continue              # still (possibly) ours: keep the record
            del self._originals[absolute]

        if self._originals:
            warnings.append(
                'detours remain installed: stub region and event buffer kept')
            return tuple(warnings)

        self._release_setup(self._buffer, self._stub_region, warnings)
        if self._buffer is None and self._stub_region is None:
            # A later install() starts a fresh lifecycle.
            self._report = None
        return tuple(warnings)

    def teardown(self):
        """Undo every detour and release the shared allocations (ADR-0004).

        The same work as `uninstall()`, shaped as the managers' teardown
        contract: a list of `(what, why)` failures, never raising, so
        `Debugger.close()` can walk the rest of the chain and report everything
        together. A block that stays installed keeps the stub region and the
        ring, exactly as `uninstall()` reports it.
        """
        return [("bbl instrumentation", warning)
                for warning in self.uninstall()]

    def discard(self):
        """Forget every detour and allocation without touching the target.

        For the terminate path: the bytes are gone with the process, so there
        is nothing to restore, but the records must not outlive it and pretend
        the detours are still armed. The plans stay cached; a later install()
        on that dead target fails instead of writing.
        """
        self._originals.clear()
        self._buffer = None
        self._stub_region = None
        self._report = None
