"""The trace tracers a Debugger owns, undone as one teardown step.

A tracer is caller-owned: `BblTracer(dbg)` and its siblings keep the caller's
own handle on what they armed. But a tracer handed a `Debugger` is also
something that debugger's `close()` must disarm — otherwise an INT3 or a
debug-register slot outlives the session and blocks the next one in the same
process. The four tracers register themselves through `attach_trace()`, and
this registry is the single name `_TEARDOWN_ORDER` carries for all of them.

A registry rather than four more names in the tuple: a caller may create any
number of tracers, in any order, and each forgets its own state when undone
(ADR-0004). The registry turns their cleanup warnings — `disarm()`'s
`tuple[str, ...]` — into the `(what, why)` problems the rest of the chain
reports, naming the tracer that could not let go.
"""


class TraceRegistry:
    """Attached trace tracers, in attachment order."""

    def __init__(self):
        self._attached = []

    def __len__(self):
        return len(self._attached)

    def __iter__(self):
        return iter(tuple(self._attached))

    def __contains__(self, item):
        return any(attached is item for attached in self._attached)

    def attach(self, tracer):
        """Register `tracer` for teardown; return it for one-line construction.

        Identity, not equality, decides "already attached": two distinct
        tracers of the same class are two things to undo, the same object
        twice is one. Tracers that auto-register call this themselves, so
        attaching again is a no-op.
        """
        if tracer not in self:
            self._attached.append(tracer)
        return tracer

    def teardown(self):
        """Undo every tracer; return the chain's `[(what, why)]` problems.

        Never raises: a tracer whose cleanup explodes is one reported problem,
        and the remaining tracers are still undone. That is the contract every
        other manager implements, kept here so `Debugger.close()` walks the
        chain without a special case for traces.

        A tracer's `teardown()` returns `disarm()`'s cleanup warnings
        (`tuple[str, ...]`); each becomes a problem attributed to that tracer.
        A `(what, why)` pair is passed through unchanged, so a tracer that
        adopts the managers' exact shape needs no adaptation here.

        A tracer that let go is forgotten, so a second `close()` does not
        re-run it. One whose `teardown()` raised stays in the list: it was not
        undone, and a later close() has to be able to retry it.
        """
        problems = []
        remaining = []
        for index, tracer in enumerate(tuple(self._attached)):
            what = f"trace {index} ({type(tracer).__name__})"
            teardown = getattr(tracer, "teardown", None)
            if not callable(teardown):
                remaining.append(tracer)      # nothing undid this object
                problems.append((what, "no teardown()"))
                continue
            try:
                warnings = teardown() or ()
            except Exception as exc:      # a tracer must not abort the chain
                remaining.append(tracer)      # keep it for a later retry
                problems.append((what, str(exc)))
                continue
            for warning in warnings:
                if isinstance(warning, tuple) and len(warning) == 2:
                    problems.append(warning)
                else:
                    problems.append((what, str(warning)))
        self._attached = remaining
        return problems

    def discard(self):
        """Forget every tracer without touching the target (it is gone).

        The terminate path cannot restore bytes or debug registers, but the
        tracers' own records and cached handles must still be dropped. Never
        raises: the event drain that follows must not be held up by one broken
        tracer.
        """
        for tracer in tuple(self._attached):
            discard = getattr(tracer, "discard", None)
            if not callable(discard):
                continue
            try:
                discard()
            except Exception:
                pass
        # The target is gone, so nothing in the list is retryable.
        self._attached.clear()
