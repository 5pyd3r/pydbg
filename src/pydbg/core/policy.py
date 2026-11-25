"""ExceptionPolicy — what ContinueDebugEvent is told about an exception.

The library used to answer DBG_CONTINUE for every exception, whatever the
caller wanted: `Debugger.continue_event(pid, tid)` forwarded no status, so a
first-chance access violation was marked handled and the target's own SEH never
saw it — resuming simply re-executed the faulting instruction. This module makes
that answer configurable without changing the default: `ExceptionPolicy()` says
DBG_CONTINUE for every code, exactly like the old hard-coded call.

The policy decides only the continue status. It never changes whether the event
is delivered to the caller's callback: `ignore_codes` and `first_chance_only`
skip `on_exception`, not the caller (see `should_notify`).
"""

from ..constants import DBG_CONTINUE


class ExceptionPolicy:
    """The configurable answer to "how is this exception continued?".

    Args:
        ignore_codes: Exception codes whose `on_exception` is not consulted.
            They continue through `continue_flags` instead. The event is still
            delivered to the caller's callback — this only skips the policy
            callback.
        first_chance_only: When True, a second-chance exception is not handed
            to `on_exception`; it takes the original path (`continue_flags`).
            Delivery to the caller is unchanged.
        on_exception: `callable(event) -> int | None`. An int is used as the
            ContinueDebugEvent status for that event; None defers to
            `continue_flags`. Raising from it propagates to the caller.

    Breakpoint exceptions arrive as EXCEPTION events too, and the status this
    policy returns applies to them as well. Returning DBG_EXCEPTION_NOT_HANDLED
    for EXCEPTION_BREAKPOINT / STATUS_WX86_BREAKPOINT hands the INT3 to the
    target's own SEH (KNOWN_ISSUES: a target without a breakpoint handler then
    terminates), so ignore those codes unless that is the intent.
    """

    def __init__(self, ignore_codes=(), first_chance_only=False,
                 on_exception=None):
        if on_exception is not None and not callable(on_exception):
            raise TypeError(
                f"on_exception must be callable or None, got {on_exception!r}")
        self.ignore_codes = frozenset(ignore_codes)
        self.first_chance_only = bool(first_chance_only)
        self.on_exception = on_exception

    def should_notify(self, event):
        """Whether `on_exception` is consulted for this exception event.

        False for an ignored code, or for a second-chance exception while
        `first_chance_only` is set. It says nothing about whether the caller's
        callback sees the event.
        """
        if event.exception_code in self.ignore_codes:
            return False
        if (self.first_chance_only
                and event.first_chance is not None
                and not event.first_chance):
            return False
        return True

    def continue_flags(self, code):
        """The status for 'code' when `on_exception` has no answer.

        Always DBG_CONTINUE here, which is what every continue used to send.
        Override it to map codes without a callback.
        """
        return DBG_CONTINUE

    def continue_status(self, event):
        """The ContinueDebugEvent status for one exception event.

        `on_exception` is consulted first (when `should_notify` allows it); an
        int from it wins, None falls through to `continue_flags`. This is the
        single composition rule, so a subclass that overrides `continue_flags`
        keeps working for ignored codes, second chances and None returns alike.
        """
        if not self.should_notify(event):
            return self.continue_flags(event.exception_code)
        if self.on_exception is not None:
            status = self.on_exception(event)
            if status is not None:
                return status
        return self.continue_flags(event.exception_code)
