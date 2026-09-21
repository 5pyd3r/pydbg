"""What a target's message loop is doing — the three causes of a silent run.

`run()` times out with "the target is idle, blocked, or wedged", which is the
code admitting it cannot tell three different situations apart. On a real
target that cost a whole analysis round: the program was sitting on a modal
dialog, every `WriteFile` probe returned zero, and the zeros were read as "this
component does not write files" — the opposite of what was happening. The only
thing that showed it was leaving pydbg and reading the window titles directly.

This is that, as a query. It does not turn a zero into evidence: it names
*which* of the causes applies, and where it cannot, it says so in a way a
caller has to write down.

    PUMPING      windows exist, none hung, no dialog up
    MODAL        a dialog is up that only a person can dismiss
    WEDGED       a window's thread is not pumping and there is no dialog
    NO_WINDOWS   the pid owns no top-level window at all
    GONE         the pid is not in the process snapshot
    UNKNOWN      the probe could not run — which is NOT "not blocked"

`UNKNOWN` exists for the same reason `breakpoint_report()`'s `armed=None`
does: "I could not look" must never render as "nothing is wrong".
"""

from dataclasses import dataclass, field
from enum import Enum
from time import monotonic

# The window class every Win32 dialog uses. A `MessageBox` is one of these,
# and so is every `DialogBox` a program creates from a template.
DIALOG_CLASS = "#32770"


class MessageLoopState(Enum):
    """Which of the six situations the target's message loop is in."""

    PUMPING = "pumping"
    MODAL = "modal"
    WEDGED = "wedged"
    NO_WINDOWS = "no_windows"
    GONE = "gone"
    UNKNOWN = "unknown"


# The states a caller may read as "the target is running normally". A caller
# that checks `state is PUMPING` gets the same answer; this set exists so that
# code asking the looser question has somewhere to look that is not a list of
# the states it happens to remember.
RUNNING = frozenset((MessageLoopState.PUMPING,))
# The states that mean "do not draw a conclusion from a zero result".
BLOCKED = frozenset((MessageLoopState.MODAL, MessageLoopState.WEDGED,
                     MessageLoopState.GONE))
# The states that mean the probe itself could not decide.
UNDECIDED = frozenset((MessageLoopState.NO_WINDOWS,
                       MessageLoopState.UNKNOWN))


@dataclass(frozen=True, slots=True)
class WindowInfo:
    """One window, as the Cython layer reports it."""

    hwnd: int
    pid: int
    class_name: str
    text: str
    visible: bool
    enabled: bool
    hung: bool
    owner: int
    children: tuple = ()


@dataclass(frozen=True, slots=True)
class WindowProbe:
    """One probe's answer, with the evidence that decided it."""

    pid: int
    state: MessageLoopState
    windows: tuple = ()
    evidence: str = ""
    caveat: str | None = None
    sampled_at: float = 0.0
    # False when `IsHungAppWindow` was not usable — the property is documented
    # but not guaranteed, and a probe that silently loses its WEDGED signal
    # would report PUMPING for a hung target forever.
    hung_signal_available: bool = True

    def is_running(self):
        return self.state in RUNNING

    def render(self):
        lines = [f"pid {self.pid}: {self.state.value}"]
        if self.evidence:
            lines.append(f"  evidence: {self.evidence}")
        for window in self.windows:
            lines.append(f"  0x{window.hwnd:X} [{window.class_name}] "
                         f"{window.text!r}"
                         + (" (hung)" if window.hung else "")
                         + ("" if window.visible else " (hidden)"))
        if self.caveat:
            lines.append(f"  caveat: {self.caveat}")
        return "\n".join(lines)


def classify(windows, pid, *, process_exists=True, hung_signal_available=True,
             sampled_at=0.0):
    """The state implied by a window list. Pure; no Win32 here.

    Split out from the query so the whole state table is testable without a
    process, which is the difference between a rule that is checked and one
    that is described.
    """
    windows = tuple(windows)
    if not process_exists:
        return WindowProbe(pid=pid, state=MessageLoopState.GONE,
                           evidence="the pid is not in the process snapshot",
                           sampled_at=sampled_at)
    if not windows:
        return WindowProbe(
            pid=pid, state=MessageLoopState.NO_WINDOWS,
            evidence="the pid owns no top-level window",
            caveat="a target with no windows may still be running; this "
                   "probe cannot see a console program's message loop",
            sampled_at=sampled_at)

    # A dialog is checked first and deliberately is NOT `IsHungAppWindow`. A
    # message box runs its own modal loop on the same thread, so that thread
    # *is* pumping and `IsHungAppWindow` is false — the exact case that was
    # misread as "the component does not write files". Checking hungness first
    # would classify the one case that has an explanation as the one that has
    # none.
    dialog = _modal_dialog(windows)
    if dialog is not None:
        return WindowProbe(
            pid=pid, state=MessageLoopState.MODAL, windows=windows,
            evidence=f"a dialog is up and only a person can dismiss it: "
                     f"[{dialog.class_name}] {dialog.text!r}",
            sampled_at=sampled_at)

    if not hung_signal_available:
        return WindowProbe(
            pid=pid, state=MessageLoopState.UNKNOWN, windows=windows,
            evidence="the hung-window signal is unavailable",
            caveat="cannot rule out that the target is blocked",
            hung_signal_available=False, sampled_at=sampled_at)

    hung = tuple(window for window in windows if window.hung)
    if hung:
        return WindowProbe(
            pid=pid, state=MessageLoopState.WEDGED, windows=windows,
            evidence=f"{len(hung)} window(s) belong to a thread that is not "
                     f"answering messages, and no dialog is up",
            sampled_at=sampled_at)

    return WindowProbe(
        pid=pid, state=MessageLoopState.PUMPING, windows=windows,
        evidence=f"{len(windows)} window(s), none hung, no dialog",
        sampled_at=sampled_at)


def _modal_dialog(windows):
    """The window that makes this a modal state, or None.

    Two signatures, both required to be visible and enabled: a dialog class,
    or an owned window. `GW_OWNER` is set on a message box and on most modal
    dialogs; the class check catches the ones that are not owned but still
    block.
    """
    same_pid = {window.hwnd for window in windows}
    for window in windows:
        if not (window.visible and window.enabled):
            continue
        if window.class_name == DIALOG_CLASS:
            return window
        if window.owner and window.owner in same_pid:
            return window
    return None


class WindowProbeQuery:
    """Asks the target's windows what its message loop is doing.

    `enumerate_windows` is injectable so the state table can be exercised
    without a process. The default is the Cython function, looked up lazily so
    that importing this module does not require the extension to be built.
    """

    def __init__(self, enumerate_windows=None):
        self._enumerate = enumerate_windows

    def _windows(self, pid):
        if self._enumerate is None:
            from .._pydbg import enumerate_windows as native
            self._enumerate = native
        return self._enumerate(pid)

    def probe(self, pid, process_exists=True):
        """The `WindowProbe` for 'pid'.

        Failure of the probe itself is reported as `UNKNOWN` with the reason
        attached, never as a benign state and never by raising: a caller that
        asked "is this target running" is better served by "I could not tell,
        and here is why" than by an exception it will catch and treat as "no".
        """
        sampled_at = monotonic()
        try:
            raw = self._windows(pid)
        except Exception as exc:                       # noqa: BLE001
            return WindowProbe(
                pid=pid, state=MessageLoopState.UNKNOWN,
                evidence=f"the window probe failed: {exc!r}",
                caveat="cannot rule out that the target is blocked",
                sampled_at=sampled_at)

        if not process_exists:
            return classify((), pid, process_exists=False,
                            sampled_at=sampled_at)

        windows = tuple(_to_window_info(item) for item in raw)
        # `hung_signal_available` is left at its default. What `classify`
        # models is the case where the signal is known to be missing; nothing
        # here can detect that from one reading, because `IsHungAppWindow`
        # returns FALSE both for "nothing is hung" and for "I cannot tell".
        # Claiming otherwise would be the same species of guess this module
        # exists to remove, so the limitation is recorded rather than
        # papered over — see `classify`'s UNKNOWN branch, which a caller that
        # knows better can reach directly.
        return classify(windows, pid, sampled_at=sampled_at)


def _to_window_info(item):
    return WindowInfo(
        hwnd=item.get("hwnd", 0),
        pid=item.get("pid", 0),
        class_name=item.get("class_name", ""),
        text=item.get("text", ""),
        visible=bool(item.get("visible")),
        enabled=bool(item.get("enabled")),
        hung=bool(item.get("hung")),
        owner=item.get("owner", 0) or 0,
        children=tuple(_to_window_info(child)
                       for child in item.get("children", ())),
    )


@dataclass
class MessageLoopWatch:
    """Repeated probes, so a state that changes is visible as a change.

    Not a scheduler: it is the shape a caller needs when it wants to say "the
    target was pumping, and then it was not" rather than only what it is now.
    """

    query: WindowProbeQuery = field(default_factory=WindowProbeQuery)
    history: list = field(default_factory=list)

    def sample(self, pid, process_exists=True):
        result = self.query.probe(pid, process_exists=process_exists)
        self.history.append(result)
        return result

    def transitions(self):
        """(from, to, evidence) for each state change, in order."""
        out = []
        for previous, current in zip(self.history, self.history[1:]):
            if previous.state is not current.state:
                out.append((previous.state, current.state, current.evidence))
        return tuple(out)
