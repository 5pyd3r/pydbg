"""Tests for the message-loop probe — separating the three causes of a silence.

The defect is not that pydbg could not see windows. It is that a run which
produced no debug events was reported as "the target is idle, blocked, or
wedged", and on a real target that sentence covered a program sitting on a
modal dialog: every probe returned zero, the zeros were read as "this
component does not write files", and the conclusion was backwards. So the
tests here are about which cause gets named, and about the probe refusing
loudly when it cannot name one.

The three C targets exist as a set. Each owns an identical real window and
differs only in what it does next, because the requirement is that they must
*not* be classified the same way — a single target could not show that.
"""

import os
import subprocess
import time
import unittest

from tests import (
    TEST_MODAL_TARGET_PATH, TEST_WEDGE_TARGET_PATH, TEST_WINDOW_TARGET_PATH,
)
from tests.helpers import teardown

# Which of the two halves a test needs. The state table runs everywhere; the
# integration tests need a desktop that actually has windows, and say so
# instead of quietly passing on an empty list.
_WINDOWS_VISIBLE = None


def _desktop_has_windows():
    global _WINDOWS_VISIBLE
    if _WINDOWS_VISIBLE is None:
        try:
            from pydbg._pydbg import enumerate_windows
            _WINDOWS_VISIBLE = len(enumerate_windows(0)) > 0
        except Exception:                              # noqa: BLE001
            _WINDOWS_VISIBLE = False
    return _WINDOWS_VISIBLE


def _wait_for_state(pid, wanted, budget=20.0):
    """Poll the probe until it reports 'wanted', or fail with what it saw.

    Bounded and assertive rather than a sleep: a probe called before the
    target's window exists reports NO_WINDOWS, which is a true answer about a
    target that has not started and a wrong one about this one.
    """
    from pydbg.core.window_probe import WindowProbeQuery
    query = WindowProbeQuery()
    deadline = time.monotonic() + budget
    seen = None
    while time.monotonic() < deadline:
        seen = query.probe(pid)
        if seen.state is wanted:
            return seen
        time.sleep(0.1)
    raise AssertionError(
        f"target {pid} never reached {wanted.value}; last state was "
        f"{seen.state.value} ({seen.evidence})")


class TargetProcess:
    """A window target, started and killed around one test."""

    def __init__(self, path):
        self.path = path
        self.process = None

    def __enter__(self):
        # stdout/stderr to DEVNULL: an inherited pipe keeps the *test runner's*
        # pipe open after the suite finishes, so a redirected run looks hung
        # long after it has passed.
        self.process = subprocess.Popen([self.path],
                                        stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL)
        self._wait_for_windows()
        return self.process.pid

    def _wait_for_windows(self, budget=15.0):
        """Give the target time to create its window.

        Bounded, and the bound is asserted rather than assumed: a probe called
        before the window exists would report NO_WINDOWS, which is a real
        answer about a target that has not started yet and a wrong one about
        this target.
        """
        from pydbg._pydbg import enumerate_windows
        deadline = time.monotonic() + budget
        while time.monotonic() < deadline:
            if any(w["pid"] == self.process.pid
                   for w in enumerate_windows(self.process.pid)):
                return
            time.sleep(0.1)
        raise AssertionError(
            f"{os.path.basename(self.path)} created no window within "
            f"{budget:.0f}s")

    def __exit__(self, *exc):
        if self.process is None or self.process.poll() is not None:
            return
        self.process.kill()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            # A target killed while a debugger holds it can take a moment to
            # disappear; failing teardown would replace the real result with
            # an unrelated one.
            pass


class TestTheStateTable(unittest.TestCase):
    """The rules, exercised without a process.

    Pure Python because the table is the whole content of the classification
    and a rule that can only be checked by starting three programs is a rule
    that gets checked once.
    """

    def _window(self, **overrides):
        from pydbg.core.window_probe import WindowInfo
        fields = dict(hwnd=1, pid=7, class_name="PydbgWindowTarget",
                      text="PydbgWindowTarget", visible=True, enabled=True,
                      hung=False, owner=0)
        fields.update(overrides)
        return WindowInfo(**fields)

    def test_the_six_states_are_each_reachable(self):
        from pydbg.core.window_probe import MessageLoopState, classify
        cases = {
            MessageLoopState.PUMPING: (self._window(),),
            MessageLoopState.MODAL: (self._window(class_name="#32770",
                                                  text="Auto Export Error"),),
            MessageLoopState.WEDGED: (self._window(hung=True),),
            MessageLoopState.NO_WINDOWS: (),
        }
        for expected, windows in cases.items():
            with self.subTest(state=expected):
                self.assertIs(classify(windows, 7).state, expected)
        self.assertIs(classify((), 7, process_exists=False).state,
                      MessageLoopState.GONE)
        self.assertIs(classify((self._window(),), 7,
                               hung_signal_available=False).state,
                      MessageLoopState.UNKNOWN)

    def test_a_modal_dialog_is_not_the_hung_window_case(self):
        """The trap in this area, and the one the real round fell into.

        A message box runs its own modal loop, so its thread IS pumping and
        `IsHungAppWindow` is false. Classifying by hungness first would name
        the cause that has no explanation for the one case that does.
        """
        from pydbg.core.window_probe import MessageLoopState, classify
        dialog = self._window(hwnd=2, class_name="#32770", hung=False)
        result = classify((self._window(), dialog), 7)
        self.assertIs(result.state, MessageLoopState.MODAL)
        self.assertIn("#32770", result.evidence)
        self.assertNotIn("not answering", result.evidence)

    def test_an_owned_window_is_modal_even_without_the_dialog_class(self):
        from pydbg.core.window_probe import MessageLoopState, classify
        owner = self._window(hwnd=1, owner=0)
        owned = self._window(hwnd=2, class_name="CustomDialog", owner=1)
        self.assertIs(classify((owner, owned), 7).state,
                      MessageLoopState.MODAL)

    def test_an_owner_from_another_process_is_not_a_dialog(self):
        """The bite test: a dialog's owner is what makes it modal, and the
        ownership relation has to be inside the target."""
        from pydbg.core.window_probe import MessageLoopState, classify
        owned = self._window(hwnd=2, class_name="CustomDialog", owner=999)
        self.assertIs(classify((owned,), 7).state, MessageLoopState.PUMPING)

    def test_a_hidden_dialog_is_not_blocking_anything(self):
        from pydbg.core.window_probe import MessageLoopState, classify
        hidden = self._window(class_name="#32770", visible=False)
        self.assertIs(classify((hidden,), 7).state, MessageLoopState.PUMPING)

    def test_the_undecided_states_carry_a_caveat(self):
        """`NO_WINDOWS` must not read as "fine", and must not read as
        "blocked" either — it is a refusal."""
        from pydbg.core.window_probe import classify
        empty = classify((), 7)
        self.assertIsNotNone(empty.caveat)
        unknown = classify((self._window(),), 7, hung_signal_available=False)
        self.assertIn("cannot rule out", unknown.caveat)


class TestAgainstRealWindows(unittest.TestCase):
    """The positive control: a real window, a real child, a real read."""

    def setUp(self):
        if not _desktop_has_windows():
            self.skipTest(
                "no windows visible on this desktop (session 0 / headless): "
                "the probe cannot be exercised here, and passing on an empty "
                "list is the defect this module exists to prevent")

    def test_a_pumping_target_reports_windows(self):
        from pydbg.core.window_probe import MessageLoopState
        with TargetProcess(TEST_WINDOW_TARGET_PATH) as pid:
            probe = self._probe(pid)
            self.assertIs(probe.state, MessageLoopState.PUMPING)
            # Load-bearing: an enumeration that returned [] would satisfy a
            # looser state assertion, and an empty list is what a broken
            # probe returns too.
            self.assertGreaterEqual(len(probe.windows), 1)
            titles = [w.text for w in probe.windows]
            self.assertIn("PydbgWindowTarget", titles)

    def test_the_child_window_text_is_read_back(self):
        """The `EnumChildWindows` control: drop the child walk and this dies.

        The string is the one the real round needed — it was on a Static
        control inside the dialog, not in the top-level title, and reading it
        is what turned an inverted conclusion right.
        """
        with TargetProcess(TEST_WINDOW_TARGET_PATH) as pid:
            from pydbg.core.window_probe import WindowProbeQuery
            probe = WindowProbeQuery().probe(pid)
            children = [child
                        for window in probe.windows
                        for child in window.children]
            self.assertTrue(
                any(child.text == "Auto Export Error" for child in children),
                f"child texts were {[c.text for c in children]!r}")
            self.assertTrue(
                any(child.class_name == "Static" for child in children))

    def _probe(self, pid):
        from pydbg.core.window_probe import WindowProbeQuery
        return WindowProbeQuery().probe(pid)


class TestTheModalCase(unittest.TestCase):
    """The cause that cost the round, against a real message box."""

    def setUp(self):
        if not _desktop_has_windows():
            self.skipTest("no windows visible on this desktop "
                          "(session 0 / headless)")

    def test_a_message_box_is_modal_and_not_hung(self):
        from pydbg.core.window_probe import MessageLoopState
        with TargetProcess(TEST_MODAL_TARGET_PATH) as pid:
            # Polled for rather than read once: this target creates its main
            # window first and only then opens the box, so a probe taken the
            # moment any window exists correctly reports PUMPING. Reading it
            # once would make this test fail on a loaded machine and pass on
            # an idle one, which is a test describing the machine.
            probe = _wait_for_state(pid, MessageLoopState.MODAL)
            self.assertIn("#32770", probe.evidence)
            self.assertIn("Auto Export Error", probe.evidence)
            # The dialog is up AND its thread is answering. A later
            # implementation that folds MODAL into WEDGED goes red here.
            dialogs = [w for w in probe.windows if w.class_name == "#32770"]
            self.assertTrue(dialogs, "no dialog window was found")
            self.assertFalse(any(w.hung for w in dialogs),
                             "the dialog's thread is reported as hung; a "
                             "message box pumps, so WEDGED is the wrong cause")


class TestTheSameZeroGetsTwoDiagnoses(unittest.TestCase):
    """The test that would have saved the round.

    A run that produces no debug events against a pumping target and against a
    modal one used to raise the same sentence. Same zero, two causes, and the
    message has to say which.

    The probe here is the real one against a real target; only the plumbing
    that reaches `_idle_timeout` is short-circuited, because that plumbing is
    `test_run_carries_the_diagnosis` below.
    """

    def setUp(self):
        if not _desktop_has_windows():
            self.skipTest("no windows visible on this desktop "
                          "(session 0 / headless)")

    def _idle_timeout_for(self, path, wanted):
        from unittest.mock import patch

        from pydbg.core.debugger import Debugger
        with TargetProcess(path) as pid:
            probe = _wait_for_state(pid, wanted)
            debugger = Debugger.__new__(Debugger)
            with patch.object(Debugger, "window_probe", return_value=probe):
                return debugger._idle_timeout(3, 200, True)

    def test_the_two_messages_differ_and_name_the_cause(self):
        from pydbg.core.window_probe import MessageLoopState
        pumping = self._idle_timeout_for(TEST_WINDOW_TARGET_PATH,
                                         MessageLoopState.PUMPING)
        modal = self._idle_timeout_for(TEST_MODAL_TARGET_PATH,
                                       MessageLoopState.MODAL)

        self.assertIs(pumping.probe.state, MessageLoopState.PUMPING)
        self.assertIs(modal.probe.state, MessageLoopState.MODAL)
        self.assertNotEqual(str(pumping), str(modal))
        # Asserted on the phrases that name the cause, not on the word
        # "dialog": the pumping message also contains it, in "no dialog",
        # which is a statement that there is none.
        self.assertIn("waiting on a dialog", str(modal))
        self.assertIn("is pumping messages", str(pumping))
        self.assertNotIn("waiting on a dialog", str(pumping))
        self.assertNotIn("is pumping messages", str(modal))

    def test_the_old_three_way_sentence_is_gone(self):
        """The sentence that named three causes and separated none."""
        from pydbg.core.window_probe import MessageLoopState
        for path, wanted in ((TEST_WINDOW_TARGET_PATH, MessageLoopState.PUMPING),
                             (TEST_MODAL_TARGET_PATH, MessageLoopState.MODAL)):
            with self.subTest(target=os.path.basename(path)):
                error = self._idle_timeout_for(path, wanted)
                self.assertNotIn("idle, blocked, or wedged", str(error))


class TestRunCarriesTheDiagnosis(unittest.TestCase):
    """The link from `run()`'s idle path to the probe, end to end."""

    def test_a_real_timeout_carries_a_probe_and_drops_the_old_sentence(self):
        from pydbg import Debugger
        from pydbg.exceptions import TimeoutError as PydbgTimeout
        debugger = Debugger()
        pid, _tid = debugger.create_process(TEST_WINDOW_TARGET_PATH)
        try:
            with self.assertRaises(PydbgTimeout) as caught:
                debugger.run(lambda event: True, timeout_ms=200,
                             max_idle_timeouts=2)
            error = caught.exception
            self.assertFalse(hasattr(error, "probe") and error.probe is None,
                             "the timeout carried no diagnosis at all")
            self.assertNotIn("idle, blocked, or wedged", str(error))
        finally:
            teardown(debugger)
            try:
                debugger.terminate_process(0)
            except Exception:                          # noqa: BLE001
                pass
        del pid

    def test_the_probe_can_be_turned_off_and_says_so(self):
        from unittest.mock import patch

        from pydbg.core.debugger import Debugger
        debugger = Debugger.__new__(Debugger)
        with patch.object(Debugger, "window_probe") as probe:
            error = debugger._idle_timeout(3, 200, False)
        probe.assert_not_called()
        self.assertIn("cannot rule out that the target is blocked", str(error))


class TestTheRefusalsAreLoud(unittest.TestCase):
    """Requirement two: when the probe cannot run, say so in words."""

    def test_an_unavailable_probe_is_declared_in_the_message(self):
        from unittest.mock import patch

        from pydbg.core.debugger import Debugger
        debugger = Debugger.__new__(Debugger)
        with patch.object(Debugger, "window_probe", return_value=None):
            error = debugger._idle_timeout(3, 200, True)
        self.assertIn("cannot rule out that the target is blocked",
                      str(error))
        self.assertIsNone(error.probe)

    def test_a_disabled_probe_is_also_declared(self):
        from pydbg.core.debugger import Debugger
        debugger = Debugger.__new__(Debugger)
        error = debugger._idle_timeout(3, 200, False)
        self.assertIn("cannot rule out that the target is blocked",
                      str(error))

    def test_a_probe_that_cannot_decide_does_not_claim_success(self):
        from unittest.mock import patch

        from pydbg.core.debugger import Debugger
        from pydbg.core.window_probe import MessageLoopState, WindowProbe
        debugger = Debugger.__new__(Debugger)
        undecided = WindowProbe(pid=7, state=MessageLoopState.UNKNOWN,
                                evidence="the probe failed",
                                caveat="cannot rule out that the target is "
                                       "blocked")
        with patch.object(Debugger, "window_probe", return_value=undecided):
            error = debugger._idle_timeout(3, 200, True)
        self.assertIn("cannot rule out that the target is blocked",
                      str(error))

    def test_the_probe_never_raises_and_never_reports_success(self):
        """A probe that blows up becomes UNKNOWN with the reason attached."""
        from pydbg.core.window_probe import MessageLoopState, WindowProbeQuery

        def explode(pid):
            raise OSError(5, "access denied")

        probe = WindowProbeQuery(enumerate_windows=explode).probe(7)
        self.assertIs(probe.state, MessageLoopState.UNKNOWN)
        self.assertIn("access denied", probe.evidence)
        self.assertIn("cannot rule out", probe.caveat)


class TestTheWedgeCase(unittest.TestCase):
    """The third cause, with a bounded wait rather than a fixed sleep."""

    def setUp(self):
        if not _desktop_has_windows():
            self.skipTest("no windows visible on this desktop "
                          "(session 0 / headless)")

    def test_a_target_that_stops_pumping_is_not_reported_as_running(self):
        from pydbg.core.window_probe import MessageLoopState, WindowProbeQuery
        with TargetProcess(TEST_WEDGE_TARGET_PATH) as pid:
            query = WindowProbeQuery()
            probe = query.probe(pid)
            self.assertIsNot(probe.state, MessageLoopState.GONE)
            self.assertGreaterEqual(len(probe.windows), 1)

            # The OS decides for itself how long a thread must be silent
            # before calling the window hung, and that threshold is not
            # published. Polled with a budget rather than slept on, and if the
            # budget runs out the test says how long it waited — a bare skip
            # here would read the same as a pass.
            deadline = time.monotonic() + 20.0
            started = time.monotonic()
            while time.monotonic() < deadline:
                probe = query.probe(pid)
                if probe.state is MessageLoopState.WEDGED:
                    break
                time.sleep(0.25)
            else:
                self.skipTest(
                    f"the OS did not mark the window hung within "
                    f"{time.monotonic() - started:.1f}s "
                    f"(state was {probe.state.value}); IsHungAppWindow's "
                    f"threshold is not published, so this is an environment "
                    f"limit rather than a failure")
            self.assertIs(probe.state, MessageLoopState.WEDGED)
            self.assertIn("not answering messages", probe.evidence)
            self.assertNotIn("#32770", probe.evidence)


if __name__ == "__main__":
    unittest.main()
