"""Exception continue policy: configurable status, default behaviour unchanged.

Spec: docs/analysis-coverage.md §13.1.

Every exception used to be continued with DBG_CONTINUE regardless of what the
caller wanted: ``Debugger.continue_event(pid, tid)`` forwarded no status, so a
first-chance access violation was marked handled and the target's own SEH never
ran. These tests pin the default (byte-identical) and the configured behaviour,
and the live ones read the difference off av_target's own SEH handler.
"""

import os
import unittest
from types import SimpleNamespace

from pydbg.constants import (
    DBG_CONTINUE,
    DBG_EXCEPTION_NOT_HANDLED,
    EXCEPTION_ACCESS_VIOLATION,
    EXCEPTION_BREAKPOINT,
)
from pydbg.core.policy import ExceptionPolicy
from tests import TEST_AV_TARGET_PATH

try:
    from pydbg import _pydbg

    _has_cython = True
except ImportError:
    _has_cython = False


def _event(code=EXCEPTION_ACCESS_VIOLATION, first_chance=1):
    """The two fields the policy reads from a DebugEvent."""
    return SimpleNamespace(exception_code=code, first_chance=first_chance)


def _raw_exception(pid=1, tid=2, code=EXCEPTION_ACCESS_VIOLATION,
                   first_chance=1):
    return {
        "event_name": "EXCEPTION",
        "pid": pid,
        "tid": tid,
        "exception_code": code,
        "exception_addr": 0x401000,
        "first_chance": first_chance,
        "exception_params": [],
    }


class _RecordingPolicy(ExceptionPolicy):
    """A policy whose fallback status is visible in its return value."""

    def __init__(self, fallback):
        super().__init__()
        self.fallback = fallback
        self.codes = []

    def continue_flags(self, code):
        self.codes.append(code)
        return self.fallback


class TestDefaults(unittest.TestCase):
    """The default policy is exactly what the library did before."""

    def test_continue_flags_is_dbg_continue_for_every_code(self):
        policy = ExceptionPolicy()
        self.assertEqual(
            policy.continue_flags(EXCEPTION_ACCESS_VIOLATION), DBG_CONTINUE)
        self.assertEqual(
            policy.continue_flags(EXCEPTION_BREAKPOINT), DBG_CONTINUE)

    def test_every_exception_is_notified(self):
        policy = ExceptionPolicy()
        self.assertTrue(policy.should_notify(_event()))
        self.assertTrue(policy.should_notify(_event(first_chance=0)))

    def test_default_status_is_dbg_continue(self):
        self.assertEqual(
            ExceptionPolicy().continue_status(_event()), DBG_CONTINUE)

    def test_configuration_is_exposed(self):
        callback = lambda event: None       # noqa: E731 - just an identity
        policy = ExceptionPolicy(
            ignore_codes=[EXCEPTION_BREAKPOINT], first_chance_only=True,
            on_exception=callback)
        self.assertEqual(policy.ignore_codes, frozenset({EXCEPTION_BREAKPOINT}))
        self.assertTrue(policy.first_chance_only)
        self.assertIs(policy.on_exception, callback)

    def test_a_non_callable_on_exception_is_refused(self):
        with self.assertRaises(TypeError):
            ExceptionPolicy(on_exception=42)

    def test_the_policy_and_statuses_are_exported_from_the_package(self):
        import pydbg

        self.assertIs(pydbg.ExceptionPolicy, ExceptionPolicy)
        self.assertEqual(pydbg.DBG_CONTINUE, DBG_CONTINUE)
        self.assertEqual(
            pydbg.DBG_EXCEPTION_NOT_HANDLED, DBG_EXCEPTION_NOT_HANDLED)


class TestIgnoreCodes(unittest.TestCase):
    """ignore_codes skips the policy callback, never the event."""

    def test_an_ignored_code_is_not_notified(self):
        policy = ExceptionPolicy(ignore_codes=[EXCEPTION_ACCESS_VIOLATION])
        self.assertFalse(policy.should_notify(_event()))
        self.assertTrue(policy.should_notify(_event(code=EXCEPTION_BREAKPOINT)))

    def test_an_ignored_code_skips_on_exception_and_keeps_continue_flags(self):
        calls = []

        def on_exception(event):
            calls.append(event)
            return DBG_EXCEPTION_NOT_HANDLED

        policy = ExceptionPolicy(
            ignore_codes=[EXCEPTION_ACCESS_VIOLATION],
            on_exception=on_exception)
        self.assertEqual(policy.continue_status(_event()), DBG_CONTINUE)
        self.assertEqual(calls, [], "an ignored code reached on_exception")

    def test_a_code_not_listed_still_reaches_on_exception(self):
        calls = []
        policy = ExceptionPolicy(
            ignore_codes=[EXCEPTION_BREAKPOINT],
            on_exception=lambda event: calls.append(event) or
            DBG_EXCEPTION_NOT_HANDLED)
        self.assertEqual(
            policy.continue_status(_event()), DBG_EXCEPTION_NOT_HANDLED)
        self.assertEqual(len(calls), 1)


class TestFirstChanceOnly(unittest.TestCase):
    """first_chance_only leaves second-chance exceptions on the old path."""

    def test_a_second_chance_exception_is_not_notified(self):
        policy = ExceptionPolicy(first_chance_only=True)
        self.assertFalse(policy.should_notify(_event(first_chance=0)))
        self.assertFalse(policy.should_notify(_event(first_chance=False)))

    def test_a_first_chance_exception_is_still_notified(self):
        policy = ExceptionPolicy(first_chance_only=True)
        self.assertTrue(policy.should_notify(_event(first_chance=1)))
        self.assertTrue(policy.should_notify(_event(first_chance=True)))

    def test_a_second_chance_exception_keeps_continue_flags(self):
        calls = []
        policy = ExceptionPolicy(
            first_chance_only=True,
            on_exception=lambda event: calls.append(event) or
            DBG_EXCEPTION_NOT_HANDLED)
        self.assertEqual(
            policy.continue_status(_event(first_chance=0)), DBG_CONTINUE)
        self.assertEqual(calls, [], "a second-chance exception reached the callback")


class TestOnException(unittest.TestCase):
    """on_exception's int wins; None falls through to continue_flags."""

    def test_an_int_return_becomes_the_continue_status(self):
        policy = ExceptionPolicy(
            on_exception=lambda event: DBG_EXCEPTION_NOT_HANDLED)
        self.assertEqual(
            policy.continue_status(_event()), DBG_EXCEPTION_NOT_HANDLED)

    def test_the_event_is_handed_to_the_callback(self):
        event = _event()
        seen = []
        policy = ExceptionPolicy(on_exception=lambda e: seen.append(e) or None)
        policy.continue_status(event)
        self.assertEqual(seen, [event])

    def test_a_none_return_falls_back_to_continue_flags(self):
        policy = _RecordingPolicy(0x1234)
        policy.on_exception = lambda event: None
        self.assertEqual(policy.continue_status(_event()), 0x1234)
        self.assertEqual(policy.codes, [EXCEPTION_ACCESS_VIOLATION],
                         "the fallback did not go through continue_flags")

    def test_no_callback_goes_straight_to_continue_flags(self):
        policy = _RecordingPolicy(0x5678)
        self.assertEqual(policy.continue_status(_event()), 0x5678)
        self.assertEqual(policy.codes, [EXCEPTION_ACCESS_VIOLATION])


@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
class TestDebuggerContinueStatus(unittest.TestCase):
    """Debugger.continue_event is the seam the status travels through."""

    def _deliver(self, dbg, raw):
        from unittest import mock

        with mock.patch.object(_pydbg, "wait_for_debug_event",
                               return_value=raw):
            return dbg.wait_event(1)

    def test_default_policy_continues_an_exception_with_dbg_continue(self):
        from unittest import mock

        from pydbg import Debugger

        dbg = Debugger()
        self._deliver(dbg, _raw_exception())
        with mock.patch.object(_pydbg, "continue_debug_event") as cont:
            dbg.continue_event(1, 2)
        cont.assert_called_once_with(1, 2, DBG_CONTINUE)

    def test_a_non_exception_event_is_continued_exactly_as_before(self):
        from unittest import mock

        from pydbg import Debugger

        dbg = Debugger()
        self._deliver(dbg, {"event_name": "LOAD_DLL", "pid": 1, "tid": 2})
        with mock.patch.object(_pydbg, "continue_debug_event") as cont:
            dbg.continue_event(1, 2)
        cont.assert_called_once_with(1, 2)

    def test_policy_status_is_used_when_status_is_omitted(self):
        from unittest import mock

        from pydbg import Debugger

        dbg = Debugger(ExceptionPolicy(
            on_exception=lambda event: DBG_EXCEPTION_NOT_HANDLED))
        self._deliver(dbg, _raw_exception())
        with mock.patch.object(_pydbg, "continue_debug_event") as cont:
            dbg.continue_event(1, 2)
        cont.assert_called_once_with(1, 2, DBG_EXCEPTION_NOT_HANDLED)

    def test_explicit_status_overrides_the_policy(self):
        from unittest import mock

        from pydbg import Debugger

        calls = []
        dbg = Debugger(ExceptionPolicy(
            on_exception=lambda event: calls.append(event) or
            DBG_EXCEPTION_NOT_HANDLED))
        self._deliver(dbg, _raw_exception())
        with mock.patch.object(_pydbg, "continue_debug_event") as cont:
            dbg.continue_event(1, 2, status=DBG_CONTINUE)
        cont.assert_called_once_with(1, 2, DBG_CONTINUE)
        self.assertEqual(calls, [], "the policy was consulted despite status=")

    def test_an_explicit_status_needs_no_pending_event(self):
        from unittest import mock

        from pydbg import Debugger

        dbg = Debugger()
        with mock.patch.object(_pydbg, "continue_debug_event") as cont:
            dbg.continue_event(1, 2, status=DBG_EXCEPTION_NOT_HANDLED)
        cont.assert_called_once_with(1, 2, DBG_EXCEPTION_NOT_HANDLED)


def _av_target_ready():
    return os.path.exists(TEST_AV_TARGET_PATH)


@unittest.skipUnless(_has_cython, "optional dependency: Cython extension")
@unittest.skipUnless(
    _av_target_ready(),
    f"target not built: {TEST_AV_TARGET_PATH}; build it with meson")
class TestAccessViolationLive(unittest.TestCase):
    """The status reaches Windows, and Windows hands the AV to the target SEH.

    av_target faults on a NULL read inside its own __try/__except and exits
    with 42 when the handler runs. That makes the two continue statuses
    distinguishable end to end instead of only at the Python seam.
    """

    def _drain_to_first_av(self, dbg, limit=300):
        for _ in range(limit):
            event = dbg.wait_event(3000)
            self.assertIsNotNone(event, "no event arrived before the fault")
            if (event.type == "EXCEPTION"
                    and event.exception_code == EXCEPTION_ACCESS_VIOLATION):
                return event
            dbg.continue_event(event.pid, event.tid)
        self.fail("the target never faulted")

    def _drain_to_exit(self, dbg, limit=300):
        exit_code = None
        for _ in range(limit):
            event = dbg.wait_event(3000)
            if event is None:
                break
            if event.type == "EXIT_PROCESS":
                exit_code = event.raw.get("exit_code")
                dbg.continue_event(event.pid, event.tid)
                break
            dbg.continue_event(event.pid, event.tid)
        return exit_code

    def test_exception_not_handled_reaches_the_targets_own_seh(self):
        from pydbg import Debugger
        from tests.helpers import teardown

        dbg = Debugger()
        dbg.create_process(TEST_AV_TARGET_PATH)
        try:
            first = self._drain_to_first_av(dbg)
            self.assertTrue(first.first_chance)
            dbg.continue_event(first.pid, first.tid,
                               status=DBG_EXCEPTION_NOT_HANDLED)
            self.assertEqual(
                self._drain_to_exit(dbg), 42,
                "the target's own SEH did not handle the access violation")
        finally:
            teardown(dbg)

    def test_default_continue_never_reaches_the_targets_seh(self):
        from pydbg import Debugger
        from tests.helpers import teardown

        dbg = Debugger()
        dbg.create_process(TEST_AV_TARGET_PATH)
        try:
            first = self._drain_to_first_av(dbg)
            dbg.continue_event(first.pid, first.tid)
            second = None
            for _ in range(50):
                event = dbg.wait_event(3000)
                if event is None:
                    break
                if (event.type == "EXCEPTION"
                        and event.exception_code == EXCEPTION_ACCESS_VIOLATION):
                    second = event
                    break
                dbg.continue_event(event.pid, event.tid)
            self.assertIsNotNone(
                second, "DBG_CONTINUE was expected to re-execute the fault")
            self.assertEqual(second.exception_addr, first.exception_addr)
            self.assertTrue(
                second.first_chance,
                "the target's SEH received an exception the debugger claimed "
                "to have handled")
        finally:
            teardown(dbg)

    def test_a_first_chance_policy_through_run_lets_the_target_recover(self):
        from pydbg import Debugger, ExitReason
        from tests.helpers import teardown

        policy = ExceptionPolicy(
            first_chance_only=True,
            on_exception=lambda event: (
                DBG_EXCEPTION_NOT_HANDLED
                if event.exception_code == EXCEPTION_ACCESS_VIOLATION
                else None))
        dbg = Debugger(policy)
        dbg.create_process(TEST_AV_TARGET_PATH)
        try:
            seen = []

            def callback(event):
                seen.append(event)
                return None

            status = dbg.run(callback, timeout_ms=3000, max_idle_timeouts=5)
            self.assertEqual(status.reason, ExitReason.TARGET_EXITED)
            self.assertEqual(status.exit_code, 42,
                             "run() did not forward the policy status")
            faults = [event for event in seen
                      if event.type == "EXCEPTION"
                      and event.exception_code == EXCEPTION_ACCESS_VIOLATION]
            self.assertEqual(
                len(faults), 1,
                "the target faulted more than once; its handler never ran")
        finally:
            teardown(dbg)

    def test_an_ignored_code_is_still_delivered_to_the_callback(self):
        """ignore_codes skips on_exception; it must not hide the event."""
        from pydbg import Debugger, ExitReason
        from tests.helpers import teardown

        calls = []
        policy = ExceptionPolicy(
            ignore_codes=[EXCEPTION_ACCESS_VIOLATION],
            on_exception=lambda event: calls.append(event) or
            DBG_EXCEPTION_NOT_HANDLED)
        dbg = Debugger(policy)
        dbg.create_process(TEST_AV_TARGET_PATH)
        try:
            seen = []

            def callback(event):
                seen.append(event)
                if (event.type == "EXCEPTION"
                        and event.exception_code == EXCEPTION_ACCESS_VIOLATION):
                    return False        # still the caller's event to stop at
                return None

            status = dbg.run(callback, timeout_ms=3000, max_idle_timeouts=5)
            self.assertEqual(status.reason, ExitReason.STOPPED_BY_CALLBACK)
            self.assertTrue(
                any(event.type == "EXCEPTION"
                    and event.exception_code == EXCEPTION_ACCESS_VIOLATION
                    for event in seen),
                "the ignored exception was not delivered to the caller")
            self.assertEqual(
                [event for event in calls
                 if event.exception_code == EXCEPTION_ACCESS_VIOLATION],
                [], "an ignored code reached on_exception")
        finally:
            teardown(dbg)


if __name__ == "__main__":
    unittest.main()
