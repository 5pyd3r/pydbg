"""Shared pytest fixtures for pydbg tests, plus the rule that a skip is never silent."""

import os
import struct
import pytest

# Architecture constants
HOST_ARCH = struct.calcsize("P") * 8
IP_REG = "rip" if HOST_ARCH == 64 else "eip"
SP_REG = "rsp" if HOST_ARCH == 64 else "esp"
GP_REG = "rax" if HOST_ARCH == 64 else "eax"

# Test target path
TEST_TARGET_PATH = os.environ.get("TEST_TARGET_PATH", "simple_target.exe")


@pytest.fixture
def target_path():
    """Path to the test target executable."""
    return TEST_TARGET_PATH


@pytest.fixture
def debugger():
    """Create a Debugger instance (no process)."""
    from pydbg import Debugger
    return Debugger()


@pytest.fixture
def running_debugger(target_path):
    """Create a Debugger with a running process, past initial breakpoint."""
    from pydbg import Debugger

    dbg = Debugger()
    pid, tid = dbg.create_process(target_path)
    # Consume CREATE_PROCESS
    dbg.wait_event(5000)
    dbg.continue_event(pid, tid)
    # Consume until initial EXCEPTION_BREAKPOINT
    for _ in range(50):
        event = dbg.wait_event(2000)
        if event is None or event.type == "EXIT_PROCESS":
            break
        if event.type == "EXCEPTION":
            break
        dbg.continue_event(event.pid, event.tid)

    yield dbg

    # Cleanup
    try:
        dbg.terminate_process(0)
    except Exception:
        pass
    try:
        dbg.close_handle(dbg._session.process_handle)
    except Exception:
        pass
    try:
        dbg.close_handle(dbg._session.thread_handle)
    except Exception:
        pass


@pytest.fixture
def running_session(target_path):
    """Create a raw DebugSession with a running process."""
    from pydbg import _pydbg

    pid, tid, h_proc, h_thr = _pydbg.create_process(target_path)
    _pydbg.wait_for_debug_event(5000)
    _pydbg.continue_debug_event(pid, tid)
    for _ in range(20):
        event = _pydbg.wait_for_debug_event(5000)
        if event is None:
            break
        if event.get("event_name") == "EXCEPTION":
            break
        _pydbg.continue_debug_event(event["pid"], event["tid"])

    yield {"pid": pid, "tid": tid, "h_proc": h_proc, "h_thr": h_thr}

    try:
        _pydbg.terminate_process(h_proc, 0)
    except Exception:
        pass
    for _ in range(50):
        try:
            event = _pydbg.wait_for_debug_event(2000)
            if event is None:
                break
            _pydbg.continue_debug_event(event["pid"], event["tid"])
            if event.get("event_name") == "EXIT_PROCESS":
                break
        except OSError:
            break
    try:
        _pydbg.close_handle(h_proc)
    except Exception:
        pass
    try:
        _pydbg.close_handle(h_thr)
    except Exception:
        pass


@pytest.fixture
def sample_pe32plus_bytes():
    """Minimal synthetic PE32+ bytes for testing."""
    from tests.test_pe import build_minimal_pe32plus
    return build_minimal_pe32plus()


@pytest.fixture
def sample_pe32_bytes():
    """Minimal synthetic PE32 bytes for testing."""
    from tests.test_pe import build_minimal_pe32
    return build_minimal_pe32()


# ── a skip must declare which family of precondition it hit ───────────
#
# A test that stopped running used to look exactly like one that passed: the
# suite stayed green and nothing said which checks had been skipped. Every skip
# reason must now open with one of these families, and the text after it has to
# name what is missing — an unpinned "requires X" was how a whole module went
# quiet.
SKIP_FAMILIES = (
    # Something the build or pip did not install: LLVM backend, capstone, ...
    "optional dependency:",
    # This machine cannot exercise the check: session 0, no system DLL, ...
    "environment:",
    # A test target is missing; the message names the command that builds it.
    "target not built:",
)

_unexpected_skips = []


def _skip_reason(report):
    """The message pytest recorded for a skip (longrepr is (file, line, text))."""
    longrepr = report.longrepr
    reason = str(longrepr[2]) if isinstance(longrepr, tuple) and len(longrepr) == 3 \
        else str(longrepr)
    # pytest.skip() inside a test body records "Skipped: <reason>"; the prefix
    # is pytest's, not the author's, and must not decide the family check.
    for prefix in ("Skipped: ", "skipped: "):
        if reason.startswith(prefix):
            return reason[len(prefix):]
    return reason


def pytest_runtest_logreport(report):
    if not report.skipped or hasattr(report, "wasxfail"):
        return
    reason = _skip_reason(report)
    if not reason.startswith(SKIP_FAMILIES):
        _unexpected_skips.append((report.nodeid, reason))


def pytest_terminal_summary(terminalreporter):
    if not _unexpected_skips:
        return
    terminalreporter.write_sep("=", "skips that do not name a precondition")
    for nodeid, reason in _unexpected_skips:
        terminalreporter.write_line(f"{nodeid}: {reason}")
    terminalreporter.write_line(
        "prefix the reason with one of: " + ", ".join(SKIP_FAMILIES))


def pytest_sessionfinish(session, exitstatus):
    """Green with an undeclared skip is not green."""
    if _unexpected_skips and exitstatus == 0:
        session.exitstatus = 1
