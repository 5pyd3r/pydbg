"""Shared pytest fixtures for pydbg tests."""

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
