"""ThreadManager — thread open/context/suspend/resume/enumerate/step."""

from .. import _pydbg
from ..exceptions import ThreadError


class ThreadManager:
    """Manages thread operations for the debugged process."""

    def __init__(self, session):
        self._s = session

    def open(self, tid):
        try:
            return _pydbg.open_thread(tid)
        except OSError as e:
            raise ThreadError(f"OpenThread for tid {tid}: {e}")

    def get_context(self, h_thread):
        try:
            return _pydbg.get_thread_context(h_thread)
        except OSError as e:
            raise ThreadError(f"GetThreadContext: {e}")

    def set_context(self, h_thread, context):
        try:
            _pydbg.set_thread_context(h_thread, context)
        except OSError as e:
            raise ThreadError(f"SetThreadContext: {e}")

    def set_register(self, h_thread, name, value):
        self.set_context(h_thread, {name.lower(): value})

    def suspend(self, h_thread):
        try:
            return _pydbg.suspend_thread(h_thread)
        except OSError as e:
            raise ThreadError(f"SuspendThread: {e}")

    def resume(self, h_thread):
        try:
            return _pydbg.resume_thread(h_thread)
        except OSError as e:
            raise ThreadError(f"ResumeThread: {e}")

    def enumerate(self, pid):
        try:
            return _pydbg.enumerate_threads(pid)
        except OSError as e:
            raise ThreadError(f"EnumerateThreads: {e}")

    def get_ids(self, pid):
        return [t["tid"] for t in self.enumerate(pid)]

    def step(self, h_thread):
        regs = self.get_context(h_thread)
        regs["eflags"] = regs.get("eflags", 0) | 0x100
        self.set_context(h_thread, regs)
