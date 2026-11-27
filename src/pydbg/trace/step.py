"""Single-step execution via the Trap Flag (TF).

The exception codes come from `pydbg.constants`, the one home of the Win32
numbers. `EXCEPTION_SINGLE_STEP` and `STATUS_WX86_SINGLE_STEP` stay importable
from here because callers already do (`from pydbg.trace.step import ...`).
"""

from ..constants import EXCEPTION_SINGLE_STEP, STATUS_WX86_SINGLE_STEP

# A 32-bit target under WOW64 reports its single step through the WOW64 status
# code. Recognising only the native code meant step events on x86 targets never
# matched, so the tracer waited for an event that had arrived.
STEP_EXCEPTION_CODES = frozenset((EXCEPTION_SINGLE_STEP,
                                  STATUS_WX86_SINGLE_STEP))


class StepTracer:
    """Single-step execution using TF (Trap Flag)."""

    def __init__(self, session):
        self._s = session

    def step(self, h_thread):
        from ..thread.manager import ThreadManager
        tm = ThreadManager(self._s)
        regs = tm.get_context(h_thread)
        regs['eflags'] = regs.get('eflags', 0) | 0x100
        tm.set_context(h_thread, regs)

    @staticmethod
    def is_step_event(event):
        return (event.type == 'EXCEPTION' and
                event.raw.get('exception_code') in STEP_EXCEPTION_CODES)

    def clear_tf(self, h_thread):
        from ..thread.manager import ThreadManager
        tm = ThreadManager(self._s)
        regs = tm.get_context(h_thread)
        regs['eflags'] = regs.get('eflags', 0) & ~0x100
        tm.set_context(h_thread, regs)
