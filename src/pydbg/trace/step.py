EXCEPTION_SINGLE_STEP = 0x80000004


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
                event.raw.get('exception_code') == EXCEPTION_SINGLE_STEP)

    def clear_tf(self, h_thread):
        from ..thread.manager import ThreadManager
        tm = ThreadManager(self._s)
        regs = tm.get_context(h_thread)
        regs['eflags'] = regs.get('eflags', 0) & ~0x100
        tm.set_context(h_thread, regs)
