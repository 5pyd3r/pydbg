from ..exceptions import PydbgError


class StackWalker:
    """x64 stack frame walker using dbghelp StackWalk64."""

    MACHINE_X64 = 0x8664

    def __init__(self, session):
        self._s = session

    def walk(self, h_thread, context_bytes, max_frames=64):
        try:
            from .. import _pydbg
        except ImportError:
            raise PydbgError("_pydbg extension not available")

        from ..thread.manager import ThreadManager
        tm = ThreadManager(self._s)
        regs = tm.get_context(h_thread)
        ip = regs.get('rip', 0)
        sp = regs.get('rsp', 0)
        fp = regs.get('rbp', 0)

        frames = []
        for _ in range(max_frames):
            frame = _pydbg.stack_walk_frame(
                self.MACHINE_X64,
                self._s.process_handle,
                h_thread,
                bytes(context_bytes),
                ip, sp, fp)
            if frame is None:
                break
            frames.append(frame)
            ip = frame['frame_ip']
            sp = frame['frame_sp']
            fp = frame['frame_fp']
            if ip == 0:
                break
        return frames
