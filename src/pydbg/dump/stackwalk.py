from ..exceptions import PydbgError
from ..thread.manager import MACHINE_X64, MACHINE_X86, arch_for


class StackWalker:
    """Stack frame walker using dbghelp StackWalk64, x64 and WOW64.

    The caller supplies the raw CONTEXT captured for the thread (see
    ThreadManager.get_context_bytes), and the walk starts from the
    instruction, stack and frame pointers *inside those bytes* — a context
    captured at an earlier stop walks the stack as it was then.

    'machine' is None to ask the target process's architecture, or
    'x86'/'x64', 32/64, MACHINE_X86 / MACHINE_X64 (defined once in
    thread/manager.py) to state it. A WOW64 target needs a WOW64_CONTEXT,
    which get_context_bytes(machine='x86') returns.

    StackWalk64 cannot unwind until dbghelp knows the target's modules, so
    walk() takes a temporary symbol session for the process and releases it in
    a finally block. A session the caller already initialized (Debugger
    creates one) is recognized — SymInitialize refuses a second session for
    the same handle — and is left untouched.

    Known limits:

    * On x86, StackWalk64 needs FPO records or PDB symbols to unwind a 32-bit
      frame. With neither loaded, the walk can end after the first frame.
      Frames it could not prove are absent; none are invented.
    * Symbol names are not promised on either architecture. Pass 'resolve='
      to get_call_stack() for names, after initializing the symbol session
      the resolver uses.
    """

    MACHINE_X86 = MACHINE_X86
    MACHINE_X64 = MACHINE_X64

    def __init__(self, session):
        self._s = session

    def _take_symbols(self, _pydbg):
        """Start a temporary dbghelp session; True when this walk owns it.

        SymInitialize(invade=TRUE) loads the target's modules, which is what
        makes SymFunctionTableAccess64 answer. A caller-owned session for the
        same process handle makes this call fail with
        ERROR_INVALID_PARAMETER; that session is not ours to clean up, and
        returning False keeps its lifetime the caller's business.
        """
        handle = getattr(self._s, 'process_handle', None)
        if not handle:
            return False
        try:
            _pydbg.sym_initialize(handle, "", 1)
        except OSError:
            return False
        return True

    def walk(self, h_thread, context_bytes, max_frames=64, machine=None):
        """Walk up to 'max_frames' frames from the CONTEXT bytes.

        Returns [{'frame_ip', 'frame_sp', 'frame_fp'}, ...], frame 0
        innermost. The list ends where dbghelp's evidence ends, at max_frames,
        or at an ip of 0 — it is never padded to max_frames.
        """
        try:
            from .. import _pydbg
        except ImportError:
            raise PydbgError("_pydbg extension not available")

        if h_thread is None:
            raise PydbgError("walk() needs a thread handle")
        context = bytes(context_bytes)
        arch = arch_for(self._s, h_thread, machine)
        machine_type = self.MACHINE_X86 if arch == 32 else self.MACHINE_X64
        ip, sp, fp = _pydbg.context_frame_bytes(arch, context)

        frames = []
        owns_symbols = self._take_symbols(_pydbg)
        try:
            state = None
            for _ in range(max_frames):
                frame = _pydbg.stack_walk_frame(
                    machine_type, self._s.process_handle, h_thread,
                    context, ip, sp, fp, state)
                if frame is None:
                    break
                frames.append({
                    'frame_ip': frame['frame_ip'],
                    'frame_sp': frame['frame_sp'],
                    'frame_fp': frame['frame_fp'],
                })
                # StackWalk64 keeps the rest of its state in the CONTEXT it
                # updates and in STACKFRAME64; without both the next call
                # restarts from the same frame.
                context = frame.get('context', context)
                state = frame.get('frame_state')
                ip = frame['frame_ip']
                sp = frame['frame_sp']
                fp = frame['frame_fp']
                if ip == 0:
                    break
            return frames
        finally:
            if owns_symbols:
                try:
                    _pydbg.sym_cleanup(self._s.process_handle)
                except OSError:
                    pass

    def get_call_stack(self, h_thread, context_bytes, max_frames=64,
                       resolve=None, machine=None):
        """The call stack as a list of dicts, frame 0 innermost.

        Same inputs as walk(): dbghelp unwinds from the raw CONTEXT captured
        at the point of interest, so there is nothing to fetch implicitly. The
        design spec lists this without a context argument; a walk that picked
        its own context would start the stack somewhere else.

        'resolve' is an optional ip -> name callable that fills 'func_name'.
        The frame this binding returns carries no symbol, and guessing one
        from a module base is the confident-wrong answer dump/ exists to
        avoid. 'machine' is forwarded to walk().
        """
        stack = []
        for index, frame in enumerate(
                self.walk(h_thread, context_bytes, max_frames,
                          machine=machine)):
            ip = frame.get('frame_ip', 0)
            stack.append({
                'index': index,
                'ip': ip,
                'sp': frame.get('frame_sp', 0),
                'fp': frame.get('frame_fp', 0),
                'func_name': resolve(ip) if resolve and ip else None,
            })
        return stack
