# _ui.pxi — window enumeration.
#
# A thin Win32 wrapper, per docs/architecture.md: the C side returns plain
# dicts and every judgement about what they mean lives in
# core/window_probe.py. The one thing that is not merely a judgement and does
# belong here is the error handling, because a Python exception raised inside
# a C callback cannot propagate and a Win32 failure must not be reported as
# "no windows" — those are the two ways this could silently answer the same
# way whether the target is idle or the probe is broken.

from libc.stdlib cimport free, malloc
from libc.stddef cimport wchar_t
from libc.stdint cimport uintptr_t
from cpython.object cimport PyObject
from cpython.unicode cimport PyUnicode_FromWideChar

from _win32types cimport (
    BOOL,
    DWORD,
    GW_OWNER,
    HANDLE,
    HWND,
    LPARAM,
    UINT,
    EnumChildWindows,
    EnumWindows,
    GetClassNameW,
    GetLastError,
    GetWindow,
    GetWindowTextLengthW,
    GetWindowTextW,
    GetWindowThreadProcessId,
    IsHungAppWindow,
    IsWindowEnabled,
    IsWindowVisible,
)


cdef class _WindowWalk:
    """Transient state for one EnumWindows walk.

    A cdef class rather than a struct because the struct form cannot hold
    Python objects, and the two things this has to carry across the callback
    boundary — the accumulated windows and any exception the callback could
    not raise — are both Python objects.

    The GIL is held for the whole walk: EnumWindows is not a blocking call, so
    unlike WaitForDebugEvent there is nothing to release it for.
    """

    cdef list windows
    cdef DWORD pid          # 0 means "every process"
    cdef object error       # the Python exception the callback could not raise
    cdef DWORD win32_error  # set when EnumWindows itself failed

    def __cinit__(self, int pid=0):
        self.windows = []
        self.pid = <DWORD>pid
        self.error = None
        self.win32_error = 0


cdef list _collect_children(HWND parent):
    cdef _WindowWalk walk = _WindowWalk(pid=0)
    EnumChildWindows(parent, _collect_window,
                     <LPARAM><uintptr_t><PyObject*>walk)
    if walk.error is not None:
        raise walk.error
    return walk.windows


cdef int _collect_window(HWND hwnd, LPARAM lparam) noexcept:
    cdef _WindowWalk walk = <_WindowWalk><PyObject*><uintptr_t>lparam
    cdef DWORD pid = 0
    cdef int length
    cdef wchar_t* buffer
    cdef object text
    cdef object class_name

    try:
        GetWindowThreadProcessId(hwnd, &pid)
        if walk.pid and pid != walk.pid:
            return 1                      # a different process; keep walking

        length = GetWindowTextLengthW(hwnd)
        # Sized from the length that was just measured, not from a fixed
        # buffer. The text this exists to read is an error message, and a
        # truncated one is worse than none: it reads as the whole message.
        buffer = <wchar_t*>malloc((length + 1) * sizeof(wchar_t))
        if buffer == NULL:
            raise MemoryError("could not allocate a window text buffer")
        try:
            GetWindowTextW(hwnd, buffer, length + 1)
            text = PyUnicode_FromWideChar(buffer, -1)
        finally:
            free(buffer)

        length = 256
        buffer = <wchar_t*>malloc((length + 1) * sizeof(wchar_t))
        if buffer == NULL:
            raise MemoryError("could not allocate a class name buffer")
        try:
            GetClassNameW(hwnd, buffer, length + 1)
            class_name = PyUnicode_FromWideChar(buffer, -1)
        finally:
            free(buffer)

        walk.windows.append({
            'hwnd': <unsigned long long><uintptr_t>hwnd,
            'pid': pid,
            'class_name': class_name,
            'text': text,
            'visible': bool(IsWindowVisible(hwnd)),
            'enabled': bool(IsWindowEnabled(hwnd)),
            'hung': bool(IsHungAppWindow(hwnd)),
            'owner': <unsigned long long><uintptr_t>GetWindow(hwnd, GW_OWNER),
            'children': _collect_children(hwnd),
        })
    except BaseException as exc:
        # Stashed, not raised: an exception crossing back into C is undefined
        # behaviour, and swallowing it would report a broken probe as "no
        # windows", which is the defect this whole module is about.
        walk.error = exc
        return 0
    return 1


cpdef list enumerate_windows(int pid=0):
    """Every top-level window, with its children, as plain dicts.

    Three outcomes, kept apart on purpose:

    * the walk completed — the list, possibly empty;
    * the walk was stopped by our own callback — the stashed Python exception,
      re-raised;
    * EnumWindows itself failed — OSError, with the code.

    An empty list therefore means what it says. Collapsing any of the three
    into "no windows" is how a probe that never ran becomes indistinguishable
    from a target that owns no windows.
    """
    cdef _WindowWalk walk = _WindowWalk(pid=pid)
    cdef BOOL ok

    ok = EnumWindows(_collect_window, <LPARAM><uintptr_t><PyObject*>walk)
    if walk.error is not None:
        raise walk.error
    if ok == 0:
        walk.win32_error = GetLastError()
        if walk.win32_error != 0:
            raise OSError(walk.win32_error, "EnumWindows failed")
    return walk.windows
