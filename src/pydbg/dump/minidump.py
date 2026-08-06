from ..exceptions import PydbgError


STREAM_UNUSED = 0
STREAM_THREAD_LIST = 3
STREAM_MODULE_LIST = 4
STREAM_MEMORY_LIST = 5
STREAM_EXCEPTION = 6
STREAM_SYSTEM_INFO = 7
STREAM_MEMORY_64_LIST = 9


class MinidumpReader:
    """Read Windows minidump (.dmp) files via dbghelp."""

    def __init__(self, path):
        self._path = path
        self._data = None
        self._buffer = None

    def _load(self):
        if self._data is not None:
            return
        with open(self._path, 'rb') as f:
            self._data = f.read()
        # Keep a stable ctypes buffer. id(bytes) points at the object header,
        # not the char data, so dbghelp would read garbage.
        import ctypes
        self._buffer = ctypes.create_string_buffer(self._data, len(self._data))

    def get_stream(self, stream_type):
        self._load()
        try:
            import ctypes
            from .. import _pydbg
            return _pydbg.mini_dump_read_dump_stream(
                ctypes.addressof(self._buffer), stream_type)
        except OSError as e:
            raise PydbgError(f"MiniDumpReadDumpStream failed: {e}")
