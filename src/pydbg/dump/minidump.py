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

    def _load(self):
        if self._data is not None:
            return
        with open(self._path, 'rb') as f:
            self._data = f.read()

    def get_stream(self, stream_type):
        self._load()
        try:
            from .. import _pydbg
            return _pydbg.mini_dump_read_dump_stream(
                id(self._data), stream_type)
        except OSError as e:
            raise PydbgError(f"MiniDumpReadDumpStream failed: {e}")
