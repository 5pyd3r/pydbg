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

    def __init__(self, path_or_data):
        """Open a dump from a path, or from the bytes of one.

        The spec asks for both: a .dmp handed over by a person, and a buffer
        already in memory (a crash the caller captured itself).
        """
        if isinstance(path_or_data, (bytes, bytearray, memoryview)):
            self._path = None
            self._data = bytes(path_or_data)
        else:
            self._path = path_or_data
            self._data = None
        self._buffer = None

    def _load(self):
        if self._buffer is not None:
            return
        if self._data is None:
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

    def get_thread_list(self):
        """Thread list stream (MINIDUMP_THREAD_LIST, type 3).

        Raises PydbgError when the dump has no such stream — a dump written
        without threads is a fact about the dump, and returning b'' would make
        it look like a dump with zero threads.
        """
        return self.get_stream(STREAM_THREAD_LIST)

    def get_module_list(self):
        """Module list stream (MINIDUMP_MODULE_LIST, type 4)."""
        return self.get_stream(STREAM_MODULE_LIST)

    def get_memory_list(self):
        """Memory list stream (MINIDUMP_MEMORY_LIST, type 5)."""
        return self.get_stream(STREAM_MEMORY_LIST)

    def get_exception_info(self):
        """Exception stream (MINIDUMP_EXCEPTION_STREAM, type 6)."""
        return self.get_stream(STREAM_EXCEPTION)
