import os
import struct

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_TARGET = os.path.join(_TEST_DIR, 'target', 'simple_target.exe')
TEST_TARGET_PATH = os.environ.get('TEST_TARGET_PATH', _DEFAULT_TARGET)

# Architecture-aware register name helpers
HOST_ARCH = struct.calcsize("P") * 8  # 32 or 64
IP_REG = "rip" if HOST_ARCH == 64 else "eip"
SP_REG = "rsp" if HOST_ARCH == 64 else "esp"
GP_REG = "rax" if HOST_ARCH == 64 else "eax"
