import os
import struct

TEST_TARGET_PATH = os.environ.get('TEST_TARGET_PATH', 'simple_target.exe')

# Architecture-aware register name helpers
HOST_ARCH = struct.calcsize("P") * 8  # 32 or 64
IP_REG = "rip" if HOST_ARCH == 64 else "eip"
SP_REG = "rsp" if HOST_ARCH == 64 else "esp"
GP_REG = "rax" if HOST_ARCH == 64 else "eax"
