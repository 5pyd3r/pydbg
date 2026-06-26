# pydbg 分析框架改进设计

*日期: 2026-06-22*
*来源: OdenTodo 分析 subagent 反馈*

---

## 1. 问题

从 OdenTodo.exe 分析中暴露了 3 个 pydbg 问题：

| # | 问题 | 影响 |
|---|------|------|
| 1 | `_pydbg.get_teb_address()` 不存在 | AntiAware 无法获取 PEB 地址，反检测完全失效 |
| 2 | IAT 解析返回 thunk 地址而非函数地址 | 无法在运行时确定 API 函数的真实地址 |
| 3 | 忙等待游戏断点监控效率极低 | API 调用频率太低，断点几乎不触发 |

---

## 2. 修复方案

### 2.1 添加 `get_teb_address` 到 Cython 扩展

**文件:** `src/pydbg/cython/_pydbg.pyx`

**实现:** 使用 `NtQueryInformationThread` (ThreadBasicInformation=0) 获取 TEB 地址。

```cython
# 新增函数
def get_teb_address(h_thread):
    """通过 NtQueryInformationThread 获取线程 TEB 地址。"""
    cdef THREAD_BASIC_INFORMATION tbi
    cdef ULONG ret_len
    cdef NTSTATUS status

    status = NtQueryInformationThread(
        h_thread, 0, &tbi, sizeof(tbi), &ret_len)
    if status != 0:
        raise OSError(f"NtQueryInformationThread failed: 0x{status:08X}")
    return <uintptr_t>tbi.TebBaseAddress
```

需要声明：
```cython
cdef extern from "ntdef.h":
    ctypedef long NTSTATUS
    ctypedef struct THREAD_BASIC_INFORMATION:
        void* ExitStatus
        void* TebBaseAddress
        void* ClientId[2]
        void* AffinityMask

cdef extern from "ntdll.dll":
    NTSTATUS NtQueryInformationThread(
        void* ThreadHandle, int ThreadInformationClass,
        void* ThreadInformation, ULONG ThreadInformationLength,
        ULONG* ReturnLength)
```

**依赖:** `AntiAware._get_peb_address()` 已经调用此函数，修复后即可工作。

---

### 2.2 在 ModuleResolver 添加 IAT 解析

**文件:** `src/pydbg/module/resolver.py`

**新增方法:**

```python
def resolve_import(self, import_entry, image_base=0):
    """将 ImportEntry 解析为运行时函数地址。

    策略：
    1. 读取 IAT 内存获取 loader 已解析的地址
    2. 回退到 GetProcAddress 手动解析
    """
    h = self._s.process_handle
    ptr_size = 4 if getattr(self._s, 'target_arch', 32) == 32 else 8
    iat_addr = image_base + import_entry.rva

    data = self._read(iat_addr, ptr_size)
    resolved = int.from_bytes(data, 'little')
    if resolved != 0:
        return resolved

    # 回退：GetProcAddress
    dll_handle = _pydbg.get_module_handle(import_entry.dll_name)
    if dll_handle and import_entry.name:
        return _pydbg.get_proc_address(dll_handle, import_entry.name)
    return None

def get_module_handle(self, module_name):
    """获取已加载模块的句柄。"""
    return _pydbg.get_module_handle(module_name)
```

---

### 2.3 添加 MemoryMonitor

**文件:** `src/pydbg/memory/monitor.py` (新建)

**数据结构:**

```python
@dataclass
class MemoryChange:
    address: int
    old_value: bytes
    new_value: bytes
    timestamp: int

@dataclass
class Watchpoint:
    addr: int
    size: int
    fmt: str        # struct 格式字符串
    name: str       # 可读名称
    last_value: bytes = None
```

**API:**

```python
class MemoryMonitor:
    def __init__(self, session):
        self._s = session
        self._watchpoints = {}  # addr -> Watchpoint
        self._changes = []

    def watch(self, addr, size=4, fmt='<I', name=None):
        """添加监控地址。首次调用时记录初始值。"""

    def unwatch(self, addr):
        """移除监控地址。"""

    def poll(self):
        """读取所有监控地址，检测变化。返回 MemoryChange 列表。"""

    def get_changes(self, addr=None, since=None):
        """获取变化记录，可按地址和时间过滤。"""

    def get_snapshot(self):
        """获取所有监控地址的当前值。返回 {addr: value} 字典。"""

    def clear_history(self):
        """清空变化记录。"""
```

**测试:** 使用 `DebugSession` + mock `read_memory` 验证变化检测逻辑。

---

## 3. 文件变更清单

| 操作 | 文件 | 内容 |
|------|------|------|
| 修改 | `src/pydbg/cython/_pydbg.pyx` | 添加 `get_teb_address` |
| 修改 | `src/pydbg/module/resolver.py` | 添加 `resolve_import`, `get_module_handle` |
| 新建 | `src/pydbg/memory/monitor.py` | `MemoryMonitor`, `MemoryChange`, `Watchpoint` |
| 修改 | `src/pydbg/memory/__init__.py` | 导出 MemoryMonitor |
| 修改 | `src/pydbg/__init__.py` | 导出 MemoryMonitor |
| 新建 | `tests/test_memory_monitor.py` | MemoryMonitor 测试 |
| 修改 | `tests/test_stealth.py` | 验证 get_teb_address 可调用 |

---

## 4. 验证计划

1. **get_teb_address**: 验证 AntiAware 可以获取 PEB 地址
2. **resolve_import**: 验证 IAT 条目可以解析为实际函数地址
3. **MemoryMonitor**: 验证 poll() 检测到内存变化

---

*设计完成于 2026-06-22*
