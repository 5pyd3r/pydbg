# 游戏二进制分析框架设计

*日期: 2026-06-22*
*状态: 设计完成*
*原型目标: OdenTodo.exe (1996, 32-bit, DirectDraw/DirectSound)*

---

## 1. 目标

将 pydbg 从一个纯调试器扩展为一个完整的游戏二进制分析框架，能够：

1. **分析** — 对老游戏（Win32, DirectDraw/DirectSound 时代）进行完整的逻辑分析
2. **提取** — 从 PE 文件和运行时内存中提取所有游戏资源
3. **记录** — 拦截并记录所有 API 调用，构建调用图
4. **追踪** — 记录关键函数的执行路径和数据流
5. **复现** — 为游戏重新实现提供足够的信息

以 OdenTodo.exe 为第一个验证目标，设计保持通用性。

---

## 2. 现有能力

| 模块 | 能力 | 成熟度 |
|------|------|--------|
| `core/debugger.py` | 进程创建/附加/分离、事件循环 | 高 |
| `memory/manager.py` | 内存读写/查询/保护 | 高 |
| `breakpoint/` | 软件断点 (INT3) + 硬件断点 (DR0-DR3) | 高 |
| `disasm/engine.py` | Capstone x86/x64 反汇编 | 高 |
| `pe/` | PE32/PE32+ 完整解析（头/节表/导入/导出） | 高 |
| `disasm/analysis.py` | 基本块 + CFG 构建 | 中 |
| `hook/` | IAT Hook + Inline Hook (trampoline) | 中 |
| `symbol/resolver.py` | dbghelp 符号解析 | 中 |
| `dump/stackwalk.py` | x64 栈回溯 | 中 |
| `trace/calltree.py` | 调用/返回树构建 | 低 |
| `patch/assembler.py` | 代码汇编 | 低 |

---

## 3. 缺失能力与设计方案

### 3.1 反检测模块 (stealth/)

**问题**: OdenTodo 在调试器下 DirectDraw 对象损坏、InitFlag 停在 0。

**方案**: 简化实现，按需添加。

```python
# stealth/anti_aware.py

class AntiAware:
    """绕过常见调试器检测。"""

    def __init__(self, session):
        self._s = session

    def hide_all(self):
        """一次性应用所有反检测措施。"""
        self.patch_peb_being_debugged()
        self.patch_peb_nt_global_flag()
        self.patch_heap_flags()

    def patch_peb_being_debugged(self):
        """将 PEB.BeingDebugged 设为 0。"""
        # 读取 TEB -> PEB 地址
        # 写入 0 到 BeingDebugged 偏移 (FS:[0x30] -> +0x2)

    def patch_peb_nt_global_flag(self):
        """清除 PEB.NtGlobalFlag 调试标志。"""
        # 偏移 +0x68, 清除 FLG_HEAP_ENABLE_TAIL_CHECK |
        # FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS

    def patch_heap_flags(self):
        """修复进程堆标志，移除调试标志。"""
        # PEB.ProcessHeap -> Flags (+0x40) 和 ForceFlags (+0x44)

    def hook_is_debugger_present(self, return_value=0):
        """Hook IsDebuggerPresent 返回指定值。"""
        # 通过 IAT hook 实现
```

**依赖**: `MemoryManager`, `IATHook`

---

### 3.2 API 拦截框架 (intercept/)

**问题**: 无法系统性地监控 DirectDraw/DirectSound 调用及其参数和返回值。

**方案**: 基于 IAT Hook + COM VTable 替换的拦截引擎。

#### 3.2.1 拦截引擎

```python
# intercept/api_hook.py

@dataclass
class APICall:
    """一次 API 调用的记录。"""
    timestamp: int          # timeGetTime 值
    tid: int                # 线程 ID
    module: str             # 模块名 ("ddraw.dll")
    function: str           # 函数名 ("DirectDrawCreate")
    args: list              # 原始参数列表
    decoded_args: dict      # 解码后的参数
    return_value: int       # 返回值
    decoded_return: str     # 解码后的返回值 ("DD_OK")
    call_stack: list[int]   # 调用栈地址列表


class APIInterceptor:
    """通用 API 拦截引擎。"""

    def __init__(self, session):
        self._s = session
        self._hooks = {}        # (module, func) -> HookInfo
        self._calls = []        # APICall 记录
        self._decoders = {}     # (module, func) -> decoder_func
        self._filters = []

    def intercept(self, module: str, function: str, decoder=None):
        """注册 API 拦截。通过 IAT hook 实现。"""

    def intercept_module(self, module: str, preset: str = None):
        """拦截模块的所有导出函数。使用 PE 解析获取导出表。"""

    def intercept_com_vtable(self, obj_addr: int, interface: str):
        """拦截 COM 对象的 VTable 方法。
        在 DirectDrawCreate 返回后，拿到 IDirectDraw 指针，
        替换其 VTable 为代理 VTable。
        """

    def get_calls(self, module=None, function=None, tid=None) -> list[APICall]:
        """获取记录的调用，支持过滤。"""

    def get_call_count(self) -> dict[str, int]:
        """获取调用计数统计。"""

    def export_json(self, path: str):
        """导出调用记录为 JSON。"""

    def export_csv(self, path: str):
        """导出调用记录为 CSV。"""
```

#### 3.2.2 调用图构建

```python
# intercept/call_graph.py

@dataclass
class CallEdge:
    caller: int         # 调用者地址
    callee: int         # 被调用地址
    count: int          # 调用次数
    total_time: int     # 总耗时 (ms)


class CallGraphBuilder:
    """从 API 拦截记录构建调用图。"""

    def add_call(self, caller_addr, callee_addr, timestamp, return_timestamp):
        """记录一次调用。"""

    def build_graph(self) -> dict:
        """构建图结构 {nodes: [...], edges: [...]}。"""

    def export_dot(self, path: str):
        """导出为 Graphviz DOT 格式。"""

    def export_json(self, path: str):
        """导出为 JSON。"""

    def get_hot_paths(self, top_n=10) -> list:
        """获取最频繁的调用路径。"""
```

#### 3.2.3 API 预设

```python
# intercept/presets/ddraw.py

DDRAW_API_PRESET = {
    "DirectDrawCreate": {
        "args": [
            {"name": "lpGUID", "type": "pointer", "decode": "guid_or_null"},
            {"name": "lplpDD", "type": "pointer", "decode": "out_pointer"},
            {"name": "pUnkOuter", "type": "pointer", "decode": "unknown"},
        ],
        "return": {"decode": "hresult"},
    },
    # ... 更多 API
}

DDRAW_VTABLE_METHODS = {
    "IDirectDraw": {
        6: "CreateSurface",
        20: "SetCooperativeLevel",
        21: "SetDisplayMode",
        # ... 完整 VTable 映射
    },
    "IDirectDrawSurface": {
        5: "Blt",
        7: "BltFast",
        11: "Flip",
        21: "Lock",
        28: "Unlock",
        # ... 完整 VTable 映射
    },
}
```

**COM VTable 拦截策略**: 在 `DirectDrawCreate` 返回后，拿到 IDirectDraw 指针，读取其 VTable 指针，将 VTable 中的方法入口替换为代理函数。代理函数记录参数后调用原始方法。

**依赖**: `IATHook`, `InlineHook`, `PEParser`, `MemoryManager`

---

### 3.3 资源提取模块 (resource/)

**问题**: 无法从 PE 的 .rsrc 节提取嵌入资源。

**方案**: 解析 PE 资源目录，识别格式，提取到文件。

```python
# resource/pe_resource.py

@dataclass
class ResourceEntry:
    type_id: int           # RT_BITMAP=2, RT_RCDATA=10, etc.
    type_name: str         # "RT_BITMAP", "RT_RCDATA"
    name_id: int           # 资源 ID
    name_str: str          # 字符串名称
    language_id: int       # 语言 ID
    data_rva: int          # 数据 RVA
    data_size: int         # 数据大小
    data_offset: int       # 文件偏移


class PEResourceParser:
    """PE 资源目录解析器。"""

    RESOURCE_TYPES = {
        1: "RT_CURSOR", 2: "RT_BITMAP", 3: "RT_ICON",
        4: "RT_MENU", 5: "RT_DIALOG", 6: "RT_STRING",
        9: "RT_ACCELERATOR", 10: "RT_RCDATA", 16: "RT_VERSION",
        24: "RT_MANIFEST",
    }

    def __init__(self, pe):
        self._pe = pe
        self._resources = []

    def parse(self) -> list[ResourceEntry]:
        """解析资源目录（3层：Type -> Name -> Language）。"""

    def get_by_type(self, type_id: int) -> list[ResourceEntry]:
        """按类型过滤。"""

    def extract(self, entry: ResourceEntry) -> bytes:
        """提取单个资源数据。"""

    def extract_all(self, output_dir: str, type_filter=None):
        """提取所有资源到目录。"""
```

```python
# resource/recognizer.py

class ResourceRecognizer:
    """自动识别资源数据格式。"""

    SIGNATURES = {
        b'RIFF': 'wav',
        b'BM': 'bmp',
    }

    def recognize(self, data: bytes) -> dict:
        """识别数据格式，返回 {format, width, height, bpp, extra}。"""

    def recognize_palette(self, data: bytes) -> dict:
        """识别调色板（256*3=768 或 256*4=1024 字节）。"""

    def recognize_sprite(self, data: bytes, width=None) -> dict:
        """尝试识别精灵数据。"""
```

**依赖**: `PE` (已有)

---

### 3.4 执行追踪模块 (trace/)

**问题**: 缺少完整的指令级执行记录和回放。

**方案**: 混合模式追踪（全量单步 + 采样）。

```python
# trace/execution.py

@dataclass
class TraceEvent:
    index: int              # 事件序号
    timestamp: int
    tid: int
    type: str               # "insn", "call", "ret", "jmp", "mem_read", "mem_write"
    address: int
    mnemonic: str
    op_str: str
    registers: dict | None  # 可选寄存器快照
    memory_access: tuple | None  # (addr, size, value)
    call_target: int | None


class ExecutionTracer:
    """执行追踪引擎。"""

    def __init__(self, session):
        self._s = session
        self._events = []
        self._max_events = 1000000
        self._filters = {'modules': [], 'functions': [], 'skip_ranges': []}
        self._record_regs = False
        self._record_memory = False

    def configure(self, record_regs=False, record_memory=False, max_events=1000000):
        """配置追踪选项。"""

    def add_module_filter(self, module_name: str):
        """只追踪指定模块。"""

    def add_function_filter(self, addr: int, size: int):
        """只追踪指定函数范围。"""

    def start(self):
        """开始追踪。使用单步执行 + 硬件断点混合模式。"""

    def stop(self):
        """停止追踪。"""

    def get_events(self, start=0, end=None) -> list[TraceEvent]:
        """获取追踪事件。"""

    def search_memory_access(self, addr: int) -> list[TraceEvent]:
        """搜索访问指定内存地址的事件。"""

    def get_execution_heatmap(self) -> dict[int, int]:
        """获取地址执行频率热图。"""

    def export_json(self, path: str):
        """导出为 JSON。"""
```

```python
# trace/dataflow.py

class DataFlowTracker:
    """追踪数据在寄存器和内存中的传播。"""

    def __init__(self, tracer: ExecutionTracer):
        self._tracer = tracer

    def track_register(self, reg_name: str, start_value: int) -> list:
        """追踪寄存器值的传播。"""

    def track_memory(self, addr: int, size: int) -> list:
        """追踪内存值的传播。"""

    def find_origin(self, event_index: int, reg_name: str) -> list:
        """找到寄存器值的最初来源。"""
```

**追踪策略**:
- **全量单步**: 每条指令都记录，适合小范围分析（单个函数）
- **采样追踪**: 只在特定地址记录（函数入口/出口），适合长时间监控
- **混合模式**: 进入关注函数时开启全量，离开时关闭（推荐）

**依赖**: `ThreadManager`, `SoftwareBreakpointManager`, `DisasmEngine`

---

### 3.5 分析工作台 (analysis/)

**问题**: 各模块独立运作，缺少统一的分析工作流。

**方案**: 协调器模式，组合各模块完成分析任务。

```python
# analysis/workbench.py

class AnalysisWorkbench:
    """游戏分析工作台。"""

    def __init__(self, target_exe: str):
        self._target = target_exe
        self._dbg = None
        self._stealth = None
        self._interceptor = None
        self._tracer = None
        self._resources = None

    def setup(self, stealth=True):
        """初始化分析环境。"""

    def load_and_analyze_pe(self) -> dict:
        """静态分析：PE 结构、导入表、资源。"""

    def run_with_interception(self, api_preset="ddraw", duration_sec=30) -> dict:
        """动态分析：运行并拦截 API 调用。"""

    def trace_function(self, func_addr: int, max_events=10000) -> list:
        """追踪指定函数执行。"""

    def extract_resources(self, output_dir: str) -> list:
        """提取所有资源。"""

    def generate_report(self, output_path: str):
        """生成分析报告。"""
```

```python
# analysis/game_analyzer.py

class GameAnalyzer:
    """针对老游戏的专用分析器。"""

    def analyze_game_loop(self) -> dict:
        """分析游戏主循环。"""

    def analyze_rendering_pipeline(self) -> dict:
        """分析渲染管线。"""

    def analyze_audio_system(self) -> dict:
        """分析音频系统。"""

    def analyze_input_handling(self) -> dict:
        """分析输入处理。"""

    def analyze_game_objects(self) -> dict:
        """分析游戏对象系统。"""
```

**依赖**: 所有新增模块 + 现有 `Debugger`, `PE`

---

## 4. 模块依赖关系

```
analysis/workbench.py
  ├── pydbg.core.Debugger (已有)
  ├── pydbg.stealth.AntiAware (新增)
  ├── pydbg.intercept.APIInterceptor (新增)
  │     ├── pydbg.hook.IATHook (已有)
  │     ├── pydbg.hook.InlineHook (已有)
  │     └── pydbg.intercept.presets.* (新增)
  ├── pydbg.intercept.CallGraphBuilder (新增)
  ├── pydbg.trace.ExecutionTracer (新增)
  │     ├── pydbg.thread.ThreadManager (已有)
  │     ├── pydbg.breakpoint.SoftwareBreakpointManager (已有)
  │     └── pydbg.disasm.DisasmEngine (已有)
  ├── pydbg.resource.PEResourceParser (新增)
  │     └── pydbg.pe.PE (已有)
  └── pydbg.resource.ResourceRecognizer (新增)
```

---

## 5. 文件结构

```
src/pydbg/
├── stealth/                    # 新增：反检测
│   ├── __init__.py
│   └── anti_aware.py
├── intercept/                  # 新增：API 拦截
│   ├── __init__.py
│   ├── api_hook.py             # 拦截引擎
│   ├── call_graph.py           # 调用图
│   └── presets/                # API 预设
│       ├── __init__.py
│       ├── ddraw.py            # DirectDraw
│       ├── dsound.py           # DirectSound
│       └── win32.py            # 常用 Win32 API
├── resource/                   # 新增：资源提取
│   ├── __init__.py
│   ├── pe_resource.py          # PE 资源解析
│   └── recognizer.py           # 格式识别
├── trace/                      # 扩展：执行追踪
│   ├── __init__.py
│   ├── calltree.py             # 已有
│   ├── step.py                 # 已有
│   ├── execution.py            # 新增：执行追踪引擎
│   └── dataflow.py             # 新增：数据流追踪
├── analysis/                   # 新增：分析工作台
│   ├── __init__.py
│   ├── workbench.py            # 工作台
│   └── game_analyzer.py        # 游戏专用分析器
├── core/                       # 已有
├── breakpoint/                 # 已有
├── disasm/                     # 已有
├── dump/                       # 已有
├── hook/                       # 已有
├── memory/                     # 已有
├── module/                     # 已有
├── patch/                      # 已有
├── pe/                         # 已有
├── symbol/                     # 已有
└── thread/                     # 已有
```

---

## 6. 实现优先级

| 阶段 | 模块 | 优先级 | 依赖 | 预估工作量 |
|------|------|--------|------|-----------|
| 1 | `intercept/api_hook.py` | P0 | IATHook, PE | 3-4 天 |
| 2 | `intercept/presets/ddraw.py` | P0 | api_hook | 2-3 天 |
| 3 | `intercept/call_graph.py` | P1 | api_hook | 1-2 天 |
| 4 | `resource/pe_resource.py` | P1 | PE | 2-3 天 |
| 5 | `resource/recognizer.py` | P1 | pe_resource | 1-2 天 |
| 6 | `stealth/anti_aware.py` | P1 | MemoryManager | 1-2 天 |
| 7 | `trace/execution.py` | P2 | ThreadManager, Breakpoint | 3-4 天 |
| 8 | `trace/dataflow.py` | P2 | execution | 2-3 天 |
| 9 | `analysis/workbench.py` | P2 | 所有新增模块 | 2-3 天 |
| 10 | `analysis/game_analyzer.py` | P3 | workbench | 2-3 天 |

---

## 7. 验证计划

### 阶段 1 验证: API 拦截

```python
# 验证：拦截 DirectDrawCreate 并记录参数
from pydbg.intercept import APIInterceptor

dbg = Debugger()
interceptor = APIInterceptor(dbg._session)
interceptor.intercept("ddraw.dll", "DirectDrawCreate")

pid, tid = dbg.create_process("OdenTodo.exe")
# ... 运行 ...
calls = interceptor.get_calls()
assert any(c.function == "DirectDrawCreate" for c in calls)
```

### 阶段 2 验证: COM VTable 拦截

```python
# 验证：拦截 IDirectDraw::CreateSurface
# 在 DirectDrawCreate 返回后，替换 VTable
# 记录 CreateSurface 的参数（DDSURFACEDESC 结构）
```

### 阶段 3 验证: 资源提取

```python
# 验证：从 OdenTodo.exe 提取所有 WAV 资源
from pydbg.resource import PEResourceParser
from pydbg.pe import PE

pe = PE.from_file("OdenTodo.exe")
parser = PEResourceParser(pe)
resources = parser.parse()
wav_resources = [r for r in resources if r.type_name == "RT_RCDATA"]
assert len(wav_resources) == 18
```

### 阶段 4 验证: 完整分析流程

```python
# 验证：使用 AnalysisWorkbench 完成 OdenTodo 完整分析
from pydbg.analysis import AnalysisWorkbench

wb = AnalysisWorkbench("OdenTodo.exe")
wb.setup(stealth=True)
pe_info = wb.load_and_analyze_pe()
resources = wb.extract_resources("./output")
result = wb.run_with_interception(api_preset="ddraw", duration_sec=10)
wb.generate_report("./output/report.md")
```

---

## 8. 风险与应对

| 风险 | 影响 | 应对 |
|------|------|------|
| COM VTable 替换导致游戏崩溃 | 拦截不可用 | 先用 IAT hook 验证，VTable 替换作为增强 |
| 反检测不够彻底 | 游戏仍无法正常运行 | 逐步添加检测绕过，优先级放低 |
| 单步追踪性能太差 | 无法长时间追踪 | 使用混合模式，关键函数才全量追踪 |
| 资源格式无法识别 | 资源提取不完整 | 保留原始字节，手动分析 |
| 调用图过于庞大 | 难以分析 | 支持过滤和聚合 |

---

## 9. 不在范围内

以下功能**不在**本次设计中，后续按需添加：

- 可视化 UI（图形化调用图、内存浏览器等）
- 自动化游戏规则推断
- 自动化精灵/地图数据格式逆向
- 跨平台支持（仅 Windows）
- 远程调试

---

*设计完成于 2026-06-22*
