# Windows 二进制分析覆盖规格

状态：v1（2026-11-22）。本文件是 wayfinder 地图「全量二进制分析框架覆盖」的终稿，
也是第一批实现的验收依据。证据与调研在本地 tracker（不入库）：
`.scratch/full-binary-analysis/research/inventory.md`、`decompiler-options.md`。

**本规格的实现范围是 §6 的 Phase 1**；其余族分阶段，各自另开 spec（§5）。

## 1. 范围与判据

- 对象：Windows 本机 PE，x86 / x64（含 WOW64 目标）。排除 AArch64 PE、.NET/CLR、内核。
- 交付面：库 API。不做正式 CLI，`devtools/` 脚本维持非正式。
- 「存在且可用」= 公开入口 + 测试 + 边界语义（拒绝而不是猜）+ 文档一句。
- 诚实性原则继承仓库：覆盖率与重叠成对报告；不可判定显式呈现；任何降级都不静默。

## 2. 分类法

每族的「完成判据」必须能被检查；「典型误判」说明什么叫看起来做了、其实没做到。

### 静态

| 族 | 范围 | 完成判据 | 典型误判 |
|---|---|---|---|
| S1 PE 加载与格式 | DOS/NT 头、节、16 个数据目录、overlay、校验和 | 每个目录可读或显式「无此目录」；版本信息解码出字符串表 | 能读导入表就当解析完了 |
| S2 代码发现 | 种子、递归下降、函数边界、填充 | x64 用 `.pdata` 的 begin/end 精确定界；32 位用种子 + 启发；起点集合与异常表一致 | 解码到的字节 = 覆盖率 |
| S3 反汇编与指令语义 | capstone 封装、操作数、隐式寄存器与标志 | 每条指令的读/写操作数、隐式寄存器与标志可查询；未建模指令显式标记 | 反汇编成功 = 语义建模完成 |
| S4 控制流 | CFG、支配、循环、switch | 每函数 CFG 有支配关系、循环与 switch 识别；未解析边显式 | 无异常就算 CFG 完整 |
| S5 数据流与值分析 | 常量传播、值集、别名 | 跨块常量/拷贝传播；汇合不一致即「未知」；值集拒绝可查询 | top 被当成 0 |
| S6 类型与结构 | base+offset 画像、字段表 | 结构画像可导出字段表（宽度、访问次数），不伪造类型名 | 起了个字段名 = 还原了结构体 |
| S7 符号与命名 | PDB、导出/导入、签名、demangle | 名字统一进 `NameTable`，来源可查 | 有 dbghelp 就有符号 |
| S8 识别与分类 | 字符串、熵、壳、版本信息、签名 | 这些事实都能从 `PE` / `analysis` 查询 | 抽到字符串 = 认识样本 |
| S9 反编译 | 单函数伪代码 | 满足 `decompiler-options` 的六条验收 | 输出像 C = 反编译正确 |
| S10 报告与工作区 | 导出、增量、批处理 | 结果可导出 JSON/DOT；workspace 增量；批处理 API | 能 print = 能交付 |

### 动态

| 族 | 范围 | 完成判据 | 典型误判 |
|---|---|---|---|
| D1 进程与线程生命周期 | 创建/附加/分离/终止、子进程、线程 | 退出状态明确；子进程树可查询 | 能启动 = 生命周期完整 |
| D2 事件与异常策略 | 一/二次机会、忽略列表、VEH、continue 标志 | 策略可配置且默认不破坏现有行为 | 固定 `DBG_CONTINUE` 也能跑 |
| D3 内存 | 读写、保护、区域、远程分配 | 含 `VirtualAllocEx` 级分配与释放 | 能读写 = 内存完整 |
| D4 断点 | 软/硬/内存断点、条件、命中计数 | 内存断点（guard page）有 API 与测试 | 有 DR 寄存器 = 有内存断点 |
| D5 追踪 | 指令/内存 trace、调用树 | 可落盘、可回放、可过滤；百万级可跑 | 单步能跑 = 有 trace |
| D6 插桩 | BBL/函数级、参数与返回值 | BBL 级插桩可用，不依赖单步 | 有 LLVM payload = 有插桩 |
| D7 钩子与拦截 | IAT/inline/导出/延迟导入 | 卸载可验证；延迟导入可钩 | 能挂钩 = 能卸干净 |
| D8 dump 与 PE 重建 | dump、节/IAT/导入表重建 | 重建物能被本仓库解析并加载 | dump 出来 = 能分析 |
| D9 执行控制与注入 | 注入、挂起、反调试原语 | 库级注入 API；检测/绕过原语可选 | demo 脚本 = API |
| D10 符号与栈回溯 | 栈回溯、符号化 | x86 与 x64 都能走；PDB 可加载 | x64 能走 = 全架构 |
| D11 观测与输出 | 事件日志、报告 | 结构化输出，可被下游消费 | 回调里 print = 有观测 |

### 跨切

| 族 | 完成判据 |
|---|---|
| X1 架构 | 架构单一真相；WOW64 全路径有测试；不猜未知 machine |
| X2 依赖与导入边界 | 零硬依赖；`import pydbg` 不加载扩展 |
| X3 安全与对抗 | 每个写目标的 manager 有 teardown；反调试原语默认关闭 |
| X4 性能与规模 | 静态 10k 函数、动态 10^6 指令有预算与实测 |

**静态与动态不共用 IR。** 动态追踪要的是廉价的事件编码，反编译要的是表达式树；
共用会逼一方让步。共用的是 `Instruction`、地址算术与 PE 模型（这三样仓库已经单一来源）。

## 3. 现状

（深度来自 2026-11-22 的逐族核查，证据见 `research/inventory.md`。）

- real：S2、S3、S4、S10；D1、D3（无分配）、D4；X2。
- partial：S1（16 目录解析 12 个：0–6、9–11、13、14；缺 7、8、12、15）、S5、S6、S7、
  S8（已有字符串、按节熵与壳启发；无签名/YARA）；D2、D6、D7、D9、D10、D11；X1、X3、X4。
- stub：D5（`StepTracer` 只置 TF，`CallTree` 未接入）、D8（只读 minidump）。
- absent：S9。

## 4. 验收矩阵（Phase 1 范围内）

| 族 | 样本 | 指标 |
|---|---|---|
| S1 | 合成 PE（`tests/pe_builder.py`）+ 真实 DLL | 5 个新目录各自能被读出或显式为空；截断输入不抛未捕获异常 |
| S8 | 已知字节 + 合成 PE | 字符串数量/内容精确匹配；全零节熵 = 0；随机节熵 > 7.5 |
| S2 | `tests/target/simple_target_x64.exe` 等 | `.pdata` 的 begin/end 与函数边界一致（Phase 2 起） |

其余族的样本与指标随各自阶段定义。

## 5. 阶段

- **Phase 1（本规格）**：S1 补全、S8 字符串/熵/壳启发。纯 Python，无新依赖。
- **Phase 2**：S2 边界（`.pdata` 的 `end_rva` 精确定界；UNWIND_INFO 的帧信息留到 Phase 5 的变量恢复）+ S9 反编译器（按 `decompiler-options` 的 S0–S5）。
- **Phase 3a**：D5 块级追踪——软件断点 + v1 记录格式 + 回放/过滤/覆盖率。
- **Phase 3b**：D5 延续（指令级窗口 trace、硬件 watchpoint 内存观察）+ D6 函数级探针（见 §9；
  探针用硬件执行断点，不做 detour/LLVM，理由写在 §9.1）。
- **Phase 4**：D8 dump 与 PE 重建。
- **Phase 5**：S6/S7 类型与符号（PDB）。
- **Phase 6**：D2/D9/D10 补齐与 X3/X4 收口。

每阶段完成后再写下一阶段的 spec；本文件只维护分类法与阶段索引。

## 6. Phase 1：本规格的实现范围

目标：让静态侧「能把 PE 读全、能给出字符串与识别证据」，且不引入任何依赖。

### 6.1 共同约束

- 纯 Python；`import pydbg` 与 `pydbg.analysis` 不加载 `_pydbg`（ADR-0001）。
- 失败语义与现有 `read_rva` / 目录解析一致：目录不存在 → `None` / 空列表；截断 → 返回已解析部分并停止；不抛未捕获异常。
- 不可读的节跨度按文件内的 `size_of_raw_data` 前缀测熵并报告该 size；完全不可读的节 `entropy=None`、`size=0`。
- 新公开入口各一句 docstring；README 由集成阶段统一更新（不单独开 ticket）。
- 不给 `pyproject.toml` 增加依赖。

### 6.2 交付项

1. **P1 PE 数据目录补全**：延迟导入（13）、绑定导入（11）、Load Config（10）、
   Security/Authenticode 位置（4）、CLR 头（14，只读头，不做 IL 分析）。
2. **P2 版本信息资源解码**：`RT_VERSION` 的 `VS_VERSIONINFO` → 固定信息 + 字符串表 + 翻译表。
3. **P3 字符串提取与熵/壳启发**：ASCII / UTF-16LE 字符串、按节熵、可组合的壳启发。

验收以各 ticket 的正文为准；Phase 1 整体另需：上述新测试全绿、`flake8 --max-line-length=120` 干净、
`pyproject.toml` 无改动。

## 7. Phase 2：反编译 MVP（S2 边界 + S9）

目标：单函数伪代码——表达式 + 控制流结构，**不做类型还原**。路线与取舍见本地调研
`decompiler-options.md`（S0–S5、六条验收），本阶段只实现其中的最小链。

### 7.1 共同约束

- 纯 Python；capstone 已是 `disasm` extra，不新增依赖。
- `pydbg.analysis.decompile` 不加载 `_pydbg`（ADR-0001）。
- 诚实降级：未建模指令 → `// unhandled: <mnemonic> <op_str>`；不可约区域 → `label` + `goto`；
  任何指令都不静默丢。
- 失败：函数不在函数表、或没有可解码指令 → 返回 `None`，不抛。

### 7.2 交付项

1. **S2 精确定界**：x64 优先用 `.pdata` 的 `begin/end`（`ExceptionEntry`），替换「下一个起点」
   启发；无 `.pdata` 时行为不变。
2. **S9 核心**：`analysis/decompile/`（`ir.py` / `expr.py` / `render.py`），公开
   `decompile_function(result, rva)`。S0 取范围、S1 降 IR、S2 块内表达式、S5 文本。
3. **S9 结构化**：`structure.py`——支配树 + 自然循环（区间法是可选替代，本实现不用它）、
   `if/else`、`while`、`do-while`、`switch`、不可约 `goto`。

### 7.3 API

```python
decompile_function(result, rva, max_blocks=4096) -> DecompiledFunction | None
DecompiledFunction(rva, text, blocks, extra_blocks, complete, unhandled, warnings)
```

- `blocks`：CFG 自己的块起点，升序，仅此而已。
- `extra_blocks`：跳表命名的、CFG 从未构建的块起点，升序；非空时 `warnings` 含
  `jump-table blocks`。两者分开，调用方拿 `blocks` 与 `build_function_cfg` 对照时不会
  因为并入而自动成立。
- `text`：C 风格，带地址注释；函数命名用 `sub_<rva>`，内存操作数保持原始
  `[base + disp]` 形状，不做变量/字段命名——变量与结构体恢复属 Phase 5，本阶段不承诺。
- `unhandled`：`(rva, mnemonic)` 元组，数量与 `text` 里 `// unhandled:` 行数一致。
- `complete=False`：CFG 有未解析边或被截断；`warnings` 说明原因。

### 7.4 支持子集

整数指令：`mov` / `lea` / `add` / `sub` / `and` / `or` / `xor` / `imul` / `inc` / `dec` /
`neg` / `not` / `cmp` / `test` / `jcc` / `jmp` / `call` / `ret` / `push` / `pop`。
EFLAGS 作为伪寄存器：写指令声明写全 6 个标志，`jcc` 声明读它实际需要的子集；子寄存器别名
（`al/ax/eax/rax` 等）归一。`push`/`pop` 可能降成显式的栈指针调整；栈指针不用于参数/局部变量
恢复（属 Phase 5），也不做完整帧还原。

### 7.5 验收

1. 五类控制流各有 golden 测试：`if/else`、`while`、`do-while`、嵌套循环（C 的 `for` 与
   `while` 共用一种形状）+ `break/continue`、4 分支 `switch`；其中 `if/else` 与 `while`
   断言整段文本（golden），其余形状断言关键词与缩进。
2. 输出引用的 RVA 集合 ==（CFG 块的指令集合 ∪ `extra_blocks` 的指令集合），且
   CFG 块的指令集合 ⊆ 输出；不静默丢，switch 也按此等式验收（不排除）。
3. `// unhandled:` 行数 == IR 里 `Opaque` 语句数。
4. 不可约函数输出 `label`/`goto`，仍满足第 2 条。
5. 500 条指令的函数反编译 < 100 ms（复用 `InstructionDecoder` 缓存，不重复解码）。
6. 同一函数两次调用输出字节级一致（无集合迭代顺序泄漏）。

Phase 2 整体另需：新测试全绿、`flake8 --max-line-length=120` 干净、`pyproject.toml` 无改动、
README 在集成阶段统一更新。

## 8. Phase 3a：块级追踪（D5）

目标：把「目标跑过哪些基本块」变成可落盘、可回放、可过滤、可汇总的事实。断点路径起步，
**不自建 DBI 引擎**；指令级/内存级预算留给 Phase 3b。

### 8.1 约束

- 纯 Python + 现有 Win32 调试原语；不新增依赖，`pyproject.toml` 不动。
- 事件流是唯一真相：`TraceWriter` 写、`read_trace` 读，两者必须逐字节互逆。
- 诚实：预算截断 → `TraceSummary.truncated` 为真（由 `reason` 推导，不单独存储）；
  模块无可用 CFG → `plan() == 0`（明确「不可追踪」而不是产出空 trace）；模块字节解析/分析失败
  （例如传入的区域根本不是 PE）同样返回 0，不抛出。
- 性能：不承诺 DynamoRIO 吞吐；记录实测块/秒并写进测试输出，不设硬阈值（避免 CI 抖动）。

### 8.2 记录格式 v1

- 文件头 12 字节：`b"PDBGTRC\0"` + `u16 version=1` + `u16 flags=0`。
- 每条记录 36 字节，结构 `<B3xIIQQQ`：`kind u8`、`tid u32`、`rva u32`、`ts u64`
  （`time.perf_counter_ns()`）、`a u64`、`b u64`。
- `kind`：`BLOCK=1`（rva=块起点，a=该块指令数）、`API=2`（a=hook id，rva=返回地址）、
  `MARK=3`（a=用户标记）、`MEM_READ=4` / `MEM_WRITE=5`（a=地址，b=大小；Phase 3b 才产生）。
- 坏 magic、未知 version、截断的尾部记录 → `TraceFormatError`。

### 8.3 API

```python
pydbg.trace.TraceWriter(path)             # 上下文管理器；write(event)
pydbg.trace.read_trace(path)              # 迭代 TraceEvent；格式错误抛 TraceFormatError
pydbg.trace.TraceEvent(kind, tid, rva, ts, a=0, b=0)
pydbg.trace.BblTracer(dbg, module=None, max_events=100_000, max_blocks=4096,
                      sink=None)
    .plan() -> int                        # 可下断点的块数；0 = 不可追踪
    .arm() -> int                         # 给计划块下断点，返回自己拥有的断点数
    .disarm() -> tuple[str, ...]          # 只撤销自己下的断点；返回清理警告
    .run(max_idle_timeouts=3) -> TraceSummary   # 未 arm 时自动 arm，跑、记录、撤销
pydbg.trace.filter_events(events, kinds=None, tid=None, rva_min=None, rva_max=None)
pydbg.trace.block_coverage(events) -> dict[int, int]
pydbg.trace.to_jsonl(events, path)
```

`module` 可以是 `enum_modules()` 的模块 dict，也可以是 `(base_address, size)` 元组（用于命名
任意区域，包括不是 PE 的区域）。标准顺序：

```python
tracer.plan()             # 目标暂停时读镜像
tracer.arm()              # 仍然暂停时下断点，避开「恢复后才下断点」的漏块竞态
dbg.continue_event(...)   # 释放挂起的调试事件
summary = tracer.run()
```

`run()` 在未调用 `arm()` 时会自行 arm，以便调用方已经恢复目标时仍可使用；该路径存在竞态，
docstring 已说明。

```python
TraceSummary(events, blocks, reason, elapsed_ns,
             warnings=(), single_step_pending=False)
```

- `blocks` 是**命中的不同块**，不是计划块数。
- `truncated` 是只读属性：`reason in {STOP_MAX_EVENTS, STOP_IDLE_TIMEOUT}`，不单独存储。
  停止原因常量由 `pydbg.trace` 导出：`STOP_MAX_EVENTS`、`STOP_IDLE_TIMEOUT`（截断）、
  `STOP_TARGET_EXITED`、`STOP_NO_BLOCKS`。
- `warnings` 报告不抛异常的清理问题：`"breakpoint left"`（目标仍活但字节没恢复）、
  `"target exited during cleanup"`（目标已退出，字节无法恢复）、
  `"reused caller breakpoints"`（计划地址上已有调用方的断点，未占有也未撤销）。
- `single_step_pending` 为真表示调试器仍有挂起的单步：调用方拥有那个尚未 continue 的调试事件。

### 8.4 块来源

`analyze_process(session, module_base, module_size=...)` → 遍历 `result.functions` 的
`cfg_of(rva)` 收集块起点，去重，只保留落在模块可执行范围内的起点，上限 `max_blocks`。

### 8.5 验收

1. 格式：五类事件 round-trip 后逐字段相等；同一事件序列写两次字节相同；坏 magic、坏 version、
   截断尾记录各抛 `TraceFormatError`。
2. 过滤：按 kind / tid / rva 区间过滤，事件顺序不变。
3. 覆盖率：同一块出现三次 → `{rva: 3}`，`unique` 计数正确。
4. 追踪：对 `tests/target/simple_target.exe` 的主模块，`plan() > 0`；`run()` 至少记录 1 个
   `BLOCK`，所有 rva 落在 `[base, base+size)`；`max_events` 生效时 `summary.truncated is True`
   且 `reason == STOP_MAX_EVENTS`；清理只撤销自己 arm 的断点（计划地址上调用方已有的断点被复用
   且保留，不调用 session 级 `verify_breakpoints()`）；目标已退出时以
   `warnings == ("target exited during cleanup",)` 记录，目标仍活却无法恢复的字节记
   `"breakpoint left"`；目标能正常终止。
5. 性能：记录实测块数与耗时、块/秒；若目标在达到 1,000 个事件前退出，以实际事件数为准。
   断言「不丢事件」（writer 计数 == reader 计数）。
6. 现有 `tests/test_trace.py tests/test_breakpoint.py` 全绿；`pyproject.toml` 不变。

### 8.6 不做

指令级/内存级记录（3b，需要 D6 插桩）、跨进程与内核 trace、时间戳精度承诺、把 trace 变成覆盖率
（`block_coverage` 只是汇总，不替代静态 `CoverageReport`）。

## 9. Phase 3b：指令级窗口、内存观察与函数级探针（D5 延续 + D6）

目标：在 Phase 3a 的块级事件之外，补上三类**可落盘的事实**：一个线程窗口内执行了哪些指令、
被观察的内存地址何时被写、某个函数被调用了几次。三者与 `BblTracer` 共用同一套 v1 记录格式、
`TraceEvent`、`TraceSummary` 与 replay，不新增记录格式版本。

### 9.1 边界与决策（与 `06-trace-instrumentation` 的差异已记录）

- **窗口，不是全量**：指令 trace 是单线程、单次运行的窗口（默认上限 10^4 条）；全量指令/内存
  trace 需要 code cache 或静态重写，等于自建 DBI，仍在 out of scope。多线程窗口不做。
- **不新增依赖**：capstone 已是 `disasm` extra；`pyproject.toml` 不动。`import pydbg.trace`
  仍不加载 `_pydbg`（ADR-0001）。
- **D6 的实现形态改为硬件执行断点探针**，不是 `instrument/` 的 LLVM detour。原决定的 detour
  方案要求 payload 把调用事实送回来，而现有 C 子集没有指针/extern 全局，pydbg 与目标之间没有
  通道；本机也没有 LLVM 后端，detour 版本只能靠 CI 验证。硬件探针不写目标字节、不引入 LLVM、
  本机可完整测试，代价是**最多 4 个调试寄存器槽位**（与 §9.4 的 watch 共享）、只在函数入口观察、
  拿不到返回值。返回值与 BBL 级 detour 一起留到 Phase 3c。
- **`MEM_READ` 不产生**：Windows 的硬件数据断点只有 write 与 read/write 两种条件；read/write
  命中时事件里没有方向信息，把读写都标成 `MEM_READ` 就是猜。本阶段只提供写观察（`MEM_WRITE`），
  `MEM_READ` 留给 Phase 3c 的插桩路径。这符合仓库「拒绝而不是猜」的边界语义。
- **已知行为**：硬件断点在初始 loader 断点处写入会被随后的 continue 丢弃（实测不触发）；三个
  新入口都要求在**正常停止点**（例如 `run_until` 之后）arm/watch。
- **诚实停止**：窗口离开模块、遇到调用方的断点、遇到异常，都以 `TraceSummary.reason` 显式停止，
  不把「没记录到」说成「没发生」。**已经驱动过目标**的预算截断不 continue 事件，
  `single_step_pending` 为真，调用方拥有那个未 continue 的调试事件；驱动前的预检停止
  （0 预算、`start` 在模块外）不消费事件，该标志为假。

### 9.2 记录格式 v1 扩展

- 新增 `INSTR = 6`：`rva` = 指令地址的 RVA，`a` = 指令长度（字节；解码失败记 0），`b` = 0。
- `KIND_NAMES` 同步加 `6: "INSTR"`。读取器不认识的 kind 仍然原样交出（整数是事实，
  `kind_name` 为 `None`），所以新文件对旧读取器是「未知种类」而不是坏文件。
- `TraceSummary` 增加 `instructions: int = 0`（INSTR 事件数；块/内存/探针 trace 为 0）。
  这是向后兼容的默认字段，`blocks` 仍是「命中的不同 BLOCK 起点数」。

### 9.3 API

```python
pydbg.trace.InstructionTracer(dbg, module=None, max_instructions=10_000, sink=None)
    .run(start=None, max_idle_timeouts=3) -> TraceSummary

pydbg.trace.MemoryWatch(dbg, addr, length=4, max_events=10_000, tid=None, sink=None)
    .arm() -> int
    .disarm() -> tuple[str, ...]
    .run(max_idle_timeouts=3) -> TraceSummary

pydbg.trace.FunctionProbe(dbg, addr, params=0, module=None, max_calls=10_000,
                          tid=None, sink=None)
    .arm() -> int
    .disarm() -> tuple[str, ...]
    .run(max_idle_timeouts=3) -> ProbeSummary

pydbg.trace.ProbeSummary(calls, reason, elapsed_ns, warnings=(), single_step_pending=False)
pydbg.trace.ProbeCall(tid, rva, args, ts)
```

停止原因复用 `STOP_MAX_EVENTS` / `STOP_IDLE_TIMEOUT` / `STOP_TARGET_EXITED`，并新增（导出）：

- `STOP_LEFT_MODULE = "left_module"`（下一条指令离开模块）
- `STOP_BREAKPOINT = "breakpoint"`（窗口内命中调用方断点）
- `STOP_EXCEPTION = "exception"`（窗口内出现非单步异常）
- `STOP_NO_MODULE = "no module"`（拿不到模块基址/大小）
- `STOP_NO_TARGET = "no target"`（没有 attach 的目标）

`truncated` 仍只由预算原因（`max_events`、`idle_timeout`）推导；`left_module` 等是「窗口按规则
结束」，不是预算截断。

### 9.4 InstructionTracer

- `module` 同 `BblTracer`：模块 dict、`(base_address, size)` 元组或 `None`（主模块）；拿不到
  基址或大小时返回 0 事件 + `STOP_NO_MODULE`，不抛。
- `start`（绝对地址）：先在**未下断点**时解码该地址的第一条指令得到长度，再用
  `dbg.run_until(start)` 跑到它，完成它留下的断点单步，把 `INSTR(start - base, len)` 记为
  第一事件，然后从下一条指令开始单步。`start=None` 时要求目标已停在一个调试事件上，窗口从
  当前 RIP 之后的第一条指令开始（当前指令已被停住，不补记）。
- 单步机制：每次继续前读 RIP 作为 `cursor`、置 TF；收到单步事件时 `executed = cursor`，
  在该地址解码长度并记 `INSTR(executed - base, len)`，`cursor = event.exception_addr`
  （单步事件的 ExceptionAddress 是**下一条**指令），再置 TF、继续。TF 在异常交付时被清掉，
  所以每一步都要重设，不能设一次。
- 预算在记录前检查；`max_instructions=0` 记录 0 条并以 `STOP_MAX_EVENTS` 截断。
- 下一条指令落在模块外 → 记完当前条后以 `STOP_LEFT_MODULE` 停止；`start` 本身、或
  `start=None` 时的当前 RIP 已在模块外 → 在驱动目标之前就以 `STOP_LEFT_MODULE` 停止
  （不置 TF、不 continue）。`rva` 因此始终落在 `[0, size)`。
- 窗口内命中断点 → `STOP_BREAKPOINT`；出现其他异常 → `STOP_EXCEPTION`；目标退出 →
  `STOP_TARGET_EXITED`；空闲超时 → `STOP_IDLE_TIMEOUT`。后两者之外的停止都不 continue 事件。
- 解码失败（capstone 缺失除外）→ 该条 `a=0`，`warnings` 记一次 `"undecodable instruction"`，
  继续走；capstone 未安装时 `DisasmEngine` 自己抛 `PydbgError`，不静默。

### 9.5 MemoryWatch

- 只观察**写**：`dbg.set_hw_breakpoint(addr, "w", length, slot, tid)`；`length ∈ {1,2,4,8}`
  且 `addr % length == 0`，不满足抛 `BreakpointError`（8 字节在 x86 目标上由 manager 拒绝）。
- `arm()` 自动挑一个空闲槽（0–3）；4 个都占用时抛 `BreakpointError`
  `"no free debug-register slot"`。`tid=None` 为进程级（含 CREATE_THREAD 复制）。
- `run()` 未 arm 时先 arm（同 `BblTracer`，存在竞态：arm 之后目标可能已经跑过一段，
  应尽量在暂停时 `arm()`）；不自动 disarm（watch 可跨多次 run）。`disarm()` 只移除自己
  arm 的那个 bp，清理失败的语义与 `BblTracer.disarm()` 一致（`"breakpoint left"` /
  `"target exited during cleanup"`）。
- 命中判定：事件的异常码是单步，且该线程 `dr6` 的槽位位为 1；记录 `MEM_WRITE(a=addr, b=length,
  rva=0)` 后把 `dr6` 清零（下一次命中才可区分）。清不掉时报 `"could not clear dr6"` 并停止。
  数据断点在访问**之后**触发，事件地址是下一条指令，所以 MEM 事件的 `rva` 刻意是 0。
- `sink` 为 None 时只统计不落盘；预算在记录前检查，0 表示第一次命中就停（0 条事件）。

### 9.6 FunctionProbe

- 硬件执行断点 `dbg.set_hw_breakpoint(addr, "x", 1, slot, tid)`；`tid` 缺省取
  `session.tid`（**单线程**探针，不做多线程聚合）。
- 命中：读 `dr6` 槽位位；返回地址取 `[rsp]`（x64，8 字节）或 `[esp]`（x86，4 字节）；
  `params` 个 `int` 参数按 ABI 取 `rcx/rdx/r8/r9`（x64）或 `[esp+4+4*i]`（x86），
  取低 32 位。记 `ProbeCall(tid, rva, args, ts)`；`rva = 返回地址 - 模块基址`，不在模块内记 0
  并 warning。`sink` 收到 `TraceEvent(kind=API, tid, rva, ts, a=hook_id)`，`hook_id` 即断点 id。
- 步过舞蹈：命中后把该槽地址清零、`dr6` 清零、置 TF，让原指令执行；下一条单步事件里恢复
  槽地址与 `dr7` 使能位、清 `dr6`。预算用尽时把槽地址与 `dr6` 清零、不置 TF，直接停
  （不清地址则继续后会立刻再次命中）。
- `disarm()` 移除 bp；槽位释放后可被 watch/另一个 probe 复用。
- 已知限制（写进 docstring 与 `KNOWN_ISSUES`）：4 槽共享；无返回值；单线程；不写目标字节，
  因此不做 detour、也不需要 RIP-relative 重定位。

### 9.7 验收

1. 格式：`INSTR` 五字段 round-trip；`KIND_NAMES[INSTR]` 与 `to_jsonl` 的 `kind_name` 正确；
   旧读取器（不认识 6）仍能读出整数。
2. 指令 trace：对 `instrument_target`（meson 构建，`TEST_INSTRUMENT_TARGET_PATH`；见附录）
   的导出 `add_numbers` 入口 `run(start=...)`，事件数 ≥ 3、全部 `0 <= rva < size`、第一事件
   `rva == start - base` 且 `a >= 1`；`max_instructions=2` 时恰好 2 条、`truncated` 为真、
   `single_step_pending` 为真；writer 计数 == reader 计数；
   `summary.instructions == events`、`summary.blocks == 0`；之后目标可正常终止。
3. 内存观察：`instrument_target` 的 `g_sum`（4 字节，正常停止点 arm）连续两次写 →
   两条 `MEM_WRITE`，`a == g_sum`、`b == 4`、值确实前进；`max_events=1` 截断；
   没有空闲槽位时报 `BreakpointError`；disarm 后 `verify_breakpoints() == []`。
4. 函数探针：`add_numbers(1, 2)` 连续 3 次调用 → 3 条 `API` 事件，`a` 为 hook id，
   `rva == 返回地址 - base`，`args == (1, 2)`；`max_calls=1` 截断；disarm 后无残留；
   槽位冲突报错。
5. Phase 3b 整体：新测试全绿、`flake8 --max-line-length=120` 干净、`pyproject.toml` 无改动、
   现有测试（含 `test_trace_bbl.py`、`test_trace_format.py`）全绿。

### 9.8 不做

- 全量指令/内存 trace、rep 前缀展开、寄存器差分、`MEM_READ` 的产生。
- 返回值捕获、BBL/指令级插桩、RIP-relative 重定位、多线程指令窗口。
- 时间戳精度承诺、把窗口 trace 变成覆盖率报告。

## 10. Phase 5：符号与类型（S7 + S6）

目标：把 PDB 变成两条可查询的事实——地址的名字、结构体的字段表——并且**没有 PDB 时结构画像仍然可用**。
`S7` 的判据是「名字统一进 `NameTable`，来源可查」，`S6` 的是「结构画像可导出字段表（宽度、访问次数），不伪造类型名」。

### 10.1 边界与路线

- **读取路线：dbghelp 离线（ctypes）+ 自研 MSF 校验壳**。dbghelp 对 GUID/age 不匹配的 PDB **静默接受**
  （只吐 3 条地址错误的 publics，`lasterr=0`），所以校验必须自己做；反过来，自研 TPI/Publics 解析器是
  3–4k 行的长尾工程，本阶段不做。`pydbg/pdb/` 的入口保持协议形状，将来换实现不动调用方。
- 只做**名字 + 类型**。行号 / 源文件映射（dbghelp 顺手能读到，但 `S7` 判据不含、本阶段不验收）、
  FLIRT / YARA 签名匹配、符号服务器下载、Go `pclntab` / Rust v0 名字恢复、32 位 PDB 都不做。
- 纯 Python：不 import `_pydbg`、不 import capstone（ADR-0001 延伸）。`pyproject.toml` 不加依赖。

### 10.2 硬约束（来自前置实测，见本地 `research/pdb-format.md`）

1. GUID/age 只比**原始字节**：info stream `+8 Age`、`+12 Guid`（16 B），与镜像 `RSDS` 逐字节相同；
   镜像侧由 `pe.parser.decode_codeview` 解出 `CodeViewInfo.guid_bytes`（16 字节原样），
   `lookup._identity_matches` 优先比它；只有不携带原始字节的鸭子类型记录才退回字符串比较。
   字符串化用 `bytes_le=` 或与 `pe.parser` 的 8-4-4-4-12 形式一致。
2. dbghelp 从 `System32\dbghelp.dll` 显式加载（`LoadLibraryExW` + `LOAD_LIBRARY_SEARCH_SYSTEM32`）；
   进程级、非可重入 → 库内 `RLock` 串行。
3. `SymSetOptions(0x204)`（`DEFERRED_LOADS|FAIL_CRITICAL_ERRORS`）；**不设 `SYMOPT_UNDNAME`**；要裸名时对
   `?` 开头的名字调 `UnDecorateSymbolName(name, ..., 0x1000)`。
4. `TypeIndex` 是**会话内不透明 id**（不是 CodeView 的 `0x1000` 基索引），禁止跨会话缓存、
   禁止写进结果或 workspace。
5. `lasterr` 只在返回 FALSE 时可信；`SYMBOL_INFOW.NameLen` **含**结尾 NUL；`TI_GET_SYMNAME` 返回
   `LocalAlloc` 指针，取完必须 `LocalFree`。
6. **空枚举 / 只有 publics 不得当成功**：它必须与校验结果一起解释；`symbols()==()` 时 `analysis` 记
   `"pdb: no symbols"` 警告，不静默。
7. MSF：块大小只接受 512 / 1024 / 2048 / 4096；`NumBlocks * BlockSize == 文件长度`；
   `Unknown1 != 0` 判显式 unknown（拒绝）。

### 10.3 API

```python
pydbg.pdb.find(pe_or_image, search_paths=()) -> PdbLookup
pydbg.pdb.open_for(pe_or_image, search_paths=()) -> Pdb | None      # find(...).pdb 的便捷形式
pydbg.pdb.Pdb(path, image_path=None, image_base=None)
    .matches(pe_or_image) -> bool
    .symbols() -> tuple[PdbSymbol, ...]
    .structs() -> tuple[StructLayout, ...]
    .layout_of(name_or_type_index) -> StructLayout | None

PdbLookup(pdb, path, reason)      # reason: None | "no codeview" | "not found"
                                  #         | "pdb mismatch" | "pdb 2.0 unsupported" | "bad pdb"
PdbSymbol(rva, name, size, kind, is_public)      # kind: "function" | "data" | "public" | "unknown"
StructLayout(name, size, fields, source, truncated=False)    # source: "pdb" | "profile"
Field(offset, name, type_name, size, bit_position=None, bit_width=None)
```

- `find()` 的查找顺序：显式 `search_paths` → 镜像 CodeView 记录的绝对路径 → 镜像所在目录下的同名 `.pdb`。
  只认 `RSDS`；`NB10` 返回 `"pdb 2.0 unsupported"`（不按路径猜）。
- `symbols()` 按 `(rva, name)` 去重；`rva = Address - ImageBase`，必须落在 `[0, image_size)`；
  `kind` 只由 `Tag`（5/7/10）决定，`unknown` 原样上报。
- `structs()`：**能读的 UDT 都返回**；读不完整的成员保留在 `fields` 里，`name`/`type_name`
  为 `None`、`size` 为 0，并置 `truncated=True`——不猜宽度、不丢字段。
- 位域：`bit_position` + `bit_width`，`offset` 是存储单元偏移。

### 10.4 名字并入 analysis

- `NameTable` 新增 `SOURCE_PDB = "pdb"`，优先级定为 `user > export > pdb > import > auto`：
  `export` 之上不动（有没有 PDB 不改变既有名字），`pdb` 压过 `import`/`auto`
  （每 build 精确的编译器符号强于 thunk 推导名）。
- `auto_names(result, function_starts=True, pdb=None)`；`resolve(result, names=None, pdb=None)`；
  `resolve_for(result, workspace=None, pdb=None)`。默认 `pdb=None` 时行为与现在逐字节一致。
- PDB 名字**只进 `NameTable`**，不改 `result.functions`（函数起点仍由代码发现决定，两套真相不并存）。
- `analysis` 对 `pydbg.pdb` 是单向依赖；`pydbg.pdb` 不认识 `analysis`。

### 10.5 类型与结构画像

- **无 PDB**：`analysis/types.py` 把现有 `StructureProfile`（`access.py`）暴露成字段表——`name` 用
  `"<function_rva>:<base_reg>"` 的标签，字段只报 `offset` / 宽度 / 读写次数 / 是否函数指针，
  **不发明字段名**。
- **有 PDB**：`StructLayout(source="pdb")` 直接来自 TPI。
- 两轨对齐：`field_report(layout, profile)` 逐 offset 给出 `present_in ∈ {"pdb", "profile", "both"}`，
  对不上的偏移照样列出。

```python
pydbg.analysis.types.structs(result, pdb=None) -> tuple[StructLayout, ...]
pydbg.analysis.types.layout_of(result, key, pdb=None) -> StructLayout | None    # key: 名字或 RVA
pydbg.analysis.types.field_report(layout, profile) -> tuple[FieldReport, ...]
FieldReport(offset, name, type_name, size, reads, writes, called, present_in)
```

反编译**不**消费类型（见 §10.7）；字段表本身已可查询。

### 10.6 验收

1. MSF：合成 fixture 覆盖 512/1024/2048/4096、空流、跨块流；坏 magic、坏块大小、截断、
   `NumBlocks` 与文件长度不符、`Unknown1 != 0` → `PdbFormatError`（带原因），不抛未捕获异常。
2. 校验：真实 PDB → `find().pdb` 非空、`reason is None`；换异 build PDB → `reason == "pdb mismatch"`、
   `open_for() is None`；目录里没有 → `"not found"`；镜像无 CodeView → `"no codeview"`。
3. 名字：导出的、静态的、数据的符号都在；名字未修饰；`(rva, name)` 去重；`rva ∈ [0, image_size)`；
   `NameTable` 优先级单测（user > export > pdb > import > auto）。
4. 类型：`Point` → `size=8`、`x@0` / `y@4`；位域 `bit_position` / `bit_width` 正确；数组字段的
   `type_name` 带宽度（如 `int[4]`）；读不出的成员 `truncated=True` 且不猜宽度；未知名字 → `None`。
5. 集成：`auto_names(result, pdb=...)` 把 PDB 名字并进结果且**不改变** `functions.starts`；
   `types.structs` 有/无 PDB 两轨都能出表；`field_report` 对 profile-only 的偏移给
   `present_in="profile"`。
6. 性能：测试 PDB 的 `find + symbols + structs` < 2 s（实测数字写进测试输出，不设更紧阈值避免 CI 抖动）。
7. Phase 5 整体：新测试全绿、`flake8 --max-line-length=120` 干净、`pyproject.toml` 无改动、现有测试全绿。
8. 测试目标：meson 构建 `pdb_target`（C）与 `pdb_target_cpp`（C++，`/Zi /DEBUG`），测试经
   `TEST_PDB_TARGET_PATH` / `TEST_PDB_PATH` 等环境变量取；缺失时按 `target not built:` 跳过。

### 10.7 与 05 的偏差

- **反编译不消费类型**：`decompile_function` 仍输出 `[base + disp]`。把字段名写进文本要求
  「基址寄存器 → 参数/局部变量」的映射，那是变量恢复，本阶段没做；字段表已可查询。留 Phase 6。

### 10.8 不做

行号 / 源映射、FLIRT / YARA、符号服务器、Go / Rust 名字恢复、32 位 PDB、PDB-only（无镜像）分析、
自研 TPI/Publics 解析器、反编译的类型渲染。

## 11. Phase 4：dump 与 PE 重建（D8）

目标：把「活进程里一段已加载的内存」变成**能被本仓库解析、也能被 Windows 加载**的 PE 文件，
并给调用方一组 **OEP 候选查询**。只做原语，不做一键自动脱壳。

### 11.1 前提与边界

- 活模块解析的现状是 `PE.from_source(ProcessSource(session, base), LoadedView(), va_base=base)`
  （`analysis/image.py`）；**没有** `PE.from_loaded_image`。
- `pe/` 没有写出能力，且 `OptionalHeader`/`FileHeader`/`SectionHeader` 丢了写 PE 需要的字段
  （`DllCharacteristics`、栈/堆、`SizeOfOptionalHeader`、`NumberOfRelocations`）——所以 writer
  **以原始头字节为底稿 patch**，不从 dataclass 重序列化。
- 纯 Python 一侧（`pe/`）不 import `memory`/`dump`（ADR-0001 延伸）；读内存与编排在 `dump/`，
  需要扩展。`pyproject.toml` 不加依赖。
- 已知 bug 的修正单独一张 ticket：`ProcessSource.read` 抛的 `MemError(PydbgError)` 不被
  `Source.try_read` 接住，活体分析遇到不可读页会抛而不是按「读不到」降级。

### 11.2 API

```python
pydbg.dump.dump_module(dbg, module=None, *, max_addr=None) -> DumpedImage
pydbg.dump.dump_region(dbg, base, size, *, name=None) -> DumpedImage

DumpedImage(rva_base, data, gaps, module_name, image_base, size_of_image,
            entry_point_rva, load_delta)
Gap(rva, size, reason)        # reason: "free" | "reserved" | "unreadable:protect=0x.."

pydbg.dump.rebuild_pe(dumped, *, entry_point=None, validate=True) -> RebuiltImage
RebuiltImage(data, report)
RebuildReport(sections_rebuilt, size_of_image, entry_point, load_delta,
              imports, unresolved_imports, gaps, warnings)

pydbg.pe.writer.write_pe(pe, image_bytes, *, entry_point=None) -> bytes
```

- `dump_module`：模块来自 `enum_modules()` 或 `None`（主模块）；先按 `LoadedView` 解析确认是 PE，
  再 dump `[0, size_of_image)`。`dump_region` 不要求 PE，`rva_base=base`。
- `DumpedImage.data` **以模块基址为 0 索引**（`data[i]` 对应 `base + i`）；`gaps` 的 rva 同基准。
- `write_pe` 接收一个用 `LoadedView` 解析出来的 `pe` 与同一份 RVA 索引字节，返回**文件布局**的字节。
  `rebuild_pe` 负责把 `DumpedImage` 变成这两样东西并组装报告。
- `RebuiltImage` 不落盘，调用方拿 `bytes` 自己写。

### 11.3 重建规则

1. 解析：`PE.from_source(BytesSource(dumped.data), LoadedView(), va_base=dumped.image_base)`；
   失败 → `RebuildError("not a PE image")`。
2. 头：复制 `[0, size_of_headers)` 原始字节为底稿，只 patch
   `SizeOfImage = align(max(section.va + span), SectionAlignment)`、`SizeOfHeaders`、
   `AddressOfEntryPoint`（可被 `entry_point` 覆盖）、`CheckSum = 0`；
   `FileAlignment`/`SectionAlignment` 保持原值。
3. 节：`raw_size = align(virtual_size, FileAlignment)`（dump 里 `virtual_size` 比 `size_of_raw_data` 可信）；
   `raw_ptr` 从 `align(SizeOfHeaders, FileAlignment)` 起逐节递增；数据取
   `data[va : va + virtual_size]`，不足零填充；更新节表 `PointerToRawData`/`SizeOfRawData`。
4. 导入：描述符 / ILT / 名字随节复制，**IAT 槽不动**（加载器会重填）；不合成导入表。
   描述符里 `name`/`ordinal` 都缺的槽进 `unresolved_imports`；导入目录落在 gap 上 → `imports_unreadable`。
5. `load_delta = 运行时模块基址 − 头里的 ImageBase`；非 0 只记录、不重写地址。
6. `validate=True` 时用 `PE(data)` 回读；失败 → `RebuildError`（带原因），不返回半成品。

### 11.4 gaps 与失败语义

- `Gap.reason` 来自 `enum_regions` 的 `state`/`protect`；**不用** `read_memory_safe` 的 `win32_error`
  （未提交页那里恒为 0）。
- gap 落在节数据上 → 零填充并按节记 `"gap in <section>"`；落在头上 → `RebuildError`。
- 结构性错误（不是 PE、头不可读、`validate` 失败）→ `RebuildError`；可降级项只进 `report`/`warnings`。

### 11.5 OEP 查询

```python
pydbg.dump.tls_callbacks(pe) -> tuple[int, ...]
pydbg.dump.executable_ranges_outside_functions(result) -> tuple[tuple[int, int], ...]
pydbg.dump.watch_writes(dbg, addr, length=4, *, tid=None) -> TraceSummary
pydbg.dump.oep_candidates(pe_or_result, watched=()) -> tuple[OepCandidate, ...]
OepCandidate(rva, source, evidence)     # source: "tls" | "pdata-gap" | "watched"
```

- 聚合器**只排序、不评分、不判定**；`evidence` 是事实（TLS 回调 RVA、该范围在 `.pdata` 内但不在任何
  已知函数起点、写观察命中的地址 + 命中次数），绝不输出「最可能」。
- `watch_writes` 是 `MemoryWatch` 的组合薄封装；已知限制写进 docstring：只观察**写**、4 个调试寄存器槽共享、
  必须在正常停止点 arm。
- 已知不可用也要写进 docstring：`StackWalker` 是 x64-only（WOW64 没有栈回溯），没有页级 guard 监控。

### 11.6 验收

1. writer round-trip：`pe_builder` 的加载布局镜像 → `write_pe` → `PE(data)`：节数、每节
   `characteristics`、`AddressOfEntryPoint`、导入项 RVA 与原来一致；`PointerToRawData` 按 `FileAlignment`
   对齐且单调；`SizeOfImage` 等于按节算出的值。
2. 重建：`build_loaded_image_with_one_import` + 人为 gaps → `report.imports == 1`、`load_delta == 0`；
   gap 落在 `.text` → 该节零填充 + `"gap in .text"` 警告；gap 落在头 → `RebuildError`。
3. 可加载：把重建字节写成临时文件，`LoadLibraryExW(path, 0, DONT_RESOLVE_DLL_REFERENCES)` 成功
   （ctypes；失败按 `environment:` 跳过）。
4. live 冒烟（`optional dependency: Cython extension`）：dump `simple_target` 主模块 → `rebuild_pe` →
   `PE(data)` 解析通过，节数与入口点与源模块一致。
5. OEP：`tls_callbacks` 与 `PE.tls.callbacks` 一致（同一个 `va_base`）；`executable_ranges_outside_functions`
   在目标上给出范围且每个范围都可执行；`oep_candidates` 的 `tls` 条目证据含 RVA；空输入返回 `()`。
6. Phase 4 整体：新测试全绿、`flake8 --max-line-length=120` 干净、`pyproject.toml` 无改动、现有测试全绿。

### 11.7 不做

一键自动脱壳、导入表合成 / 延迟 thunk 解析、全进程快照（按页）、minidump **写**（Phase 6）、
重定位重写、资源 / TLS / 导出表重建、签名与校验和、页级 guard 监控、WOW64 栈回溯。

## 12. 明确不做

GUI、正式 CLI、插件机制、AArch64、.NET/CLR 分析、内核/ETW、自建 DBI 引擎、BinDiff、
一键自动脱壳、商业类型库与签名库本体。

## 附录：本机测试

工作区内的 `python.exe` 以低完整性运行，editable loader 写不了 `build/`；纯 Python 测试用：

```powershell
$ext = 'C:\Users\spyder\AppData\Local\Programs\Python\Python313\python.exe'
$sp  = 'C:\Users\spyder\Desktop\pydbg\venv-x64\Lib\site-packages'
$env:PYTHONPATH = "<worktree>\src;$sp"
& $ext -S -m pytest tests -q -p no:cacheprovider
```

`-S` 让 `.pth` 里的 editable loader 不加载，从而绕开 `build/` 写权限；`$ext` 在工作区外（Medium 完整性），
工作区内的 venv python 是 Low 完整性、连临时目录都建不了。扩展相关测试在本阶段不跑。

Live 测试（BblTracer / InstructionTracer / MemoryWatch / FunctionProbe）需要已编译的 cp313 扩展和真实目标。
在 worktree 里这样 staging（`<main>` 是主工作区，那里有 `build/base-py`）：

```powershell
$stage = "$env:TEMP\pydbg-p3b-stage"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force "$stage\pydbg" | Out-Null
Copy-Item -Recurse <worktree>\src\pydbg\* "$stage\pydbg"
Get-ChildItem -Recurse "$stage\pydbg" -Filter *.pyd | Remove-Item -Force
Copy-Item <main>\build\base-py\src\pydbg\cython\_pydbg.cp313-win_amd64.pyd "$stage\pydbg\_pydbg.pyd"
$sp = '<main>\venv-x64\Lib\site-packages'
$env:PYTHONPATH = "$stage;<worktree>;$sp"
$env:TEST_TARGET_PATH = '<main>\tests\target\simple_target.exe'
$env:TEST_INSTRUMENT_TARGET_PATH = '<main>\build\base-py\tests\instrument_target.exe'
& 'C:\Users\spyder\AppData\Local\Programs\Python\Python313\python.exe' -S -m pytest <tests> -q -p no:cacheprovider
```

staging 后改了 `src/pydbg` 必须重新 copy；`$PYTHONPATH` 里 stage 在最前面，所以 `pydbg` 来自 stage，
`tests` 来自 worktree。
