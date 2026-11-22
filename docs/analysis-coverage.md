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
- **Phase 2**：S2 边界（`.pdata` 的 `end_rva` 与 UNWIND_INFO）+ S9 反编译器（按
  `decompiler-options` 的 S0–S5）。
- **Phase 3**：D5/D6 追踪与插桩（BBL 用断点 + stub 起步，格式自定）。
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

## 7. 明确不做

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
