# pydbg 设计评审与 v0.2 演进计划

**评审对象**：`master` @ `46e7904`
**日期**：2026-11-10
**方法**：三份只读审计（core 分层 / analysis 子系统 / 构建·测试·文档）+ 三轮共 18 个决策问题
**范围**：189 个受版本控制的文件；`core/debugger.py` 1,194 行；`analysis/` 18 模块 4,990 行；`tests/` 35 个测试模块
**状态**：决策已定，工作项已拆分为 GitHub issue #65–#87

---

## 一、一句话结论

**功能在长，骨架没跟上。**

分析层已经是仓库里最大的模块（18 文件 / 4,990 行），却不在架构文档里；
`Debugger` 自称「只做组合」，实际装了约 400 行真逻辑；
清理、目标架构、错误契约三处**没有主人**，各自有 2–4 个互相冲突的实现；
工程化基础（测试登记、构建产物、打包元数据）不可信到无法为破坏性重构兜底。

v0.2 的主题因此不是「加功能」，而是**立住边界**：让每个概念有一个主人，让每个失败有一个出口，让 CI 的绿带信息量。

---

## 二、六类不合理

以下每条断言都带 `file:line` 证据，不依赖印象。

### 2.1 文档描述的是一个不存在的系统

- `docs/architecture.md:37` 把 `disasm/analysis.py` 列为「基本块 / CFG / 后继分析」——该文件不存在，`KNOWN_ISSUES.md:183` 记录它已被 `analysis/cfg.py` 取代。全文 "analysis" 只出现这一次。
- `core/window_probe.py`、`pe/resource.py`、`patch/encoding.py`、`cython/_ui.pxi` 同样不在包布局里。
- `README.md` 的 API 参考漏掉 62 个公开方法中的 23 个；`__init__.py.__all__` 的 43 个名字有 30 个从未出现在 README 里——包括整个 `StaticAnalyzer` / `analyze_file` 家族。
- `docs/superpowers/`：15 个 plan + 13 个 spec，共 364 个 `- [ ]`、0 个 `- [x]`，无索引；描述的多数功能已经落地，还引用不存在的路径。

**为什么是问题**：文档是唯一能让下一个读者（或下一次的自己）相信「这里是什么」的东西。当它描述的是另一个系统，它的每一次存在都在消耗信任。→ #85

### 2.2 门面名不副实

`core/debugger.py` 1,194 行、61 个公开方法。设计稿承诺「~200 行、纯委托」（`docs/superpowers/specs/2026-05-27-phase1-module-refactor-design.md:87`）。实际：

- 四个方法装了约 400 行真逻辑：handle 解析 `79-204`、`wait_event` `356-439`、`run` `559-649`、`run_until` `749-846`。
- 33 处直接 `_pydbg.*` 调用，即便对应 manager 已存在（`wait_event` 里的裸 `open_thread` / `close_handle` `408-419,435` vs `ThreadManager.open()`）。
- 调用私有 `self.brk_hw._arm_thread`（`:410`），直接改 `brk_sw.lost/hits`（`:1150-1156`）。
- 用 `ctypes.windll.kernel32.IsWow64Process`（`:246-259`），而该函数已在扩展里声明（`_win32types.pxd:242`）。

→ #75 / ADR-0002

### 2.3 没有主人：清理、架构、错误

**清理**：`detach()` 只关句柄（`299-319`），INT3 / DR 槽 / IAT / inline / trampoline / 符号全部留在目标里；`terminate_process()` 完全不清；`remove_all_breakpoints()` 要调用方自己先调（docstring `877-879`）；类没有 `close()` / `__enter__`。
`detach()` 还会在关句柄**之前**抛异常（`304-309` vs `309-319`），失败即泄漏。
→ #76 / #71 / ADR-0004

**架构**：目标架构有四个存储点——`session.target_arch`（默认 64，`core/session.py:27-28`）、`pid_arch`/`tid_arch`（`:48-49`）、`ChildProcessInfo.target_arch`（`:16`）、`DisasmEngine._arch_mode`（首次锁存、永不失效）。检测失败返回 64（`debugger.py:255-256`），于是 **WOW64 目标会静默拿到 x64 上下文**。
→ #77

**错误**：`continue_event` 吞所有 `OSError`（`550-557`）；`read_memory_safe` 抛体系外的 `ValueError`；`regions_handle` 漏裸 `OSError` 而六个兄弟都包了 `MemError`；`run()` 用返回 `1` 同时表示「回调叫停」和「退出码 1」（`597,628-649`）。
→ #80、#70

### 2.4 可回答性只做了一半

库的自觉规则是「拒绝不能伪装成答案」——F19 的零命中探测、F23 的值集拒绝、`read_memory_safe` 的 gaps、`verify_breakpoints` 都是这条规则的局部实现。但：

- **规则的实现是错的**：`decoder` 只有一个全局 overlap 计数器（`decoder.py:34,184`），却被拷进每一个 section 的覆盖率报告（`engine.py:497-501`），`model.py:136-147` 与 `report.py:40-44` 都按「本节的重叠」解释。把各节相加，overlap 被乘以可执行节数——`stats.overlap_bytes` 是唯一正确的数。测试只断言那个总数（`test_analysis_attribution.py:138`），所以从没被发现。
- **规则没有名字**：F18/F21/F22/F23 只活在 commit 和测试注释里，`docs/` 下没有任何 analysis 的 spec。
- **空列表仍不等于「没有」**：`enum_modules` 失败返回空列表；`probe` 失败返回 `None` 而超时抛异常。

→ #69 / ADR-0003

### 2.5 analysis 的概念没有单一来源

- `SectionInfo`（`image.py:20-30`）复刻 `SectionHeader`（`pe/types.py:45-53`），节跨度规则 `max(virtual_size, size_of_raw_data)` 抄了 **4 处**。
- analysis 里独立构造了 **8 个** `DisasmEngine`。
- 操作数地址两套单位：`refs.memory_address` 返回 RVA，`consts.address_without_registers` 返回 VA，`owners.py:430-438` 还有第三份 `lea` 拷贝——`consts.py:139-141` 的注释记录了这套分歧曾经造成的 bug。
- 词汇三处重复：`OWNER_KINDS` vs `_OWNER_KINDS`、`_OWNED` vs `_OWNED_KINDS`，一致性靠 `test_analysis_owners.py:474-476` 断言。
- `AnalysisResult` 12 字段 / 37 方法，其中 24 个在方法体里惰性 import 兄弟模块——`model.py` 没有顶层 import，却靠 24 处函数内 import 反向连回 8 个模块。

→ #81 / #82 / #83 / #84 / ADR-0001

### 2.6 工程化基础不可信

- 35 个测试文件由 `tests/meson.build:65-353` 里 35 个手写块登记；新增测试文件 CI 看不见。`tests/conftest.py` 存在但无人使用，pytest 是死依赖。
- `ci.yml` 只有 `pull_request`，**master 的 push 不跑 CI**。
- 60+ 处静默 skip 让绿没有信息量；`KNOWN_ISSUES.md:31` 却声称 skip 已全部清除。
- 两个 `.exe` 被 `git add -f` 强推入库，且**没有任何构建规则能重建它们**——违反仓库自己写下的不变量（`KNOWN_ISSUES.md:112-117`）。
- `pyproject.toml` 作者是 `Your Name`、URL 指向 `github.com/username/pydbg`、声明 MIT 却没有 LICENSE 文件、版本硬编码三处。

→ #65 / #66 / #67 / #86 / #87

### 2.7 现存 bug（不需要决策，直接修）

| 严重度 | 问题 | 位置 |
|---|---|---|
| P0 | 同一地址重复 `set_breakpoint` 把 `0xCC` 当原始字节存下，移除时写回 `0xCC`，**永久腐蚀目标** | `software.py:102-120,94-100` → #68 |
| P1 | 每节覆盖率重叠被放大 | `engine.py:497-501` → #69 |
| P1 | `attach` 失败后 `read_memory` 抛 `TypeError` 而非 `ProcessError` | `debugger.py:276-284` → #70 |
| P1 | `detach` 先抛异常后不管句柄 | `debugger.py:304-319` → #71 |
| P1 | 子进程退出后登记项与句柄不释放 | `debugger.py:378-381,544-548` → #72 |
| P1 | 写内存失败后页面保护不恢复（可能停留 RWX） | `software.py:104-140` → #73 |
| P2 | `WindowProbe` 的 GONE 分支不可达 | `window_probe.py:197,215-217` → #74 |

---

## 三、v0.2 计划

主题：**立住边界**。不新增分析能力。

### 第 0 步 — 立刻（1–3 天）

修 P0 腐蚀问题 **#68**。它独立于任何重构，且每天都在损坏目标。

### 第 1 周 — 安全网

**#65** pytest 发现 + CI `push` 触发 → **#66** 测试目标由构建产出、删除入库 `.exe` → **#67** skip 降级。

*为什么先做这个*：允许破坏性重构的前提是「重构前后测试行为不变」。而现在的测试网有三处破洞——新测试文件不被执行、构建产物不可重建、60+ 静默 skip。**在这一步完成前不做任何结构性重构。**

**验收**：新增一个 `tests/test_*.py` 无需改构建文件即被执行；`git ls-files 'tests/target/*.exe'` 为空且 clean clone 能跑子进程测试；master push 触发 CI。

### 第 2–3 周 — 核心收缩

顺序是刻意排的：

1. **#76 清理所有权 + ProcessManager**（ADR-0004）。先做，因为门面拆分若不先有 teardown，只是把泄漏点搬家。
2. **#77 架构单一真相**。先于事件循环，因为断点与单步路径都要读 arch。
3. **#78 事件循环收敛 + `HandleOutcome`**。
4. **#79 断点状态 dataclass 化**。
5. **#80 错误契约 + `ExitStatus`**。
6. **#75 门面收缩**（ADR-0002）。最后做——它依赖前面几步把 manager 定形。

**验收**：`with Debugger() as dbg:` 退出后目标内存/寄存器/句柄全部回到安装前；`Debugger` 公开方法 ≤ 35；`debugger.py` 除 `ProcessManager` 外无直接 `_pydbg.*`；`run()` 返回带 reason 的 `ExitStatus`。

### 第 4 周 — analysis 边界

**#81** 脱离扩展（ADR-0001）→ **#82** `AnalysisResult` 去方法化 → **#83** 节模型/解码器/RVA 约定 → **#84** 词汇单一来源。

**验收**：在未编译扩展的环境里 `from pydbg.analysis import analyze_file` 成功、`pytest tests/test_analysis*.py` 可跑；`grep -c "DisasmEngine(" src/pydbg/analysis` 为 1；`model.py` 内无函数体内 import。

### 第 5 周 — 收尾

**#85** 文档重构 → **#86** 打包元数据 → **#87** instrument 冻结。剩余 P1/P2 bug（#69–#74 中未被前述重构吸收的部分）在此清空。

### 长期指标

| 指标 | 现在 | v0.2 目标 |
|---|---|---|
| `core/debugger.py` 行数 | 1,194 | ≤ 500 |
| `Debugger` 公开方法 | 61 | ≤ 35 |
| 无扩展环境 import analysis | 否 | 是 |
| 新增测试文件被 CI 看见 | 否 | 是 |
| 入库的构建产物 | 2 个 `.exe` | 0 |
| 文档与代码一致性 | 架构文档漏掉最大模块 | 按真实依赖图重写 |

---

## 四、v1.0 方向（一句话）

**把 pydbg 变成「同一份 PE / 反汇编概念既能静态回答、也能动态证实」的分析内核**：静态分析提出假设（这个地址是函数、这个槽位取值受限），动态调试去证实或推翻；两条线共享同一种可回答的结果类型。这正是 F19–F24 已经在做的事，但还没有被写成架构。

---

## 五、明确不做

- 不新增分析能力（F25 及以后）——边界定住之前，新能力只会加深耦合。
- 不修 instrument 的 x64 RIP-relative 重定位（登记为已知限制）。
- 不支持 32 位宿主。
- 不引入新的重型依赖。
- 不追求第三方 API 稳定性——这是个人/小团队工具箱。

---

## 六、索引

### 决策记录

| ADR | 决策 |
|---|---|
| [0001](adr/0001-analysis-without-extension.md) | 静态分析不依赖 Windows 扩展 |
| [0002](adr/0002-facade-is-primitives-only.md) | Debugger 只做调试原语的门面 |
| [0003](adr/0003-answerability-contract.md) | 可回答性：拒绝不能伪装成答案 |
| [0004](adr/0004-teardown-ownership.md) | 清理所有权：manager 自撤销，close() 定顺序 |

### 工作项

| 阶段 | Issue |
|---|---|
| P0 | #68 |
| 安全网 | #65 #66 #67 |
| 核心收缩 | #76 #77 #78 #79 #80 #75 |
| analysis | #81 #82 #83 #84 |
| 收尾 | #85 #86 #87 #69 #70 #71 #72 #73 #74 |
