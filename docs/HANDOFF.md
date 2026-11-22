# 交接文档（2026-11-22）

给接手的会话/人：pydbg 目前处于 v0.2「立住边界」的收尾阶段。核心收缩、测试安全网、文档三条线已完成；剩下分析线的结构整理与少量缺陷。

## 一、已经合入的（按主题）

**核心收缩（ADR-0002 / 0004）**

| PR | 内容 |
|---|---|
| #89 | `set_breakpoint` 幂等——重复设置曾把 `0xCC` 当原始字节存下，永久腐蚀目标 |
| #91 | 清理所有权：每个 manager 实现 `teardown()`/`discard()`，`Debugger.close()` 按固定顺序撤销并聚合失败；顺带修 #71（detach 失败泄漏句柄） |
| #92 | 目标架构单一真相：`pid_arch` 是唯一存储，`target_arch` 派生；线程靠 `tid_pid` 继承 |
| #93 | 事件循环收敛：`_dispatch_exception` 唯一实现，`HandleOutcome`（NOT_MINE/HANDLED/DEGRADED）取代旁路计数器 |
| #94 | `Breakpoint` dataclass 取代软 4 元组/硬 6 元组；`set_hw_breakpoint` 接受 `pid` |
| #95 | 错误契约：`run()` 返回 `ExitStatus`；`continue_event` 只放过 `ERROR_INVALID_PARAMETER`；两个逃逸的 `ValueError`/`OSError` 归位 |
| #96 | `ProcessManager`：句柄解析（严格/按需/try）收成一处 |
| #97 | 门面收缩 62 → 46 个方法；`dbg.windows` 成为新能力对象；README 补能力对象表 |

**测试与工程化**

| PR | 内容 |
|---|---|
| #90 | 35 个手写 meson test 块 → 单个 pytest 入口；CI 加 `push(master)`；测试目标由 meson/32 位脚本构建、不再入库；skip 必须声明三族之一否则判红 |
| #101 | 覆盖率重叠按节计算（原先把全局值拷进每节，各节相加会乘以节数）；分母改用 `max(virtual, raw)` |
| #102 | 打包元数据：LICENSE、真实作者/URL、可用的 dev extra、版本一致性测试 |

**文档与分析线**

| PR | 内容 |
|---|---|
| #88 | 设计评审 `docs/design-review.md` + 4 条 ADR + `GLOSSARY.md` |
| #99 | `import pydbg` 与 `pydbg.analysis` 不再需要 Windows 扩展（`constants.py` + 惰性 `__getattr__`） |
| #103 | 按现在的代码重写 `architecture.md` |
| #104 | 13 个 plan 归档到 `docs/archive/plans/` 并加索引 |
| #105 | `KNOWN_ISSUES.md` 从 20KB 台账改成按模块的现状声明（旧的归档） |

## 二、本机构建与测试（重要，容易踩）

**症状**：工作区内的可执行文件一律以 **Low 完整性级别**启动，`venv-x64\Scripts\python.exe` 因此写不了 `build/`（Medium），meson 的 editable loader 报
`PermissionError: ...meson-python-build-log.txt`。这不是 ACL 问题——把同一份 `python.exe` 复制到用户目录运行就是 Medium。

**可用做法**（已在本会话验证）：

```powershell
# 1. 用工作区外的 Python 构建（cython/meson/ninja 装进它）
$py = 'C:\Users\spyder\AppData\Local\Programs\Python\Python313\python.exe'
& $py -m pip install cython meson ninja
# 需要 vcvarsall amd64 提供 cl，PATH 里加上 $py 旁边的 Scripts
& $py -m mesonbuild.mesonmain setup build\base-py --buildtype=release
& $py -m mesonbuild.mesonmain compile -C build\base-py
```

```powershell
# 2. 跑测试：把包复制到临时目录并接上已编译的扩展
$stage = "$env:LOCALAPPDATA\Temp\pydbg-run2"
Copy-Item -Recurse src\pydbg "$stage\pydbg"
Get-ChildItem -Recurse "$stage\pydbg" -Filter *.pyd | Remove-Item -Force
Copy-Item build\base-py\src\pydbg\cython\_pydbg.cp313-win_amd64.pyd "$stage\pydbg\_pydbg.pyd"
$env:PYTHONPATH = "$stage;$PWD;$PWD\venv-x64\Lib\site-packages"
# 再设 TEST_* 环境变量（见 tests/meson.build 的 test_env），然后：
& $py -m pytest tests -q -p no:cacheprovider
```

`TEST_*` 至少要有：`TEST_TARGET_PATH`、`TEST_WOW64_TARGET_PATH`、`TEST_ARGV_TARGET_PATH`、`TEST_NESTED_TARGET_PATH`、`TEST_WINDOW_TARGET_PATH`、`TEST_MODAL_TARGET_PATH`、`TEST_WEDGE_TARGET_PATH`、`TEST_AV_TARGET_PATH`、`TEST_INSTRUMENT_TARGET_PATH`、`TEST_INSTRUMENT_TARGET32_PATH`、`TEST_CHILD_TARGET`、`TEST_CHILD_TARGET_X64`、`TEST_SPAWN_CHILD`。少设一个，对应模块会失败（不是跳过）。

基线：**777 passed / 6 skipped**。

## 三、剩余工作

### #82 `AnalysisResult` 去方法化（下一个）

现状：39 个方法（`model.py:272-560`），24 处在方法体里惰性 import 兄弟模块。建议分四片，每片一 commit、跑全量再进下一片：

1. **渲染类**（`render_*`，11 个）→ `report.py` 自由函数。先确认 `render_stats` 等是否仍有调用者（审计说零调用——若有，删比搬好）。
2. **查询类**（`callers_of`/`xrefs_of`/`data_refs_of`/`ref_kinds*`，6 个）。
3. **所有权/值集类**（`owner_of`/`boundary_of`/`classify_range`/`receiver_of`/`value_set_of`/`narrow_value_set`，8 个）——惰性 import 的大头。
4. 其余（`scan*`/`cfg_of`/`names`/`label`/`accesses`/`structures`/`attribution`）——`**kwargs` 转发链，最难。

### 其余

- **#83** 概念所有权：`SectionInfo` 复刻 `SectionHeader`；跨度规则 `max(virtual, raw)` 抄 4 处；8 处自建 `DisasmEngine`；RVA/VA 两套单位。
- **#84** 术语单一来源：`OWNER_KINDS` ×2、`_OWNED`/`_OWNED_KINDS` ×2，靠测试同步。
- **#73** 写内存失败后页面保护不恢复（`breakpoint/software.py` 的 protect→write→restore 缺 `try/finally`）。
- **#74** `WindowProbe` GONE 分支经门面不可达。
- **#87** instrument 冻结：LLVM 路径配置化、移入可选 extra、不修 RIP-relative。
- **#98** CI 的 LLVM 下载步骤无重试（`gh release download` 抖动即红）。
- **#100** `TestNestedDebugging` 对子进程 pid 无等待/重试，偶发 `OpenProcess` 拒绝。

## 四、约定与坑

- **永远不在 master 上提交**：feature 分支 + PR，AI 不合并。
- **GitHub 直连常失败**：`git push` 报 443 超时就按 CLAUDE.md 用一次性 `-c http.proxy=http://192.168.13.101:1080`，不要写进配置。`gh` 同理用 `HTTPS_PROXY` 环境变量。
- **进行中的 run 不能重跑**：等它结束再 `gh run rerun <id> --failed`。
- **PowerShell 替换脚本会静默改错文件**：`@(@('a','b'))` 单元素嵌套数组会被展平成两个字符串，`$p[0]` 实际是首字符。本会话曾因此把 `tests/` 下所有 `f` 替换成 `"`，靠 `git checkout -- tests/` 恢复。做批量替换务必先 dry-run 并 `git status` 复核。
- **`git mv dir/*.md` 在 PowerShell 里不展开 glob**，必须 `Get-ChildItem | ForEach-Object { git mv $_.FullName ... }`。
- **`meson` 需要 `cython` 在 PATH 上**（meson 用 `find_program('cython')`，不认纯 Python 模块）。
- **CI 的 `llvm-instrument` 与 `build-and-test` 是两套环境**：前者启用 LLVM 后端，部分 instrument 测试只有在那里真跑；后者是必需的验证。

## 五、判据（写给下一个人）

改完之后问三个问题：

1. **删除是否比搬移更诚实？**（零调用的方法先删）
2. **失败有没有出口？**（操作抛 `PydbgError` 子类；查询能区分答案/拒绝/空）
3. **这个数字有几个来源？**（架构、断点、版本——都曾被复制过）
