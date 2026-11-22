# 已知限制（现状）

按模块分节，每节写**现在**的状态和最后核对日期。这里不记变更日志、不记
已修问题——那些在 git 历史与 GitHub issues 里。

历史版本（20KB 的旧台账）已归档到
[docs/archive/KNOWN_ISSUES-2026-11-22.md](archive/KNOWN_ISSUES-2026-11-22.md)。
它把「已修」与「仍存在」混在一起，且声称所有 skip 已清除（实际尚有），
因此不再维护。

## 插桩（instrument）

- x64 目标若被覆盖的首个 ≥5B 序列含 RIP-relative 指令，trampoline 不做重定位。
- C 子集只支持 `int`/`void`；指针等类型静默映射为 `i32`。
- `&&` / `||` 不保留短路求值。
- 多线程安全由调用方负责（需自行挂起其他线程）。
- 后端为可选构建（`-Denable-llvm-instrument=true`），未启用时相关测试声明为
  `optional dependency:` 并跳过。

_核对：2026-11-22_

## 调试核心

- `set_hw_breakpoint` 的 8 字节校验按目标进程架构；跨架构子进程需显式传 `pid`。
- 写内存失败时页面保护可能已改（#73）。
- `WindowProbe` 的 GONE 分支经门面不可达（#74）。

_核对：2026-11-22_

## 静态分析

- 覆盖率按节报告，各节重叠之和等于 `stats.overlap_bytes`（#69 已修，此处仅记录口径）。
- 无法证明已解码的区间以 gap / unproven run 报告；它们不是错误，是拒绝。

_核对：2026-11-22_

## 平台与打包

- 宿主恒为 x64；32 位通过 WOW64 调试。
- `requires-python >= 3.10`（PEP 604、`dataclass(slots=True)`）；CI 只测 3.13。
- 版本在 `pyproject.toml`、`meson.build`、`__init__.__version__` 三处，由
  `tests/test_packaging.py` 强制一致。

_核对：2026-11-22_

## 测试与 CI

- 套件通过单个 pytest 入口运行；新 `tests/test_*.py` 自动被发现。
- skip 必须声明三族之一（`optional dependency:` / `environment:` /
  `target not built:`），否则会话判红。
- LLVM 预编译包下载步骤无重试，网络抖动会让 `llvm-instrument` 变红（#98）。
- `TestNestedDebugging` 对子进程 pid 无等待/重试，偶发失败（#100）。

_核对：2026-11-22_

## 未完成的工作

不在本文件里跟踪。见 GitHub issues（#73 #74 #82 #83 #84 #87 #98 #100）。
