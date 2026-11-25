# 已知限制（现状）

按模块分节，每节写**现在**的状态和最后核对日期。这里不记变更日志、不记
已修问题——那些在 git 历史与 GitHub issues 里。

历史版本（20KB 的旧台账）已归档到
[docs/archive/KNOWN_ISSUES-2026-11-22.md](archive/KNOWN_ISSUES-2026-11-22.md)。
它把「已修」与「仍存在」混在一起，且声称所有 skip 已清除（实际尚有），
因此不再维护。

## 插桩（instrument）

- 特性自 v0.2 **冻结**：不新增插桩功能，不修 x64 RIP-relative。
- x64 目标若被覆盖的首个 ≥5B 序列含 RIP-relative 指令，trampoline 不做重定位。
- 旧 `instrument/templates.py` 的 trampoline 把被覆盖指令**原样复制**：前缀里出现
  `[rip+disp]` 时，指令搬到 trampoline 后 `disp` 仍按原地址解释，目标被静默寻址到错误位置
  （`_read_min_5_bytes` 也不拒绝这种前缀）。Phase 3c 的 `instrument/bbl.py` 用自己的
  `relocate_prefix` + 机器码 stub，不经过这个 trampoline；该缺陷不在 3c 范围内修复。
- C 子集只支持 `int`/`void`；指针等类型静默映射为 `i32`。
- `&&` / `||` 不保留短路求值。
- 多线程安全由调用方负责（需自行挂起其他线程）。
- 后端为可选构建：`-Denable-llvm-instrument=true`，`llvm-config` 由
  `-Dllvm-config=<path>` 指定或在 PATH 上查找；Python 依赖在 extra
  `instrument` 中，核心安装不链接 LLVM。未启用时相关测试声明为
  `optional dependency:` 并跳过。

_核对：2026-11-25_

## 调试核心

- `set_hw_breakpoint` 的 8 字节校验按目标进程架构；跨架构子进程需显式传 `pid`。

_核对：2026-11-22_

## 静态分析

- 覆盖率按节报告，各节重叠之和等于 `stats.overlap_bytes`（#69 已修，此处仅记录口径）。
- 无法证明已解码的区间以 gap / unproven run 报告；它们不是错误，是拒绝。

_核对：2026-11-22_

## 追踪（trace）

- v1 格式新增 `INSTR`（6）；`MEM_READ` 仍未产生：硬件数据断点没有读/写方向信息，
  本阶段拒绝猜，读观察留给 Phase 3c 的插桩路径。
- `InstructionTracer` 是单线程窗口，离开模块即停；TF 在异常交付时被清掉，因此每一步都重设，
  不能设一次。
- `MemoryWatch` 只观察写；4 个调试寄存器槽与 `FunctionProbe` 共享；必须在正常停止点 arm
  （初始 loader 停止点写入会被下一次 continue 丢弃）；watch 跨多次 `run()`，不自动 disarm。
- `FunctionProbe` 是硬件执行断点探针，不是 detour/LLVM：不写目标字节，但无返回值、单线程、
  与 `MemoryWatch` 共享 4 个槽位。

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

_核对：2026-11-22_

## 未完成的工作

不在本文件里跟踪。见 GitHub issues（open 状态）。
