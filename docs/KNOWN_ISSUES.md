# 已知限制（现状）

按模块分节，每节写**现在**的状态和最后核对日期。这里不记变更日志、不记
已修问题——那些在 git 历史与 GitHub issues 里。

历史版本（20KB 的旧台账）已归档到
[docs/archive/KNOWN_ISSUES-2026-11-22.md](archive/KNOWN_ISSUES-2026-11-22.md)。
它把「已修」与「仍存在」混在一起，且声称所有 skip 已清除（实际尚有），
因此不再维护。

## 插桩（instrument）

- **冻结已于 2026-11-28 解除**（用户决定）。解除的范围是 32 位目标上的 BBL 插桩
  （`docs/analysis-coverage.md` §12.1/§12.5）；本节其余现状不因解冻而顺带扩张。
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

_核对：2026-11-28_

## 注入（inject）

- **WOW64 目标上的 APC 受 Windows 限制**：`QueueUserAPC` 跨位数不被支持（MS 文档：地址会不正确、
  应用会崩溃）。实测 64 位宿主向 WOW64 线程投递时走 native dispatcher——`ret` 或 64 位编码能跑，
  但 32 位专属编码（如 `A3 moffs32`）会被当成 64 位 moffs 解释并崩溃；把 `kernel32!Sleep` 当 APC
  也会崩。
  因此 `pydbg.inject.queue_apc` 只校验并下发 32 位地址；**能作为 APC 执行的函数体必须与两种位数都
  兼容**（例如 `B8 imm32` + `C7 00 imm32`）。要执行 32 位专属代码，需在目标内注入 stub 由 32 位
  上下文自己调用 `QueueUserAPC`——不在当前范围（见 `docs/analysis-coverage.md` §13.2）。
  注入 DLL 与 shellcode 不受此限制。

_核对：2026-11-28_

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
