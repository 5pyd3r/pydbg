# 静态分析不依赖 Windows 扩展

**Status**: accepted (2026-11-10)

`import pydbg.analysis` 曾经被锁死在 Windows 上：它会先执行包的 `__init__.py`，而那里第一行就是 `from ._pydbg import ...`——一个 23 MB 的编译扩展。但分析层本来就只依赖纯 Python 的 `pe/`、`disasm/`（capstone）和 `exceptions`，与活进程的接触只有 `analysis/process_source.py:25` 一处函数内导入。

我们决定：`pydbg.analysis` 必须在没有扩展的环境里可 import、可测试；扩展的导入只发生在真正需要它的模块里；顶层 `__init__` 惰性化。

**Considered Options**: 拆成两个发行包（拒绝：当前只有一个使用场景，拆包只增加版本协调成本）；保持现状（拒绝：让 23 MB 的 Windows 扩展成为纯静态分析的安装前提）。

**Consequences**: 纯静态分析可以在非 Windows、未编译的环境里运行与测试；`from pydbg import Debugger` 变成惰性属性，需要清晰的导入期错误提示。反向约束同样成立：任何在 `analysis` 里直接 import `core` / `memory` 的改动都会破坏这条边界。
