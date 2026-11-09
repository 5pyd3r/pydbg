# 清理所有权：manager 自撤销，close() 定顺序

**Status**: accepted (2026-11-10)

`detach()` 只关句柄（`core/debugger.py:299-319`）：INT3、DR 槽、IAT/inline hook、trampoline、dbghelp 符号全部留在目标里；`terminate_process()` 完全不做清理；`remove_all_breakpoints()` 要调用方自己先调。结果是 `detach()` 之后目标可能带着被改过的代码页继续运行。

我们决定：每个 manager 实现自己的 `teardown()`；`Debugger.close()` 按固定顺序调用——hook → instrument → 硬件断点 → 软件断点 → 符号 → 进程句柄；`detach()` / `terminate_process()` 变成 `close()` 的特例；补上 `__enter__` / `__exit__`。

**Considered Options**: `DebugSession` 持 undo 栈、安装时注册回滚（拒绝：它把顺序依赖藏进注册顺序里，而顺序恰恰是这件事唯一难的部分）。

**Consequences**: 新增 manager 必须同时实现并测试 teardown，否则 `close()` 会静默漏掉它——需要一条「注册与撤销成对」的机制性检查，而不是靠人记得。
