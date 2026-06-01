# Hook Framework

基于 pydbg 的 IAT Hook + Inline Hook 框架。

## 架构

```
HookManager          — 统一接口，事件循环分发
  ├── InlineHooker   — 内联 hook（修改函数入口指令）
  └── IATHooker      — IAT hook（修改导入地址表指针）
```

## 核心原理

### Inline Hook（JMP + trampoline）

```
原始函数:  [JMP rel32 → trampoline] [后续指令...]
Trampoline: [被覆盖的指令(偏移已修正)] [JMP rel32 → 原函数+N]
Hook回调:   Python函数，接收 (dbg, event, hook_info, mgr)
```

1. 读取目标地址的指令，累计 ≥ 5 字节
2. 修正相对指令偏移（CALL/JMP/Jcc 的 rel32 需要重算目标地址）
3. 在 ±2GB 范围内分配 RWX 内存，写入：修正后的指令 + JMP 回原函数
4. 覆盖目标地址：`E9 rel32`（JMP 到 trampoline）
5. 在 trampoline 入口设断点 → 触发 Python 回调
6. `call_original()`：移除断点，RIP = trampoline → 原函数正常执行

### IAT Hook

```
IAT条目:  [原始函数指针] → [JMP桩地址]
JMP桩:    [INT3]          ← 断点触发
Hook回调: Python函数
```

1. 解析目标模块 PE，找到 IAT 中目标函数的条目
2. 读取原始函数指针，保存
3. 分配 JMP 桩（含 INT3），覆盖 IAT 条目指向桩
4. 任何通过 IAT 的调用都会触发桩中的断点
5. `call_original()`：设置 RIP = 原始函数指针

## 使用

```python
from pydbg import Debugger
from hook_framework import HookManager

dbg = Debugger()
pid, tid = dbg.create_process("target.exe")

mgr = HookManager(dbg)

# Inline hook
def my_hook(dbg, event, hook_info, mgr):
    print("Hook fired!")
    mgr.call_original(event, hook_info)  # 让原函数继续运行

info = mgr.hook_inline(target_addr, my_hook)

# IAT hook
info = mgr.hook_iat("target.exe", "printf", my_hook)

# 事件循环
mgr.run()
```

## 限制

- **单次触发**：`call_original` 恢复原始字节后不再重新 hook（避免 INT3 循环）
- **x64 only**：间接 JMP 使用 14 字节（FF 25 + 8字节绝对地址）
- **静态 hook**：不支持运行时动态修改 hook 点

## pydbg 新增能力

本次未新增 Cython API，完全使用已有能力：
- `virtual_alloc_ex` / `virtual_free_ex` — 分配/释放远程内存
- `write_process_memory` / `read_process_memory` — 读写远程内存
- `virtual_protect_ex` — 修改页面保护
- `set_breakpoint` / `remove_breakpoint` — 软件断点
- `set_register` — 修改 RIP
- `DisasmEngine` — 反汇编（读取指令边界）
