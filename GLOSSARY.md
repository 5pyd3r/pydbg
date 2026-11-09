# pydbg

Windows 二进制分析工具箱：一个宿主进程（恒为 64 位）同时驱动动态调试与静态分析，
两个引擎共享同一套 PE 与反汇编概念。

## 调试（动态）

**Target**:
被调试的那个进程。它运行在 Host 里，位数可以与 Host 不同（32 位 target 走 WOW64）。
_Avoid_: 被调试程序、client、inferior

**Host**:
运行 pydbg 解释器与扩展的进程，恒为 64 位。
_Avoid_: 调试器进程、driver

**Target arch**:
Target 的位数（32 或 64）。同一个 pid 只有一个值，线程不单独拥有它。
_Avoid_: bitness；`machine` 是传给扩展的参数编码，不是领域概念

**Debug event**:
Win32 调试端口上报的一次事件（CREATE_PROCESS / EXCEPTION / LOAD_DLL / EXIT_PROCESS …）。
_Avoid_: message、notification

**Continue**:
让一个因 debug event 暂停的 target 继续执行。
_Avoid_: resume（resume 专指恢复被挂起的线程）

**Software breakpoint（INT3）**:
向目标写入 0xCC 的断点。移除时必须写回**最初**读到的字节，而不是移除前那一刻读到的字节。
_Avoid_: 内存断点

**Hardware breakpoint（DR slot）**:
用调试寄存器 Dr0–3 实现的断点，数量受槽位限制。
_Avoid_: 硬件监视点

**Degraded**:
断点已命中，但事后恢复（重装 INT3 或回退 IP）失败了。它是「带缺陷的成功」，必须被报告。
_Avoid_: failed（failed 是根本没命中）

**Trampoline**:
为目标中被覆盖指令准备的副本，加跳回原处的指令。
_Avoid_: stub（stub 指跳向 payload 的那段）

**Teardown**:
把一个能力在 target 里留下的一切（字节、寄存器、句柄、符号）撤销回安装前。每个 manager 自己负责自己那份。
_Avoid_: cleanup、restore、detach（detach 是 Win32 操作；teardown 是它所欠的前提）

**Capability object**:
已经能独立构造、独立测试的能力对象（窗口探测、符号、hook、单步追踪、反汇编/汇编）。它不挂在 Debugger 门面上。
_Avoid_: manager、service

## 分析（静态）

**Image**:
一份 PE 的内容，可能来自磁盘，也可能来自活进程的内存映射。两者用同一个模型表示。
_Avoid_: 文件、二进制（那是实现来源，不是概念）

**Seed**:
一个已知或推断出的函数起点（入口点、导出、call 目标、thunk）。
_Avoid_: root、entry（entry 只是 seed 的一种）

**Linear scan**:
从某个地址起逐条解码，遇到不可解码字节或跳转就记录并重同步的扫描过程。
_Avoid_: disassembly（disassembly 是解码结果，scan 是过程）

**Resync**:
扫描在不可解码字节之后重新找到指令边界。
_Avoid_: recovery

**Gap / unproven run**:
无法证明已被解码的地址区间。它必须与已解码区间一起报告，不能单独出现。
_Avoid_: hole、missing

**Coverage with overlap**:
解码覆盖率必须与重叠字节数成对出现——单独报覆盖率会在解码跑偏时反而读高。
_Avoid_: coverage（单独使用即为违规）

**Function start**:
被判定为函数入口的地址。一个 seed 不一定成为 function start（可能被判为 thunk 或数据）。
_Avoid_: 函数头

**Owner / Boundary / Receiver**:
owner 是区间归属的判定结果（函数、thunk、数据、未知）；boundary 是判定所依据的证据类型；receiver 是调用指令的接收者（寄存器或内存基址）。
_Avoid_: 归属、所有者

**Value set**:
某个槽位上可能取值的集合，带 decided / undecided 标记。undecided 的值集不能当答案使用。
_Avoid_: 常量、类型

**Xref**:
从一个指令位置到另一个地址的引用，带 kind。
_Avoid_: 交叉引用

## 横切规则

**Answerability（可回答性）**:
每个查询型 API 的返回都必须能区分「答案」「带原因的拒绝」「空答案」。空集合不等于「没有」。
_Avoid_: 容错、健壮性

**Refusal**:
明确声明「这次没查成、原因是什么」的返回值。它不能与答案共用同一个形状。
_Avoid_: 错误（错误是抛出的，拒绝是返回的）

**Silent failure**:
目标或结果已经被改变、调用方却毫无察觉的状态。它必须被转成可询问的返回值或异常。
_Avoid_: 隐患、边缘情况
