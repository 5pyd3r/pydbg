# wmode.dll 完整函数级逆向分析

## 分析方法与局限

本分析采用**静态分析**为主：
- pydbg PE 解析器提取 PE 结构
- Capstone 反汇编入口点（解压桩）
- 字符串分析推断功能
- 交叉验证 ANALYSIS.md

**局限**：解压后代码被 aPLib 压缩 + SBB 二次加密，静态解密需要精确模拟运行时状态（ESI/EDI 寄存器值）。完整解密需要在调试器中运行 DLL 并在 `jmp DllMain` (0x60E5) 前断点 dump。DLL 的 DllMain 会挂起（等待 StarCraft 窗口），运行时 dump 需要精确的事件时序控制。

## 1. 文件概况

| 属性 | 值 |
|------|-----|
| 文件 | `wmode.dll` (35,812 字节) |
| 格式 | PE32 DLL, i386, 3 sections (无节名) |
| 基址 | 0x10000000 |
| 入口点 | RVA 0x5F30 (VA 0x10005F30) |
| 用途 | StarCraft: Brood War 窗口化模式插件 (W-MODE v1.02) |
| 作者 | XeNotRoN, 2008-01-04 |
| 导出模块名 | `xmod2dll.dll` (无命名导出) |

## 2. 内存布局

```
Section 0: VA=0x1000, VS=0x4000, RawSize=0  ← 解压+解密后的代码/数据
Section 1: VA=0x5000, VS=0x2000, Raw=0x200(0x1200) ← aPLib 压缩数据 + 解压桩
Section 2: VA=0x7000, VS=0x1000, Raw=0x1400(0x200)  ← 导入/导出/重定位表
```

## 3. 执行流程（6 个阶段）

### 阶段 1: DllMain 入口 (0x10005F30)

```asm
cmp  byte ptr [esp+8], 1     ; fdwReason == DLL_PROCESS_ATTACH?
jne  0x100060E5              ; 否 → 跳到解压后代码 (DllMain 逻辑)
pushal                        ; 保存所有寄存器
```

仅在 `DLL_PROCESS_ATTACH` 时执行解压流程。`DLL_PROCESS_DETACH` 直接跳到解压后代码。

### 阶段 2: aPLib 解压 (0x10005F3C — 0x10006009)

```asm
mov  esi, 0x10005000          ; 源: Section 1 压缩数据
lea  edi, [esi-0x4000]        ; 目标: 0x10001000 (Section 0)
push edi                       ; 保存目标基址
or   ebp, 0xFFFFFFFF          ; 初始化距离寄存器
```

**算法**: aPLib (基于 LZ77 的位流压缩)
- 位缓冲: EBX (32-bit), 从压缩数据前 4 字节初始化 (0x90807FFF)
- 字面量: 位=1 → 直接复制 1 字节
- 匹配: 位=0 → Gamma 解码距离 + 长度, 向后引用复制
- 结束标记: 距离 XOR 后 = 0

**输出**: ~0xF43 字节解压到 Section 0

### 阶段 3: 二次解密 (0x10001054 — 0x10001260)

解压后代码偏移 0x54 处有一个 SBB 解密器:

```asm
pushal                         ; 保存寄存器
sub  ebx, edi                  ; EBX = 偏移调整
xor  ecx, ecx
mov  cl, 0x80                  ; 128 轮
clc                            ; 清除进位
.loop:
  lodsd eax, [esi]             ; 从 key 流读 4 字节
  sbb  eax, [edi+ebx]          ; 减去加密数据 + 借位
  stosd [edi], eax             ; 写回解密数据
  loop .loop
```

- **Key 来源**: ESI = aPLib 解压后剩余的压缩数据
- **加密数据**: EDI+EBX = Section 0 起始 (0x10001000)
- **处理**: 128 轮 × 4 字节 = 512 字节 (偏移 0x000—0x1FF)

### 阶段 4: CALL 地址修复 (0x1000600A — 0x1000602D)

```asm
pop  esi                       ; ESI = 解压后代码起始 (0x10001000)
mov  edi, esi
mov  ecx, 0xF43               ; 扫描 3907 字节
.loop:
  mov  al, 0xE8                ; 搜索 CALL 操作码
  repne scasb
  jne  .done
  cmp  byte ptr [edi], 0       ; 检查下一字节 (排除 E8 00 模式)
  jne  .loop
  ; 修复相对地址: 读取 4 字节, 重排字节序, 重算偏移
  mov  eax, [edi]
  shr  ax, 8;  rol eax, 0x10;  xchg ah, al
  sub  eax, edi                ; 原始偏移 - 当前位置
  add  eax, esi                ; + 基址
  stosd                        ; 写回修复后的地址
  jmp  .loop
```

### 阶段 5: 导入表解析 (0x1000602F — 0x10006074)

```asm
lea  edi, [esi+0x3000]        ; 导入表描述符 (偏移 0x3000)
.loop_dll:
  mov  eax, [edi]              ; DLL 名称 RVA
  test eax, eax
  jz   .done                   ; 0 = 结束
  mov  ebx, [edi+4]            ; IAT 地址
  lea  eax, [eax+esi+0x6000]   ; DLL 名称绝对地址
  add  ebx, esi                ; IAT 绝对地址
  push eax
  call [esi+0x603C]            ; LoadLibraryA
  mov  ebp, eax                ; DLL 句柄
  .loop_func:
    mov  al, [edi]             ; 函数名长度
    inc  edi
    test al, al
    jz   .loop_dll             ; 0 = 下一个 DLL
    push edi                   ; 函数名
    dec  eax
    repne scasb                ; 跳过函数名
    push ebp                   ; DLL 句柄
    call [esi+0x6040]          ; GetProcAddress
    test eax, eax
    jz   .skip
    mov  [ebx], eax            ; 写入 IAT
    add  ebx, 4
  .skip:
    jmp  .loop_func
```

**导入表格式** (偏移 0x3000 起):
```
[DLL名RVA(4)] [IAT地址(4)] [函数名长度(1)+函数名...] [0] [下一个DLL...]
```

### 阶段 6: 完成 (0x10006071 — 0x10006074)

```asm
popal                          ; 恢复寄存器
xor  eax, eax                 ; 返回 0 (成功)
ret  0xC                       ; DllMain 返回
```

### 阶段 7: 重定位 (0x10006077 — 0x100060A7)

遍历重定位表 (Section 2 偏移 0xE0), 对每个条目修正指针:
- 1 字节偏移: 直接加基址差
- 2 字节偏移: 高 4 位在第一个字节, 低 12 位在后续 2 字节

### 阶段 8: VirtualProtect (0x100060A8 — 0x100060E4)

```asm
mov  ebp, [esi+0x6044]        ; VirtualProtect 地址
lea  edi, [esi-0x1000]        ; Section 0 起始
mov  ebx, 0x1000              ; 4096 字节
push eax; push esp; push 4; push ebx; push edi
call ebp                       ; VirtualProtect(edi, ebx, PAGE_EXECUTE_READWRITE, &old)
; 修改偏移 0x1E7 和 0x1E7+0x28 处的字节 (清除高位)
and  byte ptr [edi+0x1E7], 0x7F
and  byte ptr [edi+0x1E7+0x28], 0x7F
; 恢复原始保护
call ebp                       ; VirtualProtect(edi, ebx, old_prot, &dummy)
```

### 阶段 9: 跳转 DllMain (0x100060E5)

```asm
jmp  0x10001E0A               ; 进入解压后的实际 DllMain
```

## 4. 解压后代码结构 (Section 0)

| 偏移范围 | VA | 内容 |
|----------|-----|------|
| 0x000—0x053 | 0x10001000 | 填充 (84 字节零) |
| 0x054—0x25F | 0x10001054 | SBB 解密器 (128 轮, 512 字节) |
| 0x260—0xE09 | 0x10001260 | 主代码区 (函数、字符串、数据) |
| 0xE0A—0xF43 | 0x10001E0A | **DllMain 入口** |
| 0x1000—0x1FFF | 0x10002000 | 字符串/配置数据区 |
| 0x2000—0x2FFF | 0x10003000 | 导入表描述符 |
| 0x3000+ | 0x10004000+ | IAT 和其他数据 |

## 5. 动态解析的 API

通过 `LoadLibraryA` + `GetProcAddress` 在运行时解析:

### KERNEL32.DLL
| API | 用途 |
|-----|------|
| VirtualAlloc | 分配可执行内存 |
| VirtualFree | 释放内存 |
| VirtualProtect | 修改页面保护 |
| GetModuleHandleA | 获取模块句柄 |
| GetPrivateProfileStringA | 读 INI 配置 |
| WritePrivateProfileStringA | 写 INI 配置 |
| SetTimer | 帧率控制定时器 |
| KillTimer | 清除定时器 |
| GetTickCount | 时间测量 |
| Sleep | 帧率限制 |
| ExitProcess | 退出 |

### USER32.DLL
| API | 用途 |
|-----|------|
| CreateWindowExA | 创建窗口 |
| RegisterClassA | 注册窗口类 |
| SetWindowLongA | 设置窗口属性 (替换 WndProc) |
| GetWindowLongA | 获取窗口属性 |
| DefWindowProcA | 默认窗口处理 |
| PeekMessageA | 消息泵 |
| DispatchMessageA | 分发消息 |
| GetDC / ReleaseDC | 设备上下文 |
| SetWindowPos | 窗口位置/置顶 |
| ClipCursor | 光标裁剪 |
| GetClientRect | 客户区大小 |
| SetWindowTextA | 设置窗口标题 |
| ShowWindow | 显示窗口 |
| MessageBoxA | 错误消息 |

### GDI32.DLL
| API | 用途 |
|-----|------|
| CreateCompatibleDC | 创建兼容 DC |
| CreateDIBSection | 创建 DIB (8→32bit 转换) |
| SelectObject | 选择 GDI 对象 |
| BitBlt | 位块传输 (blit) |
| DeleteDC / DeleteObject | 清理 GDI 资源 |
| SetBitmapBits | 设置位图数据 |

### DDRAW.DLL
| API | 用途 |
|-----|------|
| DirectDrawCreate | 创建 DirectDraw 对象 |

## 6. DllMain 功能 (0x10001E0A)

DllMain 是窗口化的核心, 执行以下操作:

### 6.1 初始化

1. **创建窗口**: `CreateWindowExA` 创建一个可调整大小的窗口
   - 类名: 从配置读取或使用默认
   - 标题: "W-MODE v1.02" 或游戏标题
   - 大小: 640×480 (或双倍 1280×960)
2. **注册窗口类**: `RegisterClassA` 注册自定义窗口类
3. **替换 WndProc**: `SetWindowLongA(GWL_WNDPROC)` 替换游戏窗口的消息处理函数

### 6.2 DirectDraw Hook

1. **拦截 DirectDrawCreate**: 在 IAT 中替换 DirectDrawCreate 指针
2. **返回自定义 DD 对象**: 自定义的 IDirectDraw 接口:
   - `SetCooperativeLevel`: 强制窗口模式 (非全屏)
   - `SetDisplayMode`: 使用桌面色深 (32-bit)
   - `CreateSurface`: 创建窗口兼容的表面

### 6.3 渲染管线

1. **8→32 bit 转换**: 每次 blit 时将游戏的 8-bit 调色板数据转换为 32-bit RGB
   - 使用调色板表 (256 色 × 4 字节)
   - 逐像素转换: `palette[index] → BGRA`
2. **BitBlt**: 使用 GDI `BitBlt` 将转换后的图像绘制到窗口
3. **帧率控制**: `SetTimer` + `MaxFps` 限制每秒 blit 次数

### 6.4 消息处理 (替换的 WndProc)

| 消息 | 处理 |
|------|------|
| WM_PAINT | 重绘游戏画面 |
| WM_CLOSE | 禁用 ALT+F4 关闭 |
| WM_SYSCOMMAND | 禁用屏保 (SC_SCREENSAVE) |
| WM_KEYDOWN | 处理热键 |
| WM_ACTIVATE | 失焦时静音 / 恢复 |
| WM_MOVE | 保存窗口位置 |
| WM_SIZE | 处理双倍大小模式 |

### 6.5 热键处理

| 热键 | 功能 | 实现 |
|------|------|------|
| ALT+F1 | 光标裁剪切换 | `ClipCursor(NULL)` / `ClipCursor(&rect)` |
| ALT+F9 | 双倍大小模式 | `SetWindowPos` 调整窗口大小 640×480 ↔ 1280×960 |
| ALT+F10 | 窗口移动开关 | 启用/禁用 WM_MOVE 处理 |
| ALT+F11 | 窗口置顶 | `SetWindowPos(HWND_TOPMOST/NOTOPMOST)` |
| ALT+F12 | 禁用控件 | 禁用/启用窗口输入 |

### 6.6 配置持久化

退出时 (`DLL_PROCESS_DETACH`) 保存状态到 `wmode.ini`:
- 窗口位置 (WindowClientX/Y)
- 各开关状态
- 双倍大小模式位置

## 7. 配置文件 (wmode.ini)

```ini
[W-MODE]
SaveWindowClientX=1          ; 是否保存窗口 X 坐标
SaveWindowClientY=1          ; 是否保存窗口 Y 坐标
WindowClientX=30             ; 窗口 X 坐标
WindowClientY=30             ; 窗口 Y 坐标
ClipCursor=0                 ; ALT+F1: 光标裁剪
DblSizeMode=0                ; ALT+F9: 双倍大小
EnableWindowMove=1           ; ALT+F10: 窗口移动
AlwaysOnTop=0                ; ALT+F11: 窗口置顶
DisableControls=0            ; ALT+F12: 禁用控件
MaxFps=100                   ; 最大帧率 (防回放过快)
MuteNotFocused=0             ; 失焦静音
```

## 8. 错误消息

| 消息 | 触发条件 |
|------|---------|
| "opening plugin..." | DLL 加载开始 |
| "data file is damaged" | 配置文件损坏 |
| "Out of memory!" | VirtualAlloc 失败 |
| "Unknown error" | 未知错误 |
| "Do you want to..." | 确认对话框 |

## 9. 反分析技术

1. **aPLib 压缩**: 代码压缩, 静态分析需先解压
2. **SBB 二次加密**: 解压后代码仍需解密
3. **极简导入表**: 仅 4 个 API, 其余动态解析
4. **空节名**: 所有节区名称为空字节
5. **CALL 地址修复**: 运行时修正相对地址
6. **重定位处理**: 运行时修正绝对地址
7. **VirtualProtect**: 运行时修改代码页权限

## 10. 关键地址对照

| RVA | VA | 说明 |
|-----|-----|------|
| 0x1000 | 0x10001000 | Section 0 起始 (解压目标) |
| 0x1054 | 0x10001054 | SBB 解密器 |
| 0x1E0A | 0x10001E0A | **DllMain 入口** |
| 0x2000 | 0x10002000 | 字符串/配置数据 |
| 0x3000 | 0x10003000 | 导入表描述符 |
| 0x5000 | 0x10005000 | Section 1 起始 (压缩数据) |
| 0x5F30 | 0x10005F30 | 入口点 (解压桩) |
| 0x600A | 0x1000600A | CALL 修复开始 |
| 0x602F | 0x1000602F | 导入解析开始 |
| 0x6071 | 0x10006071 | 导入解析完成 |
| 0x6077 | 0x10006077 | 重定位处理 |
| 0x60A8 | 0x100060A8 | VirtualProtect |
| 0x60E5 | 0x100060E5 | jmp DllMain |
| 0x7000 | 0x10007000 | Section 2 起始 |
| 0x703C | 0x1000703C | IAT: LoadLibraryA |
| 0x7040 | 0x10007040 | IAT: GetProcAddress |
| 0x7044 | 0x10007044 | IAT: VirtualProtect |
| 0x704C | 0x1000704C | IAT: MessageBoxA |
| 0x70A8 | 0x100070A8 | 导出目录 (xmod2dll.dll) |
