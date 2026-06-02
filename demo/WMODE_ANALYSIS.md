# wmode.dll 完整函数级逆向分析（运行时 dump 验证）

## 分析方法

1. pydbg PE 解析器分析 PE 结构
2. Capstone 反汇编解压桩代码（Section 1）
3. 使用 pydbg `dll_injector.py` 注入 DLL（CreateRemoteThread + LoadLibraryA）
4. 注入 32 位进程，dump 解密后的 Section 0
5. Capstone 完整反汇编 DllMain 及所有子函数

## 1. DllMain 流程 (0x10001E0A)

```
DllMain(hinstDLL, fdwReason, lpvReserved)
├── 检查 fdwReason == DLL_PROCESS_ATTACH
├── [1] 解析 API (sub_100020BA)
│   └── 通过 IAT 表 (0x10001000-0x1000104C) 解析 15 个 API
├── [2] GetModuleFileNameA(hinstDLL, buf, 0x104)
│   └── 获取 wmode.dll 自身路径
├── [3] _lopen("C:\...\wmode.ini", 0x20)
│   └── 打开配置文件（OF_READWRITE | OF_SHARE_DENY_NONE）
├── [4] _lread(handle, header_buf, 0x40)
│   └── 读取文件头 64 字节
├── [5] 验证 MZ 签名 (0x5A4D)
├── [6] _lread(handle, xmod_header, 0x12)
│   └── 读取 XMOD 头 (18 字节)
├── [7] 验证 XMOD 签名 ("XMOD" = 0x444F4D58)
├── [8] GlobalAlloc(0, plugin_size + 0x52)
│   └── 分配内存存放 XMOD 插件数据
├── [9] _lread(handle, alloc_ptr, plugin_size - 0x40)
│   └── 读取完整插件数据
├── [10] _lread(handle, footer_buf, 0x100)
│   └── 读取尾部数据
├── [11] _lclose(handle)
├── [12] 验证 XMOD 头完整性
├── [13] PRNG XOR 解密 (sub_100015A8)
│   └── 解密插件数据: key = key * 0x343FD + 0x269EC3
├── [14] 解压/验证 (sub_100011A5)
│   └── 解压插件代码
├── [15] lstrcpyA + lstrlenA — 构建 INI 路径
├── [16] GetPrivateProfileIntA("XMOD2DLL", "HijackInstall", 1, ini_path)
│   └── 检查是否启用 hijack 安装
├── [17a] 如果 HijackInstall=1: call sub_100019B3
│   └── 安装窗口化 hook（DirectDraw hook + WndProc 替换）
├── [17b] 如果 HijackInstall=0: call sub_10001A2F
│   └── 备用初始化路径
└── 返回 TRUE (popal; mov al, 1; leave; ret 0xC)
```

## 2. API 解析表 (0x10001000 — 0x1000104C)

所有 API 通过间接跳转表调用：

| 偏移 | IAT 槽 | API |
|------|--------|-----|
| 0x1000 | [0x10001004] | GetModuleFileNameA |
| 0x1004 | [0x10001008] | GetModuleHandleA |
| 0x1008 | [0x1000100C] | GetPrivateProfileIntA |
| 0x100C | [0x10001010] | GetPrivateProfileStringA |
| 0x1010 | [0x10001014] | GetProcAddress |
| 0x1014 | [0x10001018] | GlobalAlloc |
| 0x1018 | [0x1000101C] | GlobalFree |
| 0x101C | [0x10001020] | LoadLibraryA |
| 0x1020 | [0x10001024] | VirtualAlloc |
| 0x1024 | [0x10001028] | VirtualFree |
| 0x1028 | [0x1000102C] | VirtualProtect |
| 0x102C | [0x10001030] | _lclose |
| 0x1030 | [0x10001034] | _llseek |
| 0x1034 | [0x10001038] | _lopen |
| 0x1038 | [0x1000103C] | _lread |
| 0x103C | [0x10001040] | lstrcpyA |
| 0x1040 | [0x10001044] | lstrlenA |
| 0x1044 | [0x10001048] | MessageBoxA |
| 0x1048 | [0x1000104C] | GetSystemInfo |

## 3. XMOD 插件解密 (sub_100015A8)

```asm
mov  ebx, 0xA5A5A5A5          ; 初始 key
.loop:
  imul ebx, ebx, 0x343FD      ; key *= 0x343FD
  add  ebx, 0x269EC3           ; key += 0x269EC3
  xor  byte ptr [edi], bl      ; data[i] ^= low_byte(key)
  inc  edi
  loop .loop
```

这是 **线性同余生成器 (LCG)** PRNG，参数：
- multiplier = 0x343FD (213501)
- increment = 0x269EC3 (2530979)
- modulus = 2^32
- seed = 0xA5A5A5A5

## 4. 错误消息

| 地址 | 消息 | 触发条件 |
|------|------|---------|
| 0x1000187F | "GMH error!" | GetModuleHandleA 失败 |
| 0x1000188A | "GPA error!" | GetProcAddress 失败 |
| 0x10001895 | "GMFN error!" | GetModuleFileNameA 失败 |
| 0x100018A1 | "Error opening plugin data file!" | _lopen 失败 |
| 0x100018C1 | "Error reading plugin data file!" | _lread 失败 |
| 0x100018E1 | "Plugin is invalid!" | XMOD 签名/MZ 签名验证失败 |
| 0x100018F4 | "Out of memory!" | GlobalAlloc 返回 NULL |
| 0x10001903 | "Plugin is damaged!" | 解压验证失败 |
| 0x10001934 | "Unknown error!" | 未知错误 |
| 0x1000194A | "Error loading XMOD! Continue?" | MessageBoxA 确认对话框 |

## 5. 配置

INI 路径：`<StarCraft目录>\wmode.ini`
Section: `[XMOD2DLL]`
Key: `HijackInstall` (默认=1)

## 6. 关键字符串

| 地址 | 字符串 | 用途 |
|------|--------|------|
| 0x10001977 | "XeN'z XMOD2DLL adapter" | 版本标识 |
| 0x10001997 | "XMOD2DLL" | INI section 名 |
| 0x100019A0 | "HijackInstall" | INI key |
| 0x100019AE | ".ini" | 文件扩展名 |
| 0x10001A66 | "storm" | Storm.dll 引用 |
| 0x10002110 | "C:\Input\starcraft\wmode.ini" | 运行时路径 |
| 0x10002214 | "MZx" | MZ 签名验证缓冲区 |
| 0x10002254 | "XMOD" | XMOD 签名 |
| 0x1000425B | ".text" | PE 节名 |
| 0x10004283 | ".reloc" | PE 节名 |

## 7. XMOD 加载器 (sub_10001D05)

XMOD 是自定义的 PE-like 格式，加载流程：

```
sub_10001D05 (XMOD Loader)
├── 验证 XHDR 签名 (0x52444858 = "XHDR")
├── [1] sub_10001AB4 — FindModule
│   ├── GetModuleHandleA 获取模块基址
│   ├── 验证 MZ 签名 (0x5A4D)
│   ├── 验证 PE 签名 (0x4550)
│   └── 验证 PE32 magic (0x10B)
├── [2] 复制 sections 到目标地址
│   └── 按 section table 逐个 memcpy
├── [3] sub_10001BA5 — Relocation fixups
│   └── 处理 .reloc 表，修正绝对地址引用
├── [4] sub_10001BFF — Import resolution
│   ├── 遍历 import directory
│   ├── LoadLibraryA 加载 DLL
│   └── GetProcAddress 解析函数地址
├── [5] sub_10001C66 — Section protection
│   └── VirtualProtect 设置各 section 权限
├── [6] sub_100020DE — VirtualProtect 设置页面保护
└── 调用 XMOD entry point (DLL_PROCESS_ATTACH)
```

### 完整性验证 (sub_100012D0 + sub_10001312)

XMOD 加载前使用 **MD5** 验证数据完整性：

- `sub_10001312` — 标准 MD5 实现（初始化常量 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476）
- `sub_100012D0` — 计算 MD5 并与存储的哈希比对

### 加载器数据 (offset 0x3000)

XMOD 加载器配置包含 API 导入表：

| 偏移 | API 名称 |
|------|----------|
| 0x4008 | ExitProcess |
| 0x4015 | GetModuleFileNameA |
| 0x4029 | GetModuleHandleA |
| 0x403B | GetPrivateProfileIntA |
| 0x4052 | GetProcAddress |
| 0x4062 | GetSystemInfo |
| 0x4071 | GlobalAlloc |
| 0x407E | GlobalFree |
| 0x408A | LoadLibraryA |
| 0x4098 | VirtualAlloc |
| 0x40A6 | VirtualFree |
| 0x40B3 | VirtualProtect |
| 0x40C3 | _lclose |
| 0x40CC | _llseek |
| 0x40D5 | _lopen |
| 0x40DD | _lread |
| 0x40E5 | lstrcpyA |
| 0x40EF | lstrlenA |

## 8. 窗口化 Hook 安装 (sub_100019B3)

当 `HijackInstall=1` 时，安装 DirectDraw 窗口化 hook：

```
sub_100019B3 (HijackInstall)
├── sub_10001C9B — SEH 初始化
├── sub_10001AB4 — FindModule (定位目标模块)
├── sub_10001B12 — PatchMemory (修改入口指令)
│   ├── 搜索 0xE8 (CALL) 指令位置
│   └── 写入 JMP hook 跳转
└── sub_10001C92 — 恢复/清理
```

`sub_10001B12` 是核心 patch 函数：
1. `VirtualProtect` → PAGE_EXECUTE_READWRITE
2. 交换旧值/新值
3. `VirtualProtect` → 恢复原保护

## 9. 注入方法

## 10. 函数参考表

| 地址 | 名称 | 功能 |
|------|------|------|
| 0x10001000 | IAT Table | API 间接跳转表 (20 个槽位) |
| 0x10001065 | bit_count | 计算非零 DWORD 块的位长度 |
| 0x10001080 | bignum_mul | 大数乘法 (128 位) |
| 0x10001110 | bignum_cmp | 大数比较 |
| 0x10001128 | bignum_sub | 大数减法 + 右移 |
| 0x100011A5 | decompress | 解压主函数 |
| 0x100012D0 | xmod_verify | XMOD 完整性验证 (MD5) |
| 0x10001312 | md5_init | MD5 哈希初始化 + padding |
| 0x100015A8 | lcg_decrypt | LCG PRNG XOR 解密 |
| 0x1000187F | error_msgs | 错误消息字符串表 |
| 0x10001977 | version_str | "XeN'z XMOD2DLL adapter" |
| 0x100019B3 | hijack_install | 窗口化 hook 安装 |
| 0x10001A2F | alt_init | 备用初始化路径 |
| 0x10001AB4 | find_module | 查找模块并验证 PE 头 |
| 0x10001B12 | patch_mem | 内存 patch (改保护→写→恢复) |
| 0x10001B7C | reloc_fixup | 重定位修复 + 导入解析 |
| 0x10001BFF | import_resolve | 遍历 import directory 解析 |
| 0x10001C66 | section_protect | 设置 section 内存保护 |
| 0x10001C9B | seh_setup | SEH 异常处理初始化 |
| 0x10001D05 | xmod_loader | XMOD PE 加载器 |
| 0x10001E0A | DllMain | DLL 入口点 |
| 0x1000209C-0x2108 | API jumps | IAT 间接跳转桩 |
| 0x100020BA | resolve_apis | API 解析入口 |

使用 pydbg 的 `dll_injector.py` 注入 DLL，完全基于 pydbg Cython API：

```bash
# 注入到运行中的 32 位进程
python demo/dll_injector.py --pid <PID> --dll demo\injected.dll

# 创建进程挂起 → 注入 → 恢复
python demo/dll_injector.py --exe target.exe --dll demo\injected.dll
```

底层流程：
1. `open_process` 打开目标进程
2. `virtual_alloc_ex` 分配远程内存
3. `write_process_memory` 写入 DLL 路径
4. `create_remote_thread(LoadLibraryA, path)` 注入
5. `wait_for_single_object` 等待完成
6. `get_exit_code_thread` 获取 DLL 基址
