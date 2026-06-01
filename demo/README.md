# DLL Injection Demo

使用 pydbg 实现的 DLL 注入工具，基于经典的 `CreateRemoteThread + LoadLibraryA` 技术。

## 两种注入场景

### 场景 1：注入运行中的进程

```
python dll_injector.py --pid <PID> --dll <path>
```

通过 PID 打开目标进程，在其地址空间中分配内存、写入 DLL 路径、创建远程线程调用 LoadLibraryA。

### 场景 2：挂起创建进程 → 注入 → 恢复

```
python dll_injector.py --exe <path> --dll <path>
```

以 `CREATE_SUSPENDED` 标志创建进程（主线程未执行），注入 DLL（DllMain 在注入时执行），然后恢复主线程。

## 测试 DLL

`injected.c` 是一个最小化测试 DLL，加载时在 `%TEMP%` 写入标记文件 `%TEMP%\pydbg_inject_<PID>.txt`。

构建需要 Visual Studio Build Tools：

```bat
demo\build_dll.bat
```

> **注意**：Git for Windows 自带的 `link.exe`（Unix 硬链接工具）会覆盖 MSVC 的 `link.exe`，构建脚本使用 `lld-link` 规避此问题。

## pydbg 新增 API

本次为支持 DLL 注入，在 Cython 层新增了以下函数：

| 函数 | 说明 |
|------|------|
| `create_process_suspended(path)` | 以 `CREATE_SUSPENDED` 创建进程（无调试控制） |
| `open_process(pid, access)` | 通过 PID 打开进程句柄 |
| `get_exit_code_thread(h_thread)` | 获取线程退出码（远程线程返回值 = LoadLibrary 结果） |

## 注入原理

```
1. get_module_handle("kernel32.dll")     → h_kernel32
2. get_proc_address(h_kernel32, "LoadLibraryA") → fn_addr
3. virtual_alloc_ex(h_proc, size)        → remote_buf
4. write_process_memory(h_proc, remote_buf, dll_path)
5. create_remote_thread(h_proc, fn_addr, remote_buf) → h_thread
6. wait_for_single_object(h_thread)      → 等待 LoadLibrary 完成
7. get_exit_code_thread(h_thread)        → DLL 基址（0 = 失败）
8. virtual_free_ex(h_proc, remote_buf)   → 清理
```
