# pydbg Debugger 補齊功能設計

## 概述

修復 debugger.py 中的命名不一致問題，補齊缺失的高層 API，完善測試用例。

## 目標

- 修復 `MemoryError` / `MemError` 命名不一致問題
- 補齊 `Debugger` 類中缺失的方法（terminate_process, get_exit_code, protect_memory）
- 完善現有測試用例
- 添加新的測試用例覆蓋 DebugEvent 和新增 API

## 非目標

- 重構錯誤處理機制
- 添加新的 Cython 底層功能
- 修改現有架構

## 修改清單

### 1. 命名修復

**文件：`pydbg/debugger.py`**

- 保持 `MemError` 導入，移除別名
- 將所有 `PydbgMemoryError` 替換為 `MemError`（第 163、181、198、212、229 行）

**文件：`pydbg/__init__.py`**

- 將 `__all__` 中的 `'MemoryError'` 改為 `'MemError'`

### 2. 補齊高層 API

**文件：`pydbg/debugger.py`** - 在 `Debugger` 類中添加：

#### terminate_process(exit_code=1)
- 終止被調試的進程
- 參數：exit_code - 進程退出碼
- 異常：ProcessError - 無進程句柄或調用失敗
- 依賴：`_process.terminate_process()`

#### get_exit_code()
- 獲取進程退出碼
- 返回：整數退出碼
- 異常：ProcessError - 無進程句柄或調用失敗
- 依賴：`_process.get_exit_code()`

#### protect_memory(addr, size, protect)
- 修改內存區域保護屬性
- 參數：addr - 地址, size - 大小, protect - 新保護值
- 返回：舊保護值
- 異常：MemError - 調用失敗
- 依賴：`_memory.virtual_protect_ex()`

### 3. 完善測試用例

**文件：`tests/test_memory.py`**

修復 `test_write_and_read_back`：
- 添加尋找可寫內存區域的邏輯
- 添加寫入和讀取的斷言
- 驗證讀回的數據與寫入一致

**文件：`tests/test_debugger.py`**（新建）

#### TestDebugEvent 類
- test_debug_event_attributes：驗證 DebugEvent 正確解析事件字典
- test_debug_event_repr：驗證 __repr__ 格式

#### TestDebuggerAPICompleteness 類
- test_terminate_process：測試 terminate_process 方法
- test_get_exit_code_running：測試獲取運行中進程的退出碼

#### TestExceptionHelpers 類
- test_exception_code_to_str：測試異常代碼轉字符串

## 數據流

```
用戶代碼
    ↓
Debugger (高層 API)
    ↓
Cython 模塊 (_process, _memory, _thread, _bp, _exception)
    ↓
Win32 API
```

## 錯誤處理

保持現有模式：
- Cython 層：捕獲 Win32 API 返回值，失敗時 raise OSError
- Python 層：捕獲 OSError，轉換為對應的自定義異常

## 測試策略

1. 單元測試：測試每個新增方法的正常和異常路徑
2. 集成測試：驗證完整調試流程
3. 依賴：需要編譯後的 Cython 模塊

## 驗證標準

- 所有現有測試繼續通過
- 新增測試全部通過
- 命名一致，無 ImportError
