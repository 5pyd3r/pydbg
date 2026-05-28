# pydbg

使用 Python 和 Cython 扩展编写的 Windows 二进制调试器。

## 安装

**标准安装：**
```bash
pip install .
```

**可编辑安装（开发模式）：**
```bash
# 先安装构建依赖
pip install meson-python>=0.15.0 cython>=3.0.0

# 可编辑安装（无构建隔离）
pip install -e . --no-build-isolation
```

## 从源码构建

需要 meson-python 和 Cython：

**使用标准构建：**
```bash
pip install meson-python cython
python -m build
```

**使用无构建隔离模式：**
```bash
pip install meson-python cython
python -m build --no-build-isolation
```

## 测试

```bash
pytest tests/
```
