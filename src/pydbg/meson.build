# 定义 Python 包安装路径
pkg_pydir = py.get_install_dir() / 'pydbg'

# 安装 Python 模块（排除构建文件）
install_subdir('.',
  install_dir: pkg_pydir,
  exclude_files: ['meson.build'],
  exclude_directories: ['cython/'],
)

# 构建 Cython 扩展
subdir('cython')
