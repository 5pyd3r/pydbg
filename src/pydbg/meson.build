# 定义 Python 包安装路径
pkg_pydir = py.get_install_dir() / 'pydbg'

# 安装 Python 模块（排除构建文件）
install_subdir('.',
  install_dir: pkg_pydir,
  exclude_files: ['meson.build'],
  exclude_directories: ['cython/', 'instrument/llvm_backend/'],
)

# Cython include 路径：必须在声明任何 build target 之前调用
# （instrument/llvm_backend 先声明 static_library），因此从 cython/meson.build 提升至此。
add_project_arguments('-I', meson.current_source_dir() / 'cython', language : 'cython')

# LLVM Instrument 后端（可选）
if get_option('enable-llvm-instrument')
  subdir('instrument/llvm_backend')
endif

# 构建 Cython 扩展
subdir('cython')
