# Cython 扩展模块构建

# 生成合并的扩展模块
py.extension_module('_pydbg',
  '_pydbg.pyx',
  dependencies: [
    py.dependency(),
    declare_dependency(link_args: ['-lkernel32', '-luser32', '-ldbghelp'])
  ],
  install: true,
  subdir: 'pydbg',
)
