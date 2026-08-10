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

# LLVM Instrument backend（可选 — 仅 enable-llvm-instrument=true）
if get_option('enable-llvm-instrument')
  py.extension_module('_llvm_backend',
    '_llvm_backend.pyx',
    dependencies: [
      py.dependency(),
      hook_compiler_dep,  # from ../instrument/llvm_backend/meson.build
    ],
    override_options: ['cython_language=cpp'],
    install: true,
    subdir: 'pydbg',
  )
endif
