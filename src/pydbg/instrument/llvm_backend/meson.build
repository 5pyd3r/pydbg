# LLVM Instrument 后端 — 静态链接预编译 LLVM 17 + clang 组件库，构建 hook_compiler 静态库
# 不再依赖 libclang.dll（clang_to_ir 使用 clang C++ API，链接 clang 静态组件库）。
fs = import('fs')

llvm_config = ''
llvm_cfg = get_option('llvm-config')
if llvm_cfg != ''
  llvm_config = find_program(llvm_cfg, native : true)
else
  llvm_config = find_program(
    'llvm-config', 'llvm-config-18', 'llvm-config-17',
    required : false)
endif

if not llvm_config.found()
  # ── Fallback: 预编译 LLVM 搜索路径 ──────────────────────────
  llvm_search_dirs = [
    'C:/Users/Spyder/AppData/Local/llvm-17',
    'C:/Program Files/LLVM',
  ]
  llvm_use_prebuilt = false
  foreach dir : llvm_search_dirs
    if fs.exists(dir / 'bin/llvm-config.exe')
      llvm_config = find_program(dir / 'bin/llvm-config.exe', native : true)
      llvm_use_prebuilt = true
      message('LLVM Instrument: using prebuilt LLVM at ' + dir)
      break
    endif
  endforeach
  if not llvm_use_prebuilt
    error('LLVM Instrument requires llvm-config. Install prebuilt LLVM 17 or set -Dllvm-config=/path/to/llvm-config')
  endif
endif

llvm_includedir = run_command(llvm_config, '--includedir', check : true).stdout().strip()
llvm_libdir     = run_command(llvm_config, '--libdir',     check : true).stdout().strip()
llvm_cxxflags   = run_command(llvm_config, '--cxxflags',   check : true).stdout().strip().split()

llvm_components = ['core', 'executionengine', 'mcjit',
                   'native', 'nativecodegen', 'transformutils',
                   'x86', 'x86codegen', 'x86info', 'x86asmparser',
                   'x86desc', 'mc', 'object']
llvm_libs = run_command(llvm_config, '--libs',
  llvm_components, check : true).stdout().strip().split()
llvm_system = run_command(llvm_config, '--system-libs',
  check : true).stdout().strip().split()

# 防止 /OPT:REF 剥离 X86 目标符号
_x86_force = ['/INCLUDE:LLVMInitializeX86TargetInfo',
              '/INCLUDE:LLVMInitializeX86Target',
              '/INCLUDE:LLVMInitializeX86TargetMC',
              '/INCLUDE:LLVMInitializeX86AsmPrinter',
              '/INCLUDE:LLVMInitializeX86AsmParser']

# ── clang 静态组件库（替代 libclang.lib import lib）─────────────
# runToolOnCode 依赖链：Tooling→Frontend→Serialization/Driver→Parse→Sema→
# Analysis→AST→Lex→Basic，外加 Edit/Rewrite/RewriteFrontend/Support/
# Transformer，以及 clangASTMatchers（clangAnalysis 的 UnsafeBufferUsage
# 引用 MatchFinder）。
_clang_libs = []
foreach l : ['clangTooling', 'clangFrontend', 'clangSerialization', 'clangDriver',
             'clangParse', 'clangSema', 'clangAnalysis', 'clangAST', 'clangLex',
             'clangBasic', 'clangEdit', 'clangRewrite', 'clangRewriteFrontend',
             'clangSupport', 'clangTransformer', 'clangASTMatchers']
  _clang_libs += llvm_libdir / (l + '.lib')
endforeach

# clang 静态库额外依赖的 LLVM 组件（llvm-config --libs 的组件列表不含这些）：
#   LLVMOption           clangDriver 的 llvm::opt
#   LLVMWindowsDriver     clangDriver 的 MSVC 工具链探测
#   LLVMFrontendOpenMP    clangSema 的 llvm::omp 命名
# 以及 Windows version.lib（GetFileVersionInfo*）。
_llvm_clang_extras = []
foreach l : ['LLVMOption', 'LLVMWindowsDriver', 'LLVMFrontendOpenMP']
  _llvm_clang_extras += llvm_libdir / (l + '.lib')
endforeach
_llvm_clang_extras += 'version.lib'

llvm_dep = declare_dependency(
  include_directories : include_directories(llvm_includedir),
  link_args : llvm_libs + llvm_system + _llvm_clang_extras + _x86_force,
)

clang_dep = declare_dependency(
  include_directories : include_directories(llvm_includedir),
  link_args : _clang_libs,
)

# MSVC + LLVM 17 头文件兼容参数（spike 已验证）
_cpp_args = llvm_cxxflags + [
  '/std:c++17', '/EHsc',
  '/DNOMINMAX', '/D_CRT_SECURE_NO_WARNINGS',
  '/D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH',
  '/wd4146', '/wd4624',
]

hook_compiler_lib = static_library('hook_compiler',
  'hook_compiler.cpp',
  'clang_to_ir.cpp',
  'target_codegen.cpp',
  dependencies : [llvm_dep, clang_dep],
  cpp_args : _cpp_args,
  install : false,
)

hook_compiler_dep = declare_dependency(
  link_with : hook_compiler_lib,
  include_directories : include_directories('.'),
  dependencies : [llvm_dep, clang_dep],
)
