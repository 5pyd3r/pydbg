# LLVM Instrument 后端 — 静态链接预编译 LLVM 22 + clang 组件库，构建 hook_compiler 静态库
# 不再依赖 libclang.dll（clang_to_ir 使用 clang C++ API，链接 clang 静态组件库）。
fs = import('fs')

llvm_config = ''
llvm_cfg = get_option('llvm-config')
if llvm_cfg != ''
  llvm_config = find_program(llvm_cfg, native : true)
else
  llvm_config = find_program(
    'llvm-config', 'llvm-config-22', 'llvm-config-18', 'llvm-config-17',
    required : false)
endif

if not llvm_config.found()
  # ── Fallback: 预编译 LLVM 搜索路径 ──────────────────────────
  llvm_search_dirs = [
    'C:/Users/Spyder/AppData/Local/llvm-22',
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
    error('LLVM Instrument requires llvm-config. Install prebuilt LLVM 22 or set -Dllvm-config=/path/to/llvm-config')
  endif
endif

llvm_includedir = run_command(llvm_config, '--includedir', check : true).stdout().strip()
llvm_libdir     = run_command(llvm_config, '--libdir',     check : true).stdout().strip()
llvm_cxxflags   = run_command(llvm_config, '--cxxflags',   check : true).stdout().strip().split()

llvm_components = ['core',
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
# 仅 clangDriver↔clangFrontend 存在真实循环（getDriverOptTable ↔
# parseMRecipOption/GetResourcesPath），对这两个库用 /WHOLEARCHIVE 强制纳入
# 全部目标文件；其余组件按需链接（MSVC 只在符号被引用时才拉入对应 .obj），
# 并按依赖序排在后面，尽量缩小最终 .pyd 体积。
# 不包含 clangInterpreter/clangStaticAnalyzer*/clangCodeGen 等重型库——pydbg
# 只走 runToolOnCodeWithArgs（前端解析 + AST 遍历），不需要 JIT/代码生成，
# 引入它们只会拖进 ORC/LLVMCodeGen 等整条依赖链。
_clang_wholearchive = []
foreach l : ['clangDriver', 'clangFrontend']
  _clang_wholearchive += '/WHOLEARCHIVE:' + (llvm_libdir / (l + '.lib'))
endforeach

_clang_libs = []
foreach l : ['clangTooling', 'clangSerialization', 'clangParse', 'clangSema',
             'clangAnalysis', 'clangAST', 'clangLex', 'clangBasic', 'clangEdit',
             'clangRewrite', 'clangRewriteFrontend', 'clangSupport',
             'clangTransformer', 'clangASTMatchers', 'clangAPINotes',
             'clangAnalysisLifetimeSafety', 'clangDependencyScanning',
             'clangToolingCore', 'clangFormat', 'clangToolingRefactoring',
             'clangToolingASTDiff', 'clangOptions', 'clangCrossTU',
             'clangDirectoryWatcher', 'clangToolingInclusions',
             'clangToolingInclusionsStdlib', 'clangIndex']
  _clang_libs += llvm_libdir / (l + '.lib')
endforeach

# clang 静态库额外依赖的 LLVM 组件（llvm-config --libs 的组件列表不含这些）：
#   LLVMOption             clangDriver 的 llvm::opt
#   LLVMWindowsDriver       clangDriver 的 MSVC 工具链探测
#   LLVMFrontendOpenMP      clangSema 的 llvm::omp 命名
#   LLVMFrontendAtomic      新：OpenMPIRBuilder 的 AtomicInfo::EmitAtomic*Libcall
#   LLVMFrontendDirective   新：llvm::directive::FindName
#   LLVMFrontendOffloading  新：llvm::offloading::emitOffloadingEntry
#   LLVMPlugins             新：clangFrontend 的 llvm::PassPlugin::Load
# 以及 Windows version.lib（GetFileVersionInfo*）。
_llvm_clang_extras = []
foreach l : ['LLVMOption', 'LLVMWindowsDriver', 'LLVMFrontendOpenMP',
             'LLVMFrontendAtomic', 'LLVMFrontendDirective', 'LLVMFrontendOffloading',
             'LLVMPlugins', 'LLVMObjectYAML']
  _llvm_clang_extras += llvm_libdir / (l + '.lib')
endforeach
_llvm_clang_extras += 'version.lib'

# /WHOLEARCHIVE 的 clang 全量目标会引用更多 LLVM 组件；llvm-config 的拓扑
# 顺序在 clang 之前处理，晚到的引用需再扫一遍，因此把 llvm_libs 重复一次放
# 在链接行末尾（MSVC 静态库第二次传递即可解析）。
llvm_dep = declare_dependency(
  include_directories : include_directories(llvm_includedir),
  link_args : llvm_libs + llvm_system + _llvm_clang_extras + _x86_force + llvm_libs,
)

clang_dep = declare_dependency(
  include_directories : include_directories(llvm_includedir),
  link_args : _clang_wholearchive + _clang_libs,
)

# MSVC + LLVM 22 头文件兼容参数（spike 已验证）
_cpp_args = llvm_cxxflags + [
  '/std:c++17', '/EHsc',
  '/DNOMINMAX', '/D_CRT_SECURE_NO_WARNINGS',
  '/D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH',
  '/wd4146', '/wd4624', '/wd4275',
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
