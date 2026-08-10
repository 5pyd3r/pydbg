# LLVM Instrument 后端 — 检测预编译 LLVM 17 + libclang，构建 hook_compiler 静态库
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

# ── libclang ───────────────────────────────────────────────────
clang_cfg = get_option('libclang-config')
clang_dep = []
clang_found = false
if clang_cfg != '' and fs.exists(clang_cfg / '../lib/libclang.lib')
  clang_libdir = run_command(clang_cfg, '--libdir', check : true).stdout().strip()
  clang_includedir = run_command(clang_cfg, '--includedir', check : true).stdout().strip()
  clang_dep = declare_dependency(
    include_directories : include_directories(clang_includedir),
    link_args : ['-L' + clang_libdir, '-lclang'],
  )
  clang_found = true
else
  foreach dir : ['C:/Users/Spyder/AppData/Local/llvm-17', 'C:/Program Files/LLVM']
    if fs.exists(dir / 'lib/libclang.lib')
      clang_dep = declare_dependency(
        include_directories : include_directories(dir / 'include'),
        link_args : [dir / 'lib/libclang.lib'],
      )
      clang_found = true
      break
    endif
  endforeach
endif
if not clang_found
  error('LLVM Instrument requires libclang.lib under the prebuilt LLVM dir')
endif

llvm_dep = declare_dependency(
  include_directories : include_directories(llvm_includedir),
  link_args : llvm_libs + llvm_system + _x86_force,
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
  dependencies : [llvm_dep, clang_dep],
  cpp_args : _cpp_args,
  install : false,
)

hook_compiler_dep = declare_dependency(
  link_with : hook_compiler_lib,
  include_directories : include_directories('.'),
  dependencies : [llvm_dep, clang_dep],
)
