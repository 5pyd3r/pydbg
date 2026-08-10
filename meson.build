project('pydbg', 'c', 'cpp', 'cython',
  version: '0.1.0',
  meson_version: '>=0.60',
  default_options: [
    'c_std=c11',
    'cpp_std=c++17',
    'buildtype=release',
    'b_ndebug=if-release',
    'cython_language=c']
)

# Python dependency
py_mod = import('python')
py = py_mod.find_installation(pure: false)

# LLVM instrumentation — optional feature
if get_option('enable-llvm-instrument')
  message('LLVM Instrument: ENABLED')
else
  message('LLVM Instrument: DISABLED (set -Denable-llvm-instrument=true)')
endif

subdir('src/pydbg')
subdir('tests')
