project('pydbg', 'c',
  version: '0.1.0',
  meson_version: '>=0.60',
  default_options: [
    'c_std=c11',
    'buildtype=debug',
  ])

# Python dependency
py_mod = import('python')
py = py_mod.find_installation(pure: false)

subdir('src/pydbg')
subdir('tests')
