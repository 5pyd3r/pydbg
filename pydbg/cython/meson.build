cython = find_program('cython', required: true)

cython_sources = [
  '_process.pyx',
  '_memory.pyx',
  '_thread.pyx',
  '_exception.pyx',
  '_bp.pyx',
]

# Cython compilation: .pyx -> .c -> .pyd
foreach src : cython_sources
  # Step 1: cythonize .pyx to .c
  c_file = custom_target(
    'cython_' + src,
    input: src,
    output: src.replace('.pyx', '.c'),
    command: [cython, '-3', '--fast-fail', '-o', '@OUTPUT@', '@INPUT@'],
    depend_files: ['_win32types.pxd'],
  )

  # Step 2: compile .c to shared module (.pyd)
  py.extension_module(
    src.replace('.pyx', ''),
    c_file,
    c_args: [] + (get_option('buildtype') == 'debug' ? ['-D_DEBUG'] : []),
    link_args: ['-ldbghelp', '-lkernel32', '-ladvapi32', '-lpsapi'],
    subdir: 'pydbg/cython',
  )
endforeach
