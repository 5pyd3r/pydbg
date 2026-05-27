# Install pure Python files
py.install_sources(
  '__init__.py',
  'exceptions.py',
  'debugger.py',
  'pe.py',
  subdir: 'pydbg',
)

# Copy pure Python files to build dir so build/pydbg/ is a complete package
foreach f : ['__init__.py', 'exceptions.py', 'debugger.py', 'pe.py']
  configure_file(
    input: f,
    output: f,
    copy: true,
  )
endforeach

subdir('cython')
