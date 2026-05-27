# Install pure Python files
py.install_sources(
  '__init__.py',
  'exceptions.py',
  'pe.py',
  'core/__init__.py',
  'core/session.py',
  'core/event.py',
  'core/debugger.py',
  'memory/__init__.py',
  'memory/manager.py',
  'thread/__init__.py',
  'thread/manager.py',
  'breakpoint/__init__.py',
  'breakpoint/software.py',
  'breakpoint/hardware.py',
  'module/__init__.py',
  'module/resolver.py',
  subdir: 'pydbg',
)

# Copy pure Python files to build dir so build/pydbg/ is a complete package
py_sources = [
  '__init__.py', 'exceptions.py', 'pe.py',
  'core/__init__.py', 'core/session.py', 'core/event.py', 'core/debugger.py',
  'memory/__init__.py', 'memory/manager.py',
  'thread/__init__.py', 'thread/manager.py',
  'breakpoint/__init__.py', 'breakpoint/software.py', 'breakpoint/hardware.py',
  'module/__init__.py', 'module/resolver.py',
]
foreach f : py_sources
  configure_file(
    input: f,
    output: f,
    copy: true,
  )
endforeach

subdir('cython')
