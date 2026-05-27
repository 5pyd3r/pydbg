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
# Root-level files: configure_file(copy: true) works fine
foreach f : ['__init__.py', 'exceptions.py', 'pe.py']
  configure_file(input: f, output: f, copy: true)
endforeach

# Subdirectory files: copy via install_subdir + manual copy at configure time
run_command(
  'python3', '-c', '\n'.join([
    'import shutil, os',
    'src = r"' + meson.current_source_dir() + '"',
    'dst = r"' + meson.current_build_dir() + '"',
    'for d in ["core","memory","thread","breakpoint","module"]:',
    '    os.makedirs(os.path.join(dst, d), exist_ok=True)',
    'for f in [',
    '    "core/__init__.py","core/session.py","core/event.py","core/debugger.py",',
    '    "memory/__init__.py","memory/manager.py",',
    '    "thread/__init__.py","thread/manager.py",',
    '    "breakpoint/__init__.py","breakpoint/software.py","breakpoint/hardware.py",',
    '    "module/__init__.py","module/resolver.py",',
    ']:',
    '    shutil.copy2(os.path.join(src, f), os.path.join(dst, f))',
  ]),
  check: true,
)

subdir('cython')
