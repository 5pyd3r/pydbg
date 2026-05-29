# Build test target
test_target = executable(
  'simple_target',
  'target/simple_target.c',
)

# Common environment: PYTHONPATH includes project root (for tests), source (pure Python), and build (compiled extensions)
test_env = environment()
test_env.prepend('PYTHONPATH',
  meson.project_source_root()
)
test_env.prepend('PYTHONPATH',
  meson.project_source_root() / 'src'
)
test_env.prepend('PYTHONPATH',
  meson.project_build_root() / 'src'
)
test_env.set('TEST_TARGET_PATH', test_target.full_path())

# Test runner: use Python unittest via meson test
test(
  'process',
  py,
  args: ['-m', 'unittest', 'tests.test_process'],
  env: test_env,
  workdir: meson.project_build_root(),
)

test(
  'memory',
  py,
  args: ['-m', 'unittest', 'tests.test_memory'],
  env: test_env,
  workdir: meson.project_build_root(),
)

test(
  'thread',
  py,
  args: ['-m', 'unittest', 'tests.test_thread'],
  env: test_env,
  workdir: meson.project_build_root(),
)

test(
  'breakpoint',
  py,
  args: ['-m', 'unittest', 'tests.test_breakpoint'],
  env: test_env,
  workdir: meson.project_build_root(),
)

test(
  'pe',
  py,
  args: ['-m', 'unittest', 'tests.test_pe'],
  env: test_env,
  workdir: meson.project_build_root(),
)

test(
  'debugger',
  py,
  args: ['-m', 'unittest', 'tests.test_debugger'],
  env: test_env,
  workdir: meson.project_build_root(),
)

test(
  'disasm',
  py,
  args: ['-m', 'unittest', 'tests.test_disasm'],
  env: test_env,
  workdir: meson.project_build_root(),
)

test(
  'patch',
  py,
  args: ['-m', 'unittest', 'tests.test_patch'],
  env: test_env,
  workdir: meson.project_build_root(),
)

test(
  'hook',
  py,
  args: ['-m', 'unittest', 'tests.test_hook'],
  env: test_env,
  workdir: meson.project_build_root(),
)

test(
  'trace',
  py,
  args: ['-m', 'unittest', 'tests.test_trace'],
  env: test_env,
  workdir: meson.project_build_root(),
)
