# Build test target
test_target = executable(
  'simple_target',
  'target/simple_target.c',
)

# Common environment: PYTHONPATH includes both / (pure Python) and build pydbg/cython (compiled extensions)
test_env = environment()
test_env.prepend('PYTHONPATH',
  meson.project_source_root()
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
