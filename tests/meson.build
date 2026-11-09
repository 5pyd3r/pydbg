# Build test target
test_target = executable(
  'simple_target',
  'target/simple_target.c',
)

# 插桩测试目标
instrument_target = executable(
  'instrument_target',
  'target/instrument_target.c',
)

# 记录自身 argv 的测试目标（用于 create_process(cmdline=...) 验证）
argv_target = executable(
  'argv_target',
  'target/argv_target.c',
)

# 嵌套调试测试目标：一个会派出子进程的父进程（F19）。用 attach() 挂上去之后，
# 子进程不会产生 CREATE_PROCESS 事件，但它的内存仍须可读。
nested_target = executable(
  'nested_parent',
  'target/nested_parent.c',
)

# Window probes (F20). Three targets that own an identical real window and
# differ only in what they do next: pump, block on a modal dialog, or stop
# pumping. All three are needed — the whole point is that they must NOT be
# classified the same way.
window_target = executable(
  'window_target',
  'target/window_target.c',
)

modal_target = executable(
  'modal_target',
  'target/modal_target.c',
)

wedge_target = executable(
  'wedge_target',
  'target/wedge_target.c',
)

# Faults on purpose: the only way to test that a real access violation reaches
# Python with its ExceptionInformation, instead of a dict built by hand.
av_target = executable(
  'av_target',
  'target/av_target.c',
)

# Child-process target. Built here as native x64 and used for two different
# things: the debuggee of the child-debugging tests, and the *64-bit child* that
# a WOW64 parent spawns (test_wow64). Its 32-bit counterpart and the WOW64
# parent need the x86 toolchain, so scripts/build-target32.ps1 builds those —
# the same split as simple_target32.exe. Both used to sit in the tree as
# committed .exe files that no build rule could reproduce.
child_target = executable(
  'child_target',
  'target/child_target.c',
)

# Common environment: PYTHONPATH includes project root (for tests).
# The editable install (pip install -e .) handles pydbg package discovery,
# including the compiled Cython extension at the correct import path.
test_env = environment()
test_env.prepend('PYTHONPATH',
  meson.project_source_root()
)
test_env.set('TEST_TARGET_PATH', test_target.full_path())
test_env.set('TEST_WOW64_TARGET_PATH',
  meson.project_source_root() / 'tests' / 'target' / 'simple_target32.exe')
test_env.set('TEST_INSTRUMENT_TARGET_PATH', instrument_target.full_path())
test_env.set('TEST_INSTRUMENT_TARGET32_PATH',
  meson.project_source_root() / 'tests' / 'target' / 'instrument_target32.exe')
test_env.set('TEST_ARGV_TARGET_PATH', argv_target.full_path())
test_env.set('TEST_NESTED_TARGET_PATH', nested_target.full_path())
test_env.set('TEST_WINDOW_TARGET_PATH', window_target.full_path())
test_env.set('TEST_MODAL_TARGET_PATH', modal_target.full_path())
test_env.set('TEST_WEDGE_TARGET_PATH', wedge_target.full_path())
test_env.set('TEST_AV_TARGET_PATH', av_target.full_path())
test_env.set('TEST_CHILD_TARGET',
  meson.project_source_root() / 'tests' / 'target' / 'child_target32.exe')
test_env.set('TEST_CHILD_TARGET_X64', child_target.full_path())
test_env.set('TEST_SPAWN_CHILD',
  meson.project_source_root() / 'tests' / 'target' / 'spawn_child.exe')

# One meson test for the whole suite. pytest discovers tests/test_*.py by name,
# so a new test file is picked up without being registered here. The previous
# 35 hand-written blocks each named one module, which meant a new module stayed
# invisible to CI until someone remembered to add a block: the file existed,
# CI was green, and it never ran.
#
# -rs prints the skip summary, so a suite that got green by skipping says which
# skips did it. --no-header and -p no:cacheprovider keep the run quiet and stop
# pytest writing .pytest_cache into the source tree.
test(
  'pytest',
  py,
  args: [
    '-m', 'pytest',
    meson.project_source_root() / 'tests',
    '-q', '-rs', '--no-header',
    '-p', 'no:cacheprovider',
  ],
  env: test_env,
  workdir: meson.project_build_root(),
  timeout: 1800,
)
