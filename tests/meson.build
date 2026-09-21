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
  'pe_directories',
  py,
  args: ['-m', 'unittest', 'tests.test_pe_directories'],
  env: test_env,
  workdir: meson.project_build_root(),
)

test(
  'resource',
  py,
  args: ['-m', 'unittest', 'tests.test_resource'],
  env: test_env,
  workdir: meson.project_build_root(),
)

test(
  'analysis',
  py,
  args: ['-m', 'unittest', 'tests.test_analysis'],
  env: test_env,
  workdir: meson.project_build_root(),
)

test(
  'seeds',
  py,
  args: ['-m', 'unittest', 'tests.test_seeds'],
  env: test_env,
  workdir: meson.project_build_root(),
)

test(
  'analysis_runtime',
  py,
  args: ['-m', 'unittest', 'tests.test_analysis_runtime'],
  env: test_env,
  workdir: meson.project_build_root(),
)

# Analyses a real system DLL end to end, which does not fit the 30s default.
test(
  'analysis_indirect',
  py,
  args: ['-m', 'unittest', 'tests.test_analysis_indirect'],
  env: test_env,
  workdir: meson.project_build_root(),
  timeout: 180,
)

# Analyses and attributes a real system DLL end to end.
test(
  'analysis_attribution',
  py,
  args: ['-m', 'unittest', 'tests.test_analysis_attribution'],
  env: test_env,
  workdir: meson.project_build_root(),
  timeout: 180,
)

test(
  'analysis_names',
  py,
  args: ['-m', 'unittest', 'tests.test_analysis_names'],
  env: test_env,
  workdir: meson.project_build_root(),
)

test(
  'disasm_branch_flags',
  py,
  args: ['-m', 'unittest', 'tests.test_disasm_branch_flags'],
  env: test_env,
  workdir: meson.project_build_root(),
)

test(
  'analysis_backlog',
  py,
  args: ['-m', 'unittest', 'tests.test_analysis_backlog'],
  env: test_env,
  workdir: meson.project_build_root(),
)

test(
  'analysis_scan',
  py,
  args: ['-m', 'unittest', 'tests.test_analysis_scan'],
  env: test_env,
  workdir: meson.project_build_root(),
)

test(
  'analysis_owners',
  py,
  args: ['-m', 'unittest', 'tests.test_analysis_owners'],
  env: test_env,
  workdir: meson.project_build_root(),
)

# Analyses a real system DLL end to end, which does not fit the 30s default.
test(
  'analysis_data_refs',
  py,
  args: ['-m', 'unittest', 'tests.test_analysis_data_refs'],
  env: test_env,
  workdir: meson.project_build_root(),
  timeout: 180,
)

# Traces a real system DLL, which does not fit the 30s default.
test(
  'analysis_access',
  py,
  args: ['-m', 'unittest', 'tests.test_analysis_access'],
  env: test_env,
  workdir: meson.project_build_root(),
  timeout: 180,
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

test(
  'dump',
  py,
  args: ['-m', 'unittest', 'tests.test_dump'],
  env: test_env,
  workdir: meson.project_build_root(),
)

test(
  'comprehensive',
  py,
  args: ['-m', 'unittest', 'tests.test_comprehensive'],
  env: test_env,
  workdir: meson.project_build_root(),
)

test(
  'child_process',
  py,
  args: ['-m', 'unittest', 'tests.test_child_process'],
  env: test_env,
  workdir: meson.project_build_root(),
)

test(
  'module',
  py,
  args: ['-m', 'unittest', 'tests.test_module'],
  env: test_env,
  workdir: meson.project_build_root(),
)

test(
  'symbol',
  py,
  args: ['-m', 'unittest', 'tests.test_symbol'],
  env: test_env,
  workdir: meson.project_build_root(),
)

test(
  'wow64',
  py,
  args: ['-m', 'unittest', 'tests.test_wow64'],
  env: test_env,
  workdir: meson.project_build_root(),
)

test(
  'instrument',
  py,
  args: ['-m', 'unittest', 'tests.test_instrument'],
  env: test_env,
  workdir: meson.project_build_root(),
)

# Spawns debugged targets and waits on a real message box to come up, which
# does not fit the 30s default.
test(
  'window_probe',
  py,
  args: ['-m', 'unittest', 'tests.test_window_probe'],
  env: test_env,
  workdir: meson.project_build_root(),
  timeout: 180,
)

# Spawns debugged targets, a nested parent/child pair and a real child of the
# test process, and waits on target sleeps; does not fit the 30s default.
test(
  'probe_visibility',
  py,
  args: ['-m', 'unittest', 'tests.test_probe_visibility'],
  env: test_env,
  workdir: meson.project_build_root(),
  timeout: 300,
)

# These spawn several debugged processes and wait on real 1s target sleeps,
# which does not fit meson's 30s default.
test(
  'dynamic_gaps',
  py,
  args: ['-m', 'unittest', 'tests.test_dynamic_gaps'],
  env: test_env,
  workdir: meson.project_build_root(),
  timeout: 180,
)
