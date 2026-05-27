# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

pydbg is a Windows Win32 debugging library providing a high-level Python API over Cython Win32 wrappers. Public API: `from pydbg import Debugger, DebugEvent, ...`.

## Build & Test (Windows only)

```bash
# Lint
flake8 src/ tests/ --max-line-length=120

# Build
meson setup build --buildtype=release
meson compile -C build

# Test (meson handles PYTHONPATH via test_env in tests/meson.build)
meson test -C build --print-errorlogs
```

[Cython](https://cython.org/) must be installed. Build outputs `.pyd` extensions to `build/src/pydbg/cython/`.

## Architecture (post-Phase-1 refactoring)

```
Debugger (core/debugger.py) — facade, lifecycle + event loop
  ├── _session: DebugSession          — pure state dataclass (core/session.py)
  ├── memory: MemoryManager           — read/write/query/protect (memory/manager.py)
  ├── thread: ThreadManager           — context/suspend/resume/step (thread/manager.py)
  ├── brk_sw: SoftwareBreakpointManager — int3 breakpoints (breakpoint/software.py)
  ├── brk_hw: HardwareBreakpointManager — debug register breakpoints (breakpoint/hardware.py)
  └── modules: ModuleResolver         — enum modules, resolve filenames (module/resolver.py)
```

Public API unchanged. Debugger methods delegate to managers. Managers receive `DebugSession` in constructor and reference `self._s`.

Cython wrappers: `src/pydbg/cython/_process.pyx`, `_memory.pyx`, `_thread.pyx`, `_exception.pyx`, `_bp.pyx`.

## Test State

- `memory`, `process`, `thread`, `breakpoint`, `pe`, `debugger` test suites
- 11 tests skipped (pre-existing bugs): PE parser section/export/import parsing, `ContinueDebugEvent` error 87 on CI. See `docs/KNOWN_ISSUES.md`.
- Tests access `dbg._session.process_handle` etc. instead of old `dbg._process_handle`.

## CI

- Windows runner only (`windows-latest`), Python 3.13
- Trigger: `pull_request` to `master`/`main`
- Lint → Build → Test

## Development Workflow

1. Branch from `master` (`git checkout -b <branch-name>`)
2. Develop, lint locally (`flake8 src/ tests/ --max-line-length=120`)
3. **NEVER push directly to master.** Push branch, open PR to `master`
4. CI must pass before merge
5. `master` is protected (requires PR + status checks)

## WeChat Communication Rule

**All questions, results, and notifications must be sent through WeChat.** Never assume the user sees terminal output.
Primary developer's WeChat user_id: `o9cq809NAV1dcxqCc69ESmXaDto8@im.wechat`

## WeChat Background Tasks

WeChat bridge daemon runs at `/tmp/wechat-bridge-*.sock`. After every response, start a background listener:

```bash
python3 /home/ubuntu/.claude/skills/wechat/scripts/socket_client.py wait
```

Check daemon status: `python3 skills/wechat/scripts/socket_client.py status`. Send messages: `socket_client.py send '{"user_id": "...", "text": "..."}'`.

## Docs

- `docs/superpowers/specs/` — design specs
- `docs/superpowers/plans/` — implementation plans
- `docs/KNOWN_ISSUES.md` — pre-existing bugs tracked for future resolution
