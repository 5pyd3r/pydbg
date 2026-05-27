# pydbg — Python Win32 Debugger Architecture

## Overview

pydbg is a modular, extensible Windows binary debugger framework built on Python +
Cython. It provides a procedural high-level API over raw Win32 debugging primitives.

Python 3.13+ / Windows x64 / C11 / Meson build system

## Current Architecture

```
pydbg/
├── __init__.py       — Public API surface (Debugger, exceptions, constants)
├── debugger.py       — Debugger + DebugEvent (high-level facade, 602 loc)
├── exceptions.py     — Exception hierarchy (PydbgError → Process/Mem/Thread/Breakpoint)
├── pe.py             — PE32/PE32+ parser (pure Python, no deps)
└── cython/           — Win32 C bindings
    ├── _win32types.pxd  — Type declarations (289 loc, windows.h + psapi.h + tlhelp32.h)
    ├── _process.pyx     — Process: create/attach/wait/continue/detach/terminate
    ├── _memory.pyx      — Memory: read/write/query/protect/modules
    ├── _thread.pyx      — Thread: context/suspend/resume/enumerate
    ├── _exception.pyx   — Exception codes + parsing (21 NTSTATUS codes)
    └── _bp.pyx          — Hardware breakpoints (Dr0-3/Dr7 x64)
```

### Layer Diagram

```
┌──────────────────────────┐
│  tests/                  │  ← unittest
├──────────────────────────┤
│  debugger.py (Debugger)  │  ← High-level procedural API
├──────────────────────────┤
│  cython/*.pyx            │  ← Cython Win32 wrappers
├──────────────────────────┤
│  Win32 API (kernel32,    │  ← Native OS layer
│  psapi, tlhelp32)        │
└──────────────────────────┘
```

## Target Modules — Three-Phase Evolution

### Phase 1: Module Split (refactoring, no new deps)

Decompose the 602-line `debugger.py` into single-responsibility modules.

```
pydbg/
├── core/
│   ├── debugger.py    — Lifecycle: create_process, attach, detach, terminate
│   ├── event.py       — DebugEvent + wait_for_event + continue_event
│   └── session.py     — DebugSession: holds handles, breakpoint table, state
├── memory/
│   └── manager.py     — read/write/query/protect memory
├── thread/
│   └── manager.py     — enumerate/open/suspend/resume/context
├── breakpoint/
│   ├── software.py    — int3 (0xCC) software breakpoints
│   └── hardware.py    — Dr0-3 debug register breakpoints
├── module/
│   └── resolver.py    — module enumeration, base address lookup
├── exception/
│   └── handler.py     — exception classification, access violation decoding
├── pe.py              — (unchanged)
├── exceptions.py      — (unchanged)
└── cython/            — (unchanged)
```

**Design rules:**
- Each module receives a `DebugSession` reference; no global state
- Cython layer stays thin — business logic in pure Python
- All modules independently testable via mocked Cython layer

### Phase 2: Feature Expansion (2 new deps)

```
pydbg/
├── symbol/            — [NEW] Symbol resolution
│   ├── resolver.py    — symbol name → address, address → symbol+offset
│   └── pdb.py         — PDB (MSVC) file parser (uses construct)
├── disasm/            — [NEW] Disassembly
│   └── engine.py      — capstone wrapper, x86/x64 mode detection
├── trace/             — [NEW] Execution tracing
│   ├── step.py        — single-step tracing with callback
│   └── calltree.py    — call/ret tracking to build call tree
├── hook/              — [NEW] API hooking
│   ├── iat.py         — IAT (Import Address Table) hook
│   └── inline.py      — inline detour (5-byte JMP trampoline)
├── dump/              — [NEW] Crash dump analysis
│   ├── minidump.py    — Minidump file parser
│   └── stackwalk.py   — x64 stack unwind (RtlLookupFunctionEntry + unwind codes)
└── patch/             — [NEW] Runtime patching
    └── assembler.py   — assembly string → machine code (uses capstone asm)
```

### Phase 3: Advanced Features (2-3 new deps)

```
pydbg/
├── script/            — [NEW] Scripting engine
│   ├── engine.py      — Python sandbox for debug scripts
│   └── commands.py    — built-in debugger commands (bp, dump, step, etc.)
├── remote/            — [NEW] Remote debugging
│   ├── server.py      — debug server (sockets)
│   ├── client.py      — debug client
│   └── protocol.py    — message protocol definition
├── plugin/            — [NEW] Plugin system
│   ├── loader.py      — plugin discovery (entry points / directory scan)
│   └── hooks.py       — hook points: on_event, on_bp, on_module_load, etc.
├── ui/                — [NEW] User interfaces
│   ├── console.py     — interactive CLI (prompt_toolkit)
│   └── web.py         — web dashboard (flask, optional)
└── util/              — [NEW] Utilities
    ├── log.py         — structured logging
    ├── hexdump.py     — hex dump formatting
    └── pattern.py     — pattern generation/search (cyclic pattern)
```

## External Dependencies

| Library | Version | Phase | Purpose |
|---------|---------|-------|---------|
| capstone | ≥5.0 | Phase 2 | x86/x64 disassembly + assembly |
| construct | ≥2.10 | Phase 2 | PDB binary format parsing |
| prompt_toolkit | ≥3.0 | Phase 3 | Interactive CLI (syntax highlight, completion) |
| flask | ≥3.0 | Phase 3 | Web dashboard (optional) |

**Non-dependencies (by design):**
- pefile — own `pe.py` handles PE parsing
- pykd — kernel debugging, out of scope
- winappdbg — own framework
- distorm3 — capstone is more actively maintained
- pdbparse — unmaintained; `construct` is more flexible

## Design Principles

1. **Single responsibility.** Each module has one job. `debugger.py` today is 602 lines doing 6 things — split target is ~100 lines per module.

2. **Dependency direction.** Dependencies flow one way: `core ← feature ← ui/plugin`. No circular imports.

3. **Thin Cython layer.** Cython `.pyx` files are dumb wrappers around Win32 APIs. All logic (breakpoint tracking, event dispatch, exception classification) lives in pure Python.

4. **Testable in isolation.** Every module accepts its dependencies via constructor/Session; mock the Cython layer for unit tests. Integration tests require Windows + compiled extensions.

5. **Module boundaries = file boundaries.** One concept, one file. No `utils.py` dumping ground.

6. **No hard coupling to the debug loop.** The `run()` event loop is one consumer. All modules also work in single-step mode where the caller controls the loop.

## Build System

Meson with Cython:
- `meson setup build` — configure
- `meson compile -C build` — build Cython extensions
- `meson test -C build` — run test suite

CI: GitHub Actions, `windows-latest` runner, Python 3.13.
