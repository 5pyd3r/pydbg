# Trace Module Design

## Goal

Add execution tracing support (`trace/`) providing single-step tracing and call tree
construction. Uses existing disasm module for instruction analysis. No new external
dependencies.

## Scope

Three files:

- `trace/__init__.py` — package exports
- `trace/step.py` — `StepTracer`: single-step execution with TF flag
- `trace/calltree.py` — `CallTree`: call/ret tracking to build call graph

## Architecture

```
src/pydbg/trace/
├── __init__.py       — exports StepTracer, CallTree, CallNode
├── step.py           — StepTracer (TF flag management)
└── calltree.py       — CallTree (call/ret graph builder)
```

### Dependency Direction

```
Debugger ──uses──> trace/step.py ──uses──> thread (TF flag)
User callback ──uses──> trace/calltree.py ──uses──> disasm
```

External driver pattern: user controls the debug event loop, calls `step_tracer.step()` to
advance one instruction. StepTracer is stateless — it just manipulates the TF flag and helps
with event identification.

## step.py — StepTracer

```python
class StepTracer:
    """Single-step execution manager."""

    def __init__(self, session):
        self._s = session

    def step(self, h_thread):
        """Set TF flag and continue. Next event will be SINGLE_STEP."""
        # Set TF (0x100) in eflags register
        self._s.thread_manager.get_context(...)
        # Set eflags |= 0x100

    @staticmethod
    def is_step_event(event):
        """Check if DebugEvent is a single-step exception."""
        return (event.type == 'EXCEPTION' and
                event.raw.get('exception_code') == 0x80000004)

    def continue_step(self, h_thread):
        """Clear TF, continue past the step."""
```

**Usage pattern:**
```python
def my_callback(event):
    if StepTracer.is_step_event(event):
        # examine state, decide next action
        tracer.step(h_thread)  # continue stepping
    ...

dbg.run(my_callback)
```

## calltree.py — CallTree

```python
@dataclass
class CallNode:
    addr: int           # address of call instruction
    target: int         # address of called function
    depth: int          # nesting depth
    children: list[CallNode]
    ret_addr: int | None  # return address (set on ret)

class CallTree:
    """Call/ret tracking graph builder."""

    def __init__(self):
        self.root = CallNode(addr=0, target=0, depth=0, children=[], ret_addr=None)
        self._stack = [self.root]
        self._engine = None  # lazy DisasmEngine

    def on_call(self, addr, target):
        """Record a call instruction. Returns the new CallNode."""
        node = CallNode(addr=addr, target=target,
                        depth=len(self._stack), children=[], ret_addr=None)
        self._stack[-1].children.append(node)
        self._stack.append(node)
        return node

    def on_ret(self, addr):
        """Record a return instruction. Pops the stack."""
        if len(self._stack) > 1:
            node = self._stack.pop()
            node.ret_addr = addr
            return node
        return None

    def current_depth(self):
        return len(self._stack) - 1

    def is_call_insn(self, insn):
        """Check if Instruction is a call (using disasm)."""
        return insn.is_call

    def is_ret_insn(self, insn):
        """Check if Instruction is a return (using disasm)."""
        return insn.is_ret
```

## Integration with Debugger

StepTracer receives DebugSession in constructor. Debugger exposes:

```python
class Debugger:
    def __init__(self):
        ...
        self.step_tracer = StepTracer(self._session)

    def step_trace(self, h_thread):
        """Convenience: single step the given thread."""
        return self.step_tracer.step(h_thread)
```

CallTree is standalone — no Debugger integration needed. User creates and manages it
in their callback.

## Public API (pydbg/__init__.py additions)

```python
from .trace.step import StepTracer
from .trace.calltree import CallTree, CallNode
# __all__: + "StepTracer", "CallTree", "CallNode"
```

## Error Handling

- `StepTracer.step()` raises `ThreadError` if get/set context fails
- `CallTree.on_call()` / `on_ret()` are defensive — never raise
- `is_call_insn()` / `is_ret_insn()` use disasm booleans — no error path

## Tests

- `tests/test_trace.py`
- Test StepTracer.is_step_event() with mock event dicts
- Test CallTree: call/ret push/pop, depth tracking, tree structure
- Test CallNode dataclass
- Test with hardcoded x64 disasm (call/ret instructions)

## Non-goals

- Branch tracing / code coverage
- Instruction counting or profiling
- Automatic loop detection in calltree
- Multi-thread tracing
