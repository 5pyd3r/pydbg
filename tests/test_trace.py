import unittest

from pydbg.trace.step import StepTracer, EXCEPTION_SINGLE_STEP
from pydbg.trace.calltree import CallTree, CallNode

try:
    from pydbg import _pydbg  # noqa: F401

    _has_cython = True
except ImportError:
    _has_cython = False


class TestStepTracer(unittest.TestCase):

    def test_is_step_event_true(self):
        from pydbg.core.event import DebugEvent
        event = DebugEvent({
            'pid': 1, 'tid': 2,
            'event_name': 'EXCEPTION',
            'exception_code': EXCEPTION_SINGLE_STEP,
            'exception_address': 0x1000,
            'first_chance': 1,
            'exception_params': [],
        })
        self.assertTrue(StepTracer.is_step_event(event))

    def test_is_step_event_false_wrong_type(self):
        from pydbg.core.event import DebugEvent
        event = DebugEvent({
            'pid': 1, 'tid': 2,
            'event_name': 'CREATE_PROCESS',
        })
        self.assertFalse(StepTracer.is_step_event(event))

    def test_is_step_event_false_wrong_code(self):
        from pydbg.core.event import DebugEvent
        event = DebugEvent({
            'pid': 1, 'tid': 2,
            'event_name': 'EXCEPTION',
            'exception_code': 0x80000003,  # breakpoint, not single step
            'exception_address': 0x1000,
            'first_chance': 1,
            'exception_params': [],
        })
        self.assertFalse(StepTracer.is_step_event(event))


class TestCallNode(unittest.TestCase):

    def test_dataclass_fields(self):
        node = CallNode(addr=0x1000, target=0x2000, depth=1)
        self.assertEqual(node.addr, 0x1000)
        self.assertEqual(node.target, 0x2000)
        self.assertEqual(node.depth, 1)
        self.assertEqual(node.children, [])
        self.assertIsNone(node.ret_addr)

    def test_children_default(self):
        node = CallNode(addr=0, target=0, depth=0)
        self.assertEqual(node.children, [])


class TestCallTree(unittest.TestCase):

    def test_init(self):
        tree = CallTree()
        self.assertEqual(tree.current_depth(), 0)
        self.assertIsNotNone(tree.root)

    def test_on_call_increases_depth(self):
        tree = CallTree()
        tree.on_call(0x1000, 0x2000)
        self.assertEqual(tree.current_depth(), 1)

    def test_on_ret_decreases_depth(self):
        tree = CallTree()
        tree.on_call(0x1000, 0x2000)
        node = tree.on_ret(0x2005)
        self.assertEqual(tree.current_depth(), 0)
        self.assertEqual(node.ret_addr, 0x2005)

    def test_on_ret_at_root_returns_none(self):
        tree = CallTree()
        node = tree.on_ret(0x1000)
        self.assertIsNone(node)
        self.assertEqual(tree.current_depth(), 0)

    def test_nested_calls(self):
        tree = CallTree()
        tree.on_call(0x1000, 0x2000)  # depth 1
        tree.on_call(0x2010, 0x3000)  # depth 2
        self.assertEqual(tree.current_depth(), 2)
        self.assertEqual(len(tree.root.children), 1)
        self.assertEqual(len(tree.root.children[0].children), 1)

    def test_call_tree_structure(self):
        tree = CallTree()
        tree.on_call(0x1000, 0x2000)
        tree.on_call(0x2010, 0x3000)
        tree.on_ret(0x3010)  # return from b
        tree.on_call(0x2020, 0x4000)
        tree.on_ret(0x4010)  # return from c
        tree.on_ret(0x2030)  # return from a

        self.assertEqual(tree.current_depth(), 0)
        self.assertEqual(len(tree.root.children), 1)
        self.assertEqual(len(tree.root.children[0].children), 2)
        self.assertEqual(tree.root.children[0].children[0].target, 0x3000)
        self.assertEqual(tree.root.children[0].children[1].target, 0x4000)

    def test_is_call_insn(self):
        from pydbg.disasm.engine import Instruction
        insn = Instruction(
            address=0, size=5, mnemonic="call",
            op_str="0x2000", raw_bytes=b'\xe8', is_call=True)
        self.assertTrue(CallTree.is_call_insn(insn))

    def test_is_ret_insn(self):
        from pydbg.disasm.engine import Instruction
        insn = Instruction(
            address=0, size=1, mnemonic="ret",
            op_str="", raw_bytes=b'\xc3', is_ret=True)
        self.assertTrue(CallTree.is_ret_insn(insn))

    def test_current_node(self):
        tree = CallTree()
        self.assertIs(tree.current_node(), tree.root)
        node = tree.on_call(0x1000, 0x2000)
        self.assertIs(tree.current_node(), node)


class TestStepTracerLive(unittest.TestCase):
    """Live TF-flag stepping coverage."""

    @unittest.skipUnless(_has_cython, "requires Cython extension")
    def test_step_sets_tf_and_clear_restores(self):
        from tests.helpers import create_debugger, teardown
        from pydbg.trace.step import StepTracer

        dbg, pid, tid = create_debugger()
        try:
            h_thread = dbg.open_thread(tid)
            tracer = StepTracer(dbg._session)
            tracer.step(h_thread)
            regs = dbg.get_registers(h_thread)
            self.assertTrue(regs["eflags"] & 0x100)
            tracer.clear_tf(h_thread)
            regs2 = dbg.get_registers(h_thread)
            self.assertFalse(regs2["eflags"] & 0x100)
            dbg.close_handle(h_thread)
        finally:
            teardown(dbg)


if __name__ == '__main__':
    unittest.main()
