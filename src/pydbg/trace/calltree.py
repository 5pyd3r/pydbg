from dataclasses import dataclass, field


@dataclass
class CallNode:
    addr: int
    target: int
    depth: int
    children: list = field(default_factory=list)
    ret_addr: int | None = None


class CallTree:
    """Call/ret tracking graph builder."""

    def __init__(self):
        self.root = CallNode(addr=0, target=0, depth=0)
        self._stack = [self.root]

    def on_call(self, addr, target):
        node = CallNode(addr=addr, target=target, depth=len(self._stack))
        self._stack[-1].children.append(node)
        self._stack.append(node)
        return node

    def on_ret(self, addr):
        if len(self._stack) > 1:
            node = self._stack.pop()
            node.ret_addr = addr
            return node
        return None

    def current_depth(self):
        return len(self._stack) - 1

    def current_node(self):
        return self._stack[-1]

    @staticmethod
    def is_call_insn(insn):
        return insn.is_call

    @staticmethod
    def is_ret_insn(insn):
        return insn.is_ret
