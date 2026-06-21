"""Call graph builder for tracing function call relationships."""

import json
from dataclasses import dataclass, field


@dataclass
class CallEdge:
    """Represents a directed edge between two functions in the call graph."""
    caller: int
    callee: int
    count: int = 0
    total_time: int = 0


class CallGraphBuilder:
    """Builds a call graph from caller/callee address pairs with timestamps."""

    def __init__(self):
        self._edges = {}  # (caller, callee) -> CallEdge
        self._nodes = {}  # addr -> {'count': int, 'first_seen': int}

    def add_call(self, caller_addr, callee_addr, timestamp, return_timestamp):
        """Record a function call.

        Args:
            caller_addr: Address of the calling function.
            callee_addr: Address of the called function.
            timestamp: Timestamp when the call started.
            return_timestamp: Timestamp when the call returned.
        """
        duration = return_timestamp - timestamp

        # Update edges
        key = (caller_addr, callee_addr)
        if key not in self._edges:
            self._edges[key] = CallEdge(caller=caller_addr, callee=callee_addr)
        edge = self._edges[key]
        edge.count += 1
        edge.total_time += duration

        # Update nodes
        for addr in (caller_addr, callee_addr):
            if addr not in self._nodes:
                self._nodes[addr] = {'count': 0, 'first_seen': timestamp}
            self._nodes[addr]['count'] += 1

    def build_graph(self):
        """Return the full graph as a dict with 'nodes' and 'edges' keys."""
        return {
            'nodes': dict(self._nodes),
            'edges': [
                {
                    'caller': edge.caller,
                    'callee': edge.callee,
                    'count': edge.count,
                    'total_time': edge.total_time,
                }
                for edge in self._edges.values()
            ],
        }

    def export_json(self, path):
        """Export the graph to a JSON file."""
        graph = self.build_graph()
        with open(path, 'w') as f:
            json.dump(graph, f, indent=2)

    def export_dot(self, path):
        """Export the graph in Graphviz DOT format."""
        lines = ['digraph callgraph {']
        for addr, info in self._nodes.items():
            lines.append(f'  "0x{addr:x}" [label="0x{addr:x}\\ncalls={info["count"]}"];')
        for edge in self._edges.values():
            label = f'count={edge.count}, time={edge.total_time}'
            lines.append(f'  "0x{edge.caller:x}" -> "0x{edge.callee:x}" [label="{label}"];')
        lines.append('}')
        with open(path, 'w') as f:
            f.write('\n'.join(lines) + '\n')

    def get_hot_paths(self, top_n=10):
        """Return the top N hottest edges sorted by total_time descending."""
        sorted_edges = sorted(self._edges.values(), key=lambda e: e.total_time, reverse=True)
        return [
            {
                'caller': edge.caller,
                'callee': edge.callee,
                'count': edge.count,
                'total_time': edge.total_time,
            }
            for edge in sorted_edges[:top_n]
        ]

    def clear(self):
        """Remove all recorded calls."""
        self._edges.clear()
        self._nodes.clear()
